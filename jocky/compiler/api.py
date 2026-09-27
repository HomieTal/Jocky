"""JOCKY compile facade: source -> validated AST -> JSON IR.

Compile pipeline (manual §13, §1.1):
    .jky -> Lexer -> Parser -> AST -> Semantic Validation
         -> Authorization Validation -> JSON IR (.jir)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from jocky.ast import nodes as A
from jocky.authorization.model import Authorization
from jocky.compiler.irgen import generate_ir
from jocky.compiler.parser import parse_source
from jocky.modules.registry import ModuleRegistry
from jocky.runtime import errors

_REGISTRY = ModuleRegistry()


@dataclass
class CompileResult:
    program: A.Program
    ir: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)


def _walk_expr_fields(expr: Dict[str, Any], out: List[Dict[str, Any]]) -> None:
    """Collect 'name' expression nodes from a lowered expression."""
    if not isinstance(expr, dict):
        return
    if expr.get("e") == "name":
        out.append(expr)
    for key, val in expr.items():
        if key in ("e", "op"):
            continue
        if isinstance(val, dict):
            _walk_expr_fields(val, out)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _walk_expr_fields(item, out)


def _validate_collect_pipeline(pipeline: A.Pipeline, warnings: List[str]) -> None:
    """Semantic checks for a collect-pipeline (module existence, scope,
    field validity, capability mapping)."""
    src = pipeline.source
    if not isinstance(src, A.CollectExpr):
        return
    key = f"{src.module}.{src.entity}"
    if not _REGISTRY.exists(key):
        available = ", ".join(_REGISTRY.keys())
        raise errors.module_not_found(
            f'forensic module "{key}" is not available (available: {available})',
            src.line)
    collector = _REGISTRY.get(key)

    # known kwargs
    for name in src.kwargs:
        if name not in collector.arg_spec:
            raise errors.invalid_filter(
                f'collect {key}: unknown argument "{name}" '
                f"(accepted: {', '.join(collector.arg_spec) or '<none>'})",
                src.line)

    # where / sort field validation against the collector's documented fields
    fields = set(collector.fields) | {"signature_status", "record_type"}
    for stage in pipeline.stages:
        if isinstance(stage, A.SortStage):
            leaf = stage.field.split(".")[-1]
            if leaf not in fields:
                raise errors.invalid_field(
                    f'collect {key}: cannot sort by "{stage.field}" — valid fields: '
                    + ", ".join(collector.fields[:16]), stage.line)
            continue
        if not isinstance(stage, A.WhereStage):
            continue
        names: List[A.Name] = []
        _collect_names(stage.expr, names)
        for name_node in names:
            parts = name_node.path.split(".")
            if len(parts) >= 2 and parts[0] == collector.record_type:
                leaf = parts[-1]
                if leaf not in fields:
                    raise errors.invalid_field(
                        f'collect {key}: field "{name_node.path}" does not exist — '
                        "valid fields: " + ", ".join(collector.fields[:16]),
                        name_node.line)
            elif len(parts) == 1 and parts[0] not in (
                    collector.record_type, "true", "false", "null"):
                warnings.append(
                    f"line {name_node.line}: \"{parts[0]}\" resolves against the "
                    f"runtime environment, not the {collector.record_type} record")


def _collect_names(node: Any, out: List[A.Name]) -> None:
    if isinstance(node, A.Name):
        out.append(node)
    for val in vars(node).values():
        if isinstance(val, A.Node):
            _collect_names(val, out)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, A.Node):
                    _collect_names(item, out)
                elif isinstance(item, tuple):
                    for t in item:
                        if isinstance(t, A.Node):
                            _collect_names(t, out)


def _validate_pipeline_expr(node: Any, warnings: List[str]) -> None:
    """Find pipelines and bare collect expressions anywhere in the AST
    (a collect with no stages is inlined by the grammar, never wrapped in
    a Pipeline node)."""
    if isinstance(node, A.Pipeline):
        _validate_collect_pipeline(node, warnings)
    elif isinstance(node, A.CollectExpr):
        _validate_collect_pipeline(A.Pipeline(node, [], node.line), warnings)
    if isinstance(node, A.Node):
        for val in vars(node).values():
            _validate_pipeline_expr(val, warnings)
    elif isinstance(node, list):
        for item in node:
            _validate_pipeline_expr(item, warnings)


def compile_source(source_text: str, source_file: str = "") -> CompileResult:
    """Full compile: parse -> validate directives -> semantic checks -> IR."""
    program = parse_source(source_text)
    warnings: List[str] = []

    # --- authorization validation (E001/E002/E003) -----------------------
    auth_nodes = [d for d in program.directives if isinstance(d, A.Authorization)]
    if not auth_nodes:
        first_stmt_line = program.statements[0].line if program.statements else 1
        raise errors.auth_missing(
            "every JOCKY script requires an @authorization block — see manual §1.5",
            line=first_stmt_line)
    if len(auth_nodes) > 1:
        raise errors.auth_invalid(
            "multiple @authorization blocks found; exactly one is allowed",
            line=auth_nodes[1].line)
    auth = Authorization.from_fields(auth_nodes[0].fields, auth_nodes[0].line)
    auth.validate()

    # --- platform / privilege directives ----------------------------------
    for d in program.directives:
        if isinstance(d, A.PlatformDecl) and d.name.lower() not in ("windows",):
            raise errors.platform_mismatch(
                f'this prototype is Windows-only; script declares @platform {d.name}',
                d.line)
        if isinstance(d, A.Requires):
            for item in d.items:
                if not (item.startswith("privilege.") or
                        item in ("PROCESS_READ", "NETWORK_READ", "REGISTRY_READ",
                                 "EVENTLOG_READ", "FILE_READ", "HASH_FILE",
                                 "EVIDENCE_EXPORT", "SYSTEM_READ")):
                    raise errors.priv_denied(
                        f'unknown @requires item "{item}"', d.line)

    # --- semantic validation of collect pipelines --------------------------
    for stmt in program.statements:
        _validate_pipeline_expr(stmt, warnings)

    # --- scope check per collect module (E004, compile-time) ---------------
    for stmt in program.statements:
        _check_scope(stmt, auth)

    ir = generate_ir(program, source_file=source_file, source_text=source_text)
    return CompileResult(program=program, ir=ir, warnings=warnings)


def _check_scope(node: Any, auth: Authorization) -> None:
    if isinstance(node, A.CollectExpr):
        auth.check_module_in_scope(node.module, node.line)
        return
    if isinstance(node, A.Node):
        for val in vars(node).values():
            _check_scope(val, auth)
    elif isinstance(node, list):
        for item in node:
            _check_scope(item, auth)


def save_ir(ir: Dict[str, Any], path: str) -> str:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(ir, fh, indent=2, ensure_ascii=False, default=str)
    except OSError as exc:
        raise errors.export_failed(f"cannot write IR file '{path}': {exc}") from None
    return path
