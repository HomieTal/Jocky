"""AST -> JSON IR (.jir) generation, following manual §13.2.

The IR is human-readable JSON:

    {
      "jir_version": "1.0",
      "metadata": { "source_file": "...", "case_id": "...", ... },
      "instructions": [
        { "op": "COLLECT", "module": "mem", "entity": "processes",
          "filters": [ ... ], "sort": {...}, "limit": 10 },
        { "op": "ASSIGN", "name": "suspicious", "source": "$last_result" },
        { "op": "EXPORT", "format": "json", "path": "findings.json" }
      ]
    }
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from typing import Any, Dict, List, Optional

from jocky import JIR_VERSION
from jocky.ast import nodes as A


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Expression lowering
# --------------------------------------------------------------------------

def gen_expr(node: A.Node) -> Dict[str, Any]:
    if isinstance(node, A.Literal):
        return {"e": "lit", "v": node.value}
    if isinstance(node, A.Name):
        return {"e": "name", "path": node.path}
    if isinstance(node, A.FString):
        parts = []
        for part in node.parts:
            kind = part[0]
            if kind == "lit":
                parts.append({"t": "lit", "v": part[1]})
            else:
                parts.append({"t": "expr", "x": gen_expr(part[1]),
                              "spec": part[2] if len(part) > 2 else ""})
        return {"e": "fstring", "parts": parts}
    if isinstance(node, A.ListLit):
        return {"e": "list", "items": [gen_expr(i) for i in node.items]}
    if isinstance(node, A.MapLit):
        return {"e": "map", "pairs": {k: gen_expr(v) for k, v in node.pairs}}
    if isinstance(node, A.BinOp):
        return {"e": "bin", "op": node.op,
                "l": gen_expr(node.left), "r": gen_expr(node.right)}
    if isinstance(node, A.Compare):
        return {"e": "cmp", "op": node.op,
                "l": gen_expr(node.left), "r": gen_expr(node.right)}
    if isinstance(node, A.BoolOp):
        return {"e": "bool", "op": node.op, "values": [gen_expr(v) for v in node.values]}
    if isinstance(node, A.UnaryOp):
        return {"e": "unary", "op": node.op, "x": gen_expr(node.operand)}
    if isinstance(node, A.Index):
        return {"e": "index", "obj": gen_expr(node.obj), "index": gen_expr(node.index)}
    if isinstance(node, A.Slice):
        return {"e": "slice", "obj": gen_expr(node.obj),
                "start": gen_expr(node.start) if node.start else None,
                "stop": gen_expr(node.stop) if node.stop else None}
    if isinstance(node, A.Member):
        return {"e": "member", "obj": gen_expr(node.obj), "name": node.name}
    if isinstance(node, A.Call):
        callee = gen_expr(node.callee)
        name = callee.get("path") if callee.get("e") == "name" else None
        return {"e": "call", "name": name, "callee": callee,
                "args": [gen_expr(a) for a in node.args],
                "kwargs": {k: gen_expr(v) for k, v in node.kwargs.items()}}
    if isinstance(node, A.CollectExpr):
        return {"e": "collect", "module": node.module, "entity": node.entity,
                "args": [gen_expr(a) for a in node.args],
                "kwargs": {k: gen_expr(v) for k, v in node.kwargs.items()},
                "snapshot": node.snapshot}
    if isinstance(node, A.Pipeline):
        stages = []
        for st in node.stages:
            if isinstance(st, A.WhereStage):
                stages.append({"stage": "where", "expr": gen_expr(st.expr)})
            elif isinstance(st, A.SortStage):
                stages.append({"stage": "sort", "field": st.field, "desc": st.descending})
            elif isinstance(st, A.LimitStage):
                stages.append({"stage": "limit", "n": st.count})
        return {"e": "pipeline", "source": gen_expr(node.source), "stages": stages}
    raise ValueError(f"cannot lower expression node {type(node).__name__}")


# --------------------------------------------------------------------------
# Statement lowering
# --------------------------------------------------------------------------

def _collect_instruction(node: A.Node) -> Optional[Dict[str, Any]]:
    """Lower a collect(-pipeline) to the manual's COLLECT instruction shape
    (filters/sort/limit embedded). Accepts a bare CollectExpr (no stages —
    the `?pipeline` grammar rule inlines single-child pipelines) or a
    full Pipeline whose source is a collect."""
    if isinstance(node, A.Pipeline):
        src = node.source
        if not isinstance(src, A.CollectExpr):
            return None
        stages = node.stages
    elif isinstance(node, A.CollectExpr):
        src = node
        stages = []
    else:
        return None
    filters: List[Dict[str, Any]] = []
    sort: Optional[Dict[str, Any]] = None
    limit: Optional[int] = None
    for st in stages:
        if isinstance(st, A.WhereStage):
            filters.append(gen_expr(st.expr))
        elif isinstance(st, A.SortStage):
            sort = {"field": st.field, "desc": st.descending}
        elif isinstance(st, A.LimitStage):
            limit = st.count
    return {
        "op": "COLLECT",
        "module": src.module,
        "entity": src.entity,
        "args": [gen_expr(a) for a in src.args],
        "kwargs": {k: gen_expr(v) for k, v in src.kwargs.items()},
        "snapshot": src.snapshot,
        "filters": filters,
        "sort": sort,
        "limit": limit,
        "line": src.line,
    }


def gen_statements(statements: List[A.Node]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for stmt in statements:
        out.extend(_gen_statement(stmt))
    return out


def _gen_statement(stmt: A.Node) -> List[Dict[str, Any]]:
    if isinstance(stmt, A.LetStmt):
        instr = _collect_instruction(stmt.value)
        if instr is not None:
            return [instr,
                    {"op": "ASSIGN", "name": stmt.name,
                     "source": "$last_result", "const": stmt.const,
                     "line": stmt.line}]
        return [{"op": "LET", "name": stmt.name, "const": stmt.const,
                 "expr": gen_expr(stmt.value), "line": stmt.line}]

    if isinstance(stmt, A.AssignStmt):
        instr = _collect_instruction(stmt.value)
        if instr is not None:
            return [instr,
                    {"op": "ASSIGN", "name": stmt.name,
                     "source": "$last_result", "line": stmt.line}]
        return [{"op": "ASSIGN", "name": stmt.name, "expr": gen_expr(stmt.value),
                 "line": stmt.line}]

    if isinstance(stmt, A.ExprStmt):
        instr = _collect_instruction(stmt.expr)
        if instr is not None:
            return [instr]
        return [{"op": "EXPR", "expr": gen_expr(stmt.expr), "line": stmt.line}]

    if isinstance(stmt, A.PrintStmt):
        return [{"op": "PRINT", "expr": gen_expr(stmt.expr), "line": stmt.line}]

    if isinstance(stmt, A.AlertStmt):
        return [{"op": "ALERT", "severity": stmt.severity,
                 "expr": gen_expr(stmt.expr), "line": stmt.line}]

    if isinstance(stmt, A.ExportStmt):
        return [{"op": "EXPORT",
                 "expr": gen_expr(stmt.expr) if stmt.expr is not None else None,
                 "format": stmt.fmt, "path": stmt.path, "line": stmt.line}]

    if isinstance(stmt, A.IfStmt):
        return [{"op": "IF",
                 "branches": [{"cond": gen_expr(c), "body": gen_statements(b)}
                              for c, b in stmt.branches],
                 "else": gen_statements(stmt.else_body),
                 "line": stmt.line}]

    if isinstance(stmt, A.ForeachStmt):
        return [{"op": "FOREACH", "var": stmt.var, "iter": gen_expr(stmt.iterable),
                 "body": gen_statements(stmt.body), "line": stmt.line}]

    if isinstance(stmt, A.WhileStmt):
        return [{"op": "WHILE", "cond": gen_expr(stmt.cond),
                 "body": gen_statements(stmt.body), "line": stmt.line}]

    if isinstance(stmt, A.FuncDef):
        return [{"op": "FUNCDEF", "name": stmt.name,
                 "params": [{"name": n, "default": gen_expr(d) if d else None}
                            for n, d in stmt.params],
                 "body": gen_statements(stmt.body), "line": stmt.line}]

    if isinstance(stmt, A.ReturnStmt):
        return [{"op": "RETURN", "expr": gen_expr(stmt.expr) if stmt.expr else None,
                 "line": stmt.line}]

    if isinstance(stmt, A.BreakStmt):
        return [{"op": "BREAK", "line": stmt.line}]

    if isinstance(stmt, A.ContinueStmt):
        return [{"op": "CONTINUE", "line": stmt.line}]

    raise ValueError(f"cannot lower statement {type(stmt).__name__}")


# --------------------------------------------------------------------------
# Program -> IR document
# --------------------------------------------------------------------------

def generate_ir(program: A.Program, source_file: str = "",
                source_text: str = "") -> Dict[str, Any]:
    auth = {}
    requires: List[str] = []
    platform = ""
    plugins: List[str] = []
    for d in program.directives:
        if isinstance(d, A.Authorization):
            auth = dict(d.fields)
        elif isinstance(d, A.Requires):
            requires.extend(d.items)
        elif isinstance(d, A.PlatformDecl):
            platform = d.name
        elif isinstance(d, A.PluginDecl):
            plugins.append(d.name)

    doc = {
        "jir_version": JIR_VERSION,
        "metadata": {
            "source_file": source_file,
            "compiled_at": _now_iso(),
            "case_id": auth.get("case_id", ""),
            "investigator": auth.get("investigator", ""),
            "authorization": auth,
            "requires": requires,
            "platform": platform,
            "plugins": plugins,
            "script_sha256": sha256_text(source_text) if source_text else "",
        },
        "instructions": gen_statements(program.statements),
    }
    return doc
