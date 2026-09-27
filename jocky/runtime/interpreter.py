"""JOCKY runtime: the controlled interpreter executing JSON IR (JVMO).

Executes the .jir instruction stream produced by the compiler. Every
action passes through: Requested Operation -> Declared Scope ->
Authorization -> Capability Policy -> Execution. All collections write
.jrf evidence; all actions append to the .jal log.
"""

from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from jocky import APP_NAME
from jocky.authorization.model import Authorization
from jocky.evidence.store import ActionLog, EvidenceStore, now_iso, sha256_file
from jocky.modules.base import CollectContext
from jocky.modules.registry import ModuleRegistry
from jocky.runtime import errors
from jocky.runtime.capabilities import CapabilityEnforcer, capability_for_module
from jocky.runtime.interrupts import BreakSignal, ContinueSignal, ReturnSignal

_MAX_WHILE_ITERATIONS = 10_000
_MAX_CALL_DEPTH = 32
_MAX_ACTION_LOG = 5000


class RunResult:
    def __init__(self):
        self.ok = False
        self.status = "FAILED"
        self.detail = ""
        self.error: Optional[errors.JockyError] = None
        self.statements = 0
        self.duration_ms = 0
        self.alerts: List[Dict[str, Any]] = []
        self.alert_counts: Dict[str, int] = {"LOW": 0, "MEDIUM": 0,
                                             "HIGH": 0, "CRITICAL": 0}
        self.collections: List[Dict[str, Any]] = []
        self.evidence_records: List[Dict[str, Any]] = []
        self.timeline: List[Dict[str, Any]] = []
        self.prints: List[str] = []
        self.merkle_root = ""
        self.generated_at = now_iso()

    def finalize(self, ok: bool, status: str, detail: str = ""):
        self.ok = ok
        self.status = status
        self.detail = detail


def ir_to_text(instr: Dict[str, Any]) -> str:
    """Short human description of an IR instruction (for logs + UI)."""
    op = instr.get("op", "?")
    line = instr.get("line", "")
    suffix = f" (line {line})" if line else ""
    if op == "COLLECT":
        parts = [f"COLLECT {instr.get('module')}.{instr.get('entity')}"]
        if instr.get("snapshot"):
            parts[0] = "SNAPSHOT " + parts[0][8:]
        if instr.get("filters"):
            parts.append(f"{len(instr['filters'])} filter(s)")
        if instr.get("sort"):
            parts.append("sort")
        if instr.get("limit"):
            parts.append(f"limit {instr['limit']}")
        return " ".join(parts) + suffix
    if op in ("LET", "ASSIGN"):
        return f"{op} {instr.get('name')}" + suffix
    if op == "PRINT":
        return "PRINT" + suffix
    if op == "ALERT":
        return f"ALERT {instr.get('severity')}" + suffix
    if op == "EXPORT":
        return f"EXPORT {instr.get('format') or 'json'} {instr.get('path') or '<auto>'}" + suffix
    if op == "IF":
        return "IF" + suffix
    if op == "FOREACH":
        return f"FOREACH {instr.get('var')}" + suffix
    if op == "WHILE":
        return "WHILE" + suffix
    if op == "FUNCDEF":
        return f"FUNCDEF {instr.get('name')}" + suffix
    if op == "RETURN":
        return "RETURN" + suffix
    if op in ("BREAK", "CONTINUE", "EXPR"):
        return op + suffix
    return op + suffix


class JockyVM:
    """Executes a compiled JOCKY IR document under full policy control."""

    def __init__(self, registry: ModuleRegistry,
                 print_fn: Optional[Callable[[str], None]] = None,
                 progress_fn: Optional[Callable[[str], None]] = None):
        self.registry = registry
        self.print_fn = print_fn or (lambda s: None)
        self.progress_fn = progress_fn or (lambda s: None)
        self.env: Dict[str, Any] = {}
        self.consts: set = set()
        self.funcs: Dict[str, Dict[str, Any]] = {}
        self.last_result: Any = None
        self.auth: Optional[Authorization] = None
        self.enforcer: Optional[CapabilityEnforcer] = None
        self.action_log: Optional[ActionLog] = None
        self.evidence: Optional[EvidenceStore] = None
        self.case_id = ""
        self.investigator = ""
        self.evidence_dir = ""
        self._collect_counter = 0
        self._export_counter = 0
        self._depth = 0
        self._proc_cache: Optional[List[dict]] = None
        self._statements_executed = 0
        self._result: Optional[RunResult] = None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, ir: Dict[str, Any], script_path: str = "",
            ir_path: str = "", evidence_dir: str = "") -> RunResult:
        result = RunResult()
        self._result = result
        started = time.perf_counter()
        try:
            self._run_checked(ir, script_path, ir_path, evidence_dir, result)
            result.finalize(True, "COMPLETED")
        except (BreakSignal, ContinueSignal, ReturnSignal):
            result.finalize(True, "COMPLETED")
        except errors.JockyError as exc:
            result.error = exc
            result.finalize(False, "REFUSED" if exc.code.startswith("E0")
                            or exc.code in ("E001", "E002", "E003", "E004", "E010",
                                            "E020") else "FAILED", exc.format())
        except RecursionError:
            result.error = errors.runtime_error("recursion limit exceeded")
        except Exception as exc:  # noqa: BLE001 — last-resort containment
            result.error = errors.runtime_error(f"internal runtime error: {exc}")
        finally:
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            result.statements = self._statements_executed
            result.generated_at = now_iso()
            if self.evidence is not None:
                result.evidence_records = self.evidence.records
                result.merkle_root = self.evidence.parent_hash
        return result

    # ------------------------------------------------------------------

    def _run_checked(self, ir: Dict[str, Any], script_path: str, ir_path: str,
                     evidence_dir: str, result: RunResult) -> None:
        # 1. IR sanity (E104)
        if not isinstance(ir, dict) or "instructions" not in ir:
            raise errors.malformed_ir("IR document must be a JSON object with an "
                                      "'instructions' array")
        if not isinstance(ir["instructions"], list):
            raise errors.malformed_ir("'instructions' must be a JSON array")
        meta = ir.get("metadata") or {}

        # 2. Platform (E020)
        platform_decl = str(meta.get("platform") or "").lower()
        if platform_decl and platform_decl != "windows":
            raise errors.platform_mismatch(
                f"script declares @platform {platform_decl} but this runtime is "
                "windows-only")

        # 3. Authorization (E001/E002/E003) — mandatory
        self.auth = Authorization.from_fields(dict(meta.get("authorization") or {}))
        self.auth.validate()
        self.case_id = self.auth.case_id
        self.investigator = self.auth.investigator

        # 4. Privilege (@requires) (E010)
        self.enforcer = CapabilityEnforcer(meta.get("requires") or [])
        self.enforcer.check_privilege()

        # 5. Evidence + action-log plumbing
        self.evidence_dir = evidence_dir or os.path.dirname(os.path.abspath(script_path)) \
            or os.getcwd()
        self.action_log = ActionLog(os.path.join(self.evidence_dir, "action.log"),
                                    self.case_id, self.investigator)
        self.evidence = EvidenceStore(self.evidence_dir, self.case_id,
                                      self.investigator, self.action_log)
        self.action_log.add(command="RUN", capability="",
                            result=f"start {os.path.basename(script_path)}",
                            success=True, detail=f"case {self.case_id}")

        # 6. Execute instructions
        self._statements_executed = 0
        self._exec_block(ir["instructions"], result)

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def _exec_block(self, instructions: List[Dict[str, Any]], result: RunResult):
        for instr in instructions:
            self._exec(instr, result)

    def _exec(self, instr: Dict[str, Any], result: RunResult):
        self._statements_executed += 1
        if len(self.action_log.entries) < _MAX_ACTION_LOG:
            started = time.perf_counter()
            self._exec_inner(instr, result)
            self.action_log.add(
                command=ir_to_text(instr), capability="", result="ok",
                success=True, duration_ms=int((time.perf_counter() - started) * 1000))
        else:
            self._exec_inner(instr, result)

    def _exec_inner(self, instr: Dict[str, Any], result: RunResult):
        op = instr.get("op")
        line = int(instr.get("line") or 0)

        if op == "COLLECT":
            value = self._do_collect(instr)
            self.last_result = value
            return
        if op == "LET":
            if instr.get("name") in self.consts:
                raise errors.type_error(
                    f'constant "{instr["name"]}" cannot be reassigned', line)
            self.env[instr["name"]] = self.eval(instr["expr"], record=None)
            if instr.get("const"):
                self.consts.add(instr["name"])
            return
        if op == "ASSIGN":
            if instr.get("source") == "$last_result":
                self.env[instr["name"]] = self.last_result
                return
            if instr.get("name") in self.consts:
                raise errors.type_error(
                    f'constant "{instr["name"]}" cannot be reassigned', line)
            self.env[instr["name"]] = self.eval(instr.get("expr"), record=None)
            return
        if op == "PRINT":
            text = self.to_display(self.eval(instr["expr"], record=None))
            self.print_fn(text)
            if self._result is not None:
                self._result.prints.append(text)
            return
        if op == "ALERT":
            severity = str(instr.get("severity") or "MEDIUM")
            message = self.to_display(self.eval(instr["expr"], record=None))
            result.alerts.append({"severity": severity, "message": message,
                                  "raised_at": now_iso(), "line": line})
            result.alert_counts[severity] = result.alert_counts.get(severity, 0) + 1
            self.action_log.add(command=f"ALERT {severity}: {message}",
                                capability="", result=severity, success=True)
            self.print_fn(f"[ALERT:{severity}] {message}")
            return
        if op == "EXPORT":
            self._do_export(instr, result)
            return
        if op == "IF":
            for branch in instr.get("branches") or []:
                if self.truthy(self.eval(branch["cond"], record=None)):
                    self._exec_block(branch["body"], result)
                    return
            if instr.get("else"):
                self._exec_block(instr["else"], result)
            return
        if op == "FOREACH":
            iterable = self.eval(instr["iter"], record=None)
            if not isinstance(iterable, list):
                raise errors.type_error(
                    f"foreach requires a list, got {self.typeof(iterable)}", line)
            saved = self.env.get(instr["var"], _MISSING)
            for item in iterable:
                self.env[instr["var"]] = item
                try:
                    self._exec_block(instr["body"], result)
                except BreakSignal:
                    break
                except ContinueSignal:
                    continue
            if saved is _MISSING:
                self.env.pop(instr["var"], None)
            else:
                self.env[instr["var"]] = saved
            return
        if op == "WHILE":
            iterations = 0
            while self.truthy(self.eval(instr["cond"], record=None)):
                iterations += 1
                if iterations > _MAX_WHILE_ITERATIONS:
                    raise errors.runtime_error(
                        f"while loop exceeded {_MAX_WHILE_ITERATIONS} iterations "
                        "(safety limit)", line)
                try:
                    self._exec_block(instr["body"], result)
                except BreakSignal:
                    break
                except ContinueSignal:
                    continue
            return
        if op == "FUNCDEF":
            self.funcs[instr["name"]] = instr
            return
        if op == "RETURN":
            raise ReturnSignal(self.eval(instr["expr"], record=None)
                               if instr.get("expr") else None)
        if op == "BREAK":
            raise BreakSignal()
        if op == "CONTINUE":
            raise ContinueSignal()
        if op == "EXPR":
            self.eval(instr["expr"], record=None)
            return
        raise errors.malformed_ir(f'unknown IR opcode "{op}"')

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def _do_collect(self, instr: Dict[str, Any]) -> List[dict]:
        return self._execute_collect(
            module=str(instr.get("module") or ""),
            entity=str(instr.get("entity") or ""),
            args=[self.eval(a, record=None) for a in instr.get("args") or []],
            kwargs={k: self.eval(v, record=None)
                    for k, v in (instr.get("kwargs") or {}).items()},
            filters=instr.get("filters") or [],
            sort=instr.get("sort"),
            limit=instr.get("limit"),
            line=int(instr.get("line") or 0),
            snapshot=bool(instr.get("snapshot")))

    def _execute_collect(self, module: str, entity: str, args: List[Any],
                         kwargs: Dict[str, Any], filters: List[Dict[str, Any]],
                         sort: Optional[Dict[str, Any]],
                         limit: Optional[int], line: int,
                         snapshot: bool = False) -> List[dict]:
        key = f"{module}.{entity}"

        if not self.registry.exists(key):
            available = ", ".join(self.registry.keys())
            raise errors.module_not_found(
                f'forensic module "{key}" is not available on this runtime '
                f"(available: {available})", line)

        # Requested Operation -> Declared Scope -> Authorization
        self.auth.check_module_in_scope(module, line)
        # -> Capability Policy
        capability = self.enforcer.check_module(module, line)

        collector = self.registry.get(key)

        started = time.perf_counter()
        ctx = CollectContext(log=lambda s: None, progress=self.progress_fn)
        rows = self.registry.run(key, args, kwargs, ctx)
        duration = int((time.perf_counter() - started) * 1000)

        # pipeline stages (where / sort / limit)
        for stage in filters:
            rows = [r for r in rows
                    if self.truthy(self.eval(stage, record=(r, collector.record_type)))]
        if sort and sort.get("field"):
            field = sort["field"].split(".")[-1]
            desc = bool(sort.get("desc"))
            rows.sort(key=lambda r: _sort_key(r.get(field)), reverse=desc)
        if limit:
            rows = rows[: int(limit)]

        # evidence record (.jrf) — mandatory for every collection
        self._collect_counter += 1
        name = f"{self.case_id}_{module}_{entity}_{self._collect_counter:02d}"
        src_meta = {
            "capability": capability,
            "duration_ms": duration,
            "rows": len(rows),
            "filters": _brief_filters(filters),
            "sort": sort,
            "limit": limit,
            "args": {k: str(v) for k, v in kwargs.items()},
            "arguments": [str(a) for a in args],
        }
        rec = self.evidence.write_artifact(
            name=name, payload=rows,
            operation=("SNAPSHOT " if snapshot else "COLLECT ") + key,
            collected_artifact=collector.title, source_metadata=src_meta)
        self.progress_fn(f"{key}: {len(rows)} records -> {os.path.basename(rec['result_file'])}")
        if self._result is not None:
            self._result.collections.append({
                "key": key,
                "title": collector.title,
                "columns": collector.columns,
                "fields": collector.fields,
                "rows": rows,
                "artifact": os.path.basename(rec["result_file"]),
            })
        return rows

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _do_export(self, instr: Dict[str, Any], result: RunResult):
        fmt = str(instr.get("format") or "json").lower()
        path = instr.get("path")
        line = int(instr.get("line") or 0)
        self.enforcer.check_capability("EVIDENCE_EXPORT", line)
        payload = self.last_result if instr.get("expr") is None \
            else self.eval(instr["expr"], record=None)
        if payload is None:
            raise errors.export_failed("nothing to export — no result available",
                                       line)
        self._export_counter += 1
        default_name = f"{self.case_id}_export_{self._export_counter:02d}.{fmt}"
        if not path:
            path = default_name
        if not os.path.isabs(path):
            path = os.path.join(self.evidence_dir, path)
        ext = os.path.splitext(path)[1].lower().lstrip(".")
        if ext != fmt:
            path = os.path.splitext(path)[0] + "." + fmt
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        except OSError:
            pass

        rows = payload if isinstance(payload, list) else [payload]
        if fmt == "json":
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2, ensure_ascii=False, default=str)
        elif fmt == "csv":
            flat = [r if isinstance(r, dict) else {"value": r} for r in rows]
            cols: List[str] = []
            for r in flat:
                for k in r.keys():
                    if k not in cols:
                        cols.append(k)
            with open(path, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                w.writeheader()
                for r in flat:
                    w.writerow({k: _csv_cell(r.get(k)) for k in cols})
        elif fmt == "html":
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_html_table(rows, self.case_id))
        else:
            raise errors.unsupported(
                f'export format "{fmt}" is not implemented in this prototype '
                "(supported: json, csv, html)", line)

        digest = "sha256:" + sha256_file(path)
        self._collect_counter += 1
        rec = self.evidence.write_artifact(
            name=f"{self.case_id}_export_{self._export_counter:02d}",
            payload={"file": path, "format": fmt, "rows": len(rows),
                     "sha256": digest},
            operation=f"EXPORT {fmt}",
            collected_artifact=os.path.basename(path),
            source_metadata={"path": path, "rows": len(rows)})
        self.progress_fn(f"exported {len(rows)} rows -> {os.path.basename(path)}")

    # ------------------------------------------------------------------
    # Expression evaluation
    # ------------------------------------------------------------------

    def eval(self, node: Optional[Dict[str, Any]], record: Any) -> Any:
        if node is None:
            return None
        kind = node.get("e")
        record_val = record[0] if isinstance(record, tuple) else record
        record_type = record[1] if isinstance(record, tuple) else ""

        if kind == "lit":
            return node.get("v")
        if kind == "name":
            return self._resolve(node.get("path", ""), record_val, record_type,
                                 int(node.get("line") or 0))
        if kind == "fstring":
            out = []
            for part in node.get("parts") or []:
                if part.get("t") == "lit":
                    out.append(str(part.get("v") or ""))
                else:
                    value = self.eval(part.get("x"), record_val)
                    spec = part.get("spec") or ""
                    if spec:
                        try:
                            if isinstance(value, (bool, type(None))):
                                value = self.to_display(value)
                            out.append(format(value, spec))
                        except (ValueError, TypeError):
                            out.append(self.to_display(value))
                    else:
                        out.append(self.to_display(value))
            return "".join(out)
        if kind == "list":
            return [self.eval(i, record_val) for i in node.get("items") or []]
        if kind == "map":
            return {k: self.eval(v, record_val)
                    for k, v in (node.get("pairs") or {}).items()}
        if kind == "bin":
            return self._arith(node, record_val)
        if kind == "cmp":
            return self._compare(node, record_val)
        if kind == "bool":
            op = node.get("op")
            if op == "and":
                for v in node.get("values") or []:
                    if not self.truthy(self.eval(v, record_val)):
                        return False
                return True
            for v in node.get("values") or []:
                if self.truthy(self.eval(v, record_val)):
                    return True
            return False
        if kind == "unary":
            val = self.eval(node.get("x"), record_val)
            op = node.get("op")
            if op == "not":
                return not self.truthy(val)
            if op == "-":
                return -val
            if op == "~":
                return ~val
            raise errors.type_error(f"unknown unary operator {op}")
        if kind == "index":
            obj = self.eval(node.get("obj"), record_val)
            idx = self.eval(node.get("index"), record_val)
            try:
                if isinstance(obj, dict):
                    return obj.get(str(idx))
                return obj[int(idx)]
            except (IndexError, ValueError, TypeError) as exc:
                raise errors.type_error(f"invalid index {idx!r}", 0) from exc
        if kind == "slice":
            obj = self.eval(node.get("obj"), record_val)
            start = self.eval(node.get("start"), record_val)
            stop = self.eval(node.get("stop"), record_val)
            try:
                return obj[int(start) if start is not None else None:
                           int(stop) if stop is not None else None]
            except (TypeError, ValueError) as exc:
                raise errors.type_error("invalid slice bounds") from exc
        if kind == "member":
            obj = self.eval(node.get("obj"), record_val)
            name = node.get("name")
            if isinstance(obj, dict):
                return obj.get(name)
            raise errors.type_error(
                f'cannot access field "{name}" on {self.typeof(obj)}')
        if kind == "collect":
            if not self.registry.exists(
                    f'{node.get("module")}.{node.get("entity")}'):
                raise errors.module_not_found(
                    f'forensic module "{node.get("module")}.{node.get("entity")}" '
                    "is not available")
            return self._execute_collect(
                module=node.get("module"), entity=node.get("entity"),
                args=[self.eval(a, record_val) for a in node.get("args") or []],
                kwargs={k: self.eval(v, record_val)
                        for k, v in (node.get("kwargs") or {}).items()},
                filters=[], sort=None, limit=None,
                line=int(node.get("line") or 0),
                snapshot=bool(node.get("snapshot")))
        if kind == "pipeline":
            source = self.eval(node.get("source"), record_val)
            record_type = ""
            src = node.get("source") or {}
            if src.get("e") == "collect":
                try:
                    record_type = self.registry.get(
                        f'{src.get("module")}.{src.get("entity")}').record_type
                except KeyError:
                    record_type = ""
            return self._apply_stages(source, node.get("stages") or [], record_type)
        if kind == "call":
            return self._call(node, record_val)
        raise errors.runtime_error(f"unknown IR expression kind {kind!r}")

    # -- name resolution with forensic-record awareness -------------------

    def _resolve(self, path: str, record: Any, record_type: str, line: int) -> Any:
        parts = path.split(".")
        root = parts[0]
        # 1) plain variable (or module namespace root)
        if root in self.env or root in self.funcs:
            val = self.env.get(root)
            for p in parts[1:]:
                if isinstance(val, dict):
                    if p not in val:
                        raise errors.invalid_field(
                            f'field "{p}" not present on {root} record '
                            f"(available: {', '.join(list(val.keys())[:14])})", line)
                    val = val[p]
                else:
                    raise errors.invalid_field(
                        f'cannot access "{p}" on {self.typeof(val)} value', line)
            return val
        # 2) module namespace (e.g. bare "mem" before a call) — only as call target
        if root in _MODULE_NAMESPACES and len(parts) == 1:
            return root
        # 3) record-relative: process.memory_mb / entry.name / file.path
        if record is not None and isinstance(record, dict):
            if root == record_type and len(parts) >= 2:
                val: Any = record
                for p in parts[1:]:
                    if isinstance(val, dict) and p in val:
                        val = val[p]
                    else:
                        raise errors.invalid_field(
                            f'field "{p}" does not exist on {record_type} records — '
                            "valid fields: " + _fields_of(self.registry, record_type),
                            line)
                return val
            if len(parts) >= 2 and parts[1] in record:
                val = record
                for p in parts[1:]:
                    if isinstance(val, dict) and p in val:
                        val = val[p]
                    else:
                        break
                return val
            if len(parts) == 1 and root in record:
                return record[root]
        # scalar list item in a where/pipeline context: a single bare name
        # (e.g. "entry" in `items | where entry >= 10`) is the item itself
        if record is not None and not isinstance(record, dict) and len(parts) == 1:
            return record
        raise errors.name_error(
            f'undefined variable or field "{path}"', line)

    # -- operators ---------------------------------------------------------

    def _arith(self, node: Dict[str, Any], record: Any) -> Any:
        left = self.eval(node.get("l"), record)
        right = self.eval(node.get("r"), record)
        op = node.get("op")
        try:
            if op == "+":
                if isinstance(left, str) or isinstance(right, str):
                    return self.to_display(left) + self.to_display(right)
                if isinstance(left, list) and isinstance(right, list):
                    return left + right
                return left + right
            if op == "-":
                return left - right
            if op == "*":
                return left * right
            if op == "/":
                if right == 0:
                    raise errors.type_error("division by zero")
                return left / right
            if op == "//":
                if right == 0:
                    raise errors.type_error("division by zero")
                return left // right
            if op == "%":
                if right == 0:
                    raise errors.type_error("modulo by zero")
                return left % right
            if op == "**":
                return left ** right
        except TypeError as exc:
            raise errors.type_error(
                f'operator "{op}" requires numbers (got {self.typeof(left)} '
                f"and {self.typeof(right)})") from exc
        raise errors.runtime_error(f"unknown operator {op!r}")

    def _compare(self, node: Dict[str, Any], record: Any) -> Any:
        left = self.eval(node.get("l"), record)
        right = self.eval(node.get("r"), record)
        op = node.get("op")
        if op == "==":
            return self._eq(left, right)
        if op == "!=":
            return not self._eq(left, right)
        if op == "in":
            return self._contains(right, left)
        if op == "notin":
            return not self._contains(right, left)
        if op == "matches":
            try:
                return re.search(str(right), self.to_display(left)) is not None
            except re.error as exc:
                raise errors.invalid_filter(f'invalid regex "{right}": {exc}') from exc
        if op == "contains":
            return self._contains(left, right)
        if op == "startswith":
            return self.to_display(left).startswith(self.to_display(right))
        if op == "endswith":
            return self.to_display(left).endswith(self.to_display(right))
        try:
            if op == "<":
                return left < right
            if op == ">":
                return left > right
            if op == "<=":
                return left <= right
            if op == ">=":
                return left >= right
        except TypeError as exc:
            raise errors.type_error(
                f'cannot compare {self.typeof(left)} and {self.typeof(right)} '
                f'with "{op}"') from exc
        raise errors.runtime_error(f"unknown comparison {op!r}")

    @staticmethod
    def _eq(a: Any, b: Any) -> bool:
        if isinstance(a, bool) or isinstance(b, bool):
            return bool(a) == bool(b)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return float(a) == float(b)
        return a == b

    @staticmethod
    def _contains(hay: Any, needle: Any) -> bool:
        if isinstance(hay, str):
            return str(needle) in hay
        if isinstance(hay, list):
            return any(JockyVM._eq(x, needle) for x in hay)
        if isinstance(hay, dict):
            return str(needle) in hay
        raise errors.type_error(
            f'"in"/"contains" requires list, map or string (got {JockyVM.typeof(hay)})')

    def _apply_stages(self, source: Any, stages: List[Dict[str, Any]],
                      record_type: str) -> Any:
        rows = source
        for stage in stages:
            kind = stage.get("stage")
            if kind == "where":
                if not isinstance(rows, list):
                    raise errors.invalid_filter(
                        "where requires a collection (list of forensic records)")
                rows = [r for r in rows
                        if self.truthy(self.eval(stage.get("expr"),
                                                 record=(r, record_type)))]
            elif kind == "sort":
                field = (stage.get("field") or "").split(".")[-1]
                rows = sorted(rows, key=lambda r: _sort_key(
                    r.get(field) if isinstance(r, dict) else r),
                    reverse=bool(stage.get("desc")))
            elif kind == "limit":
                rows = rows[: int(stage.get("n") or 0)]
        return rows

    # -- calls -------------------------------------------------------------

    def _call(self, node: Dict[str, Any], record: Any) -> Any:
        name = node.get("name") or ""
        args = [self.eval(a, record) for a in node.get("args") or []]
        kwargs = {k: self.eval(v, record)
                  for k, v in (node.get("kwargs") or {}).items()}

        # module member functions: mem.find_process, disk.hash, disk.hash_dir
        parts = name.split(".")
        if len(parts) == 2 and parts[0] in _MODULE_NAMESPACES:
            return self._module_function(parts[0], parts[1], args, kwargs)
        # user functions
        if name and name in self.funcs:
            return self._call_user(self.funcs[name], args, kwargs)
        # builtins
        fn = _BUILTINS.get(name)
        if fn is None:
            raise errors.name_error(
                f'unknown function "{name or "<expr>"}" '
                f"(builtins: {', '.join(sorted(_BUILTINS))})",
                int(node.get("line") or 0))
        try:
            return fn(self, *args, **kwargs)
        except errors.JockyError:
            raise
        except TypeError as exc:
            raise errors.type_error(f'{name}: {exc}') from None

    def _module_function(self, module: str, member: str, args, kwargs) -> Any:
        if module == "mem" and member == "find_process" and args:
            target = str(args[0]).lower()
            if self._proc_cache is None:
                from jocky.modules.mem.processes import ProcessesCollector
                collector = ProcessesCollector()
                self._proc_cache = collector.collect([], {}, CollectContext(
                    progress=self.progress_fn))
            for rec in self._proc_cache:
                if rec.get("name", "").lower() == target:
                    return rec
            return None
        if module == "disk" and member == "hash" and args:
            path = str(args[0])
            algo = str(kwargs.get("algo") or (args[1] if len(args) > 1 else "sha256")).lower()
            if algo not in ("sha256", "md5", "sha1"):
                raise errors.invalid_filter(
                    f'hash algorithm "{algo}" not supported (sha256, md5, sha1)')
            if not os.path.isfile(path):
                raise errors.collect_failed(f'file not found: "{path}"')
            h = hashlib.new(algo)
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        if module == "disk" and member == "hash_dir" and args:
            root = str(args[0])
            out = []
            count = 0
            for dirpath, _dirs, files in os.walk(root):
                for f in files:
                    p = os.path.join(dirpath, f)
                    try:
                        out.append({"path": p,
                                    "sha256": "sha256:" + sha256_file(p),
                                    "size_bytes": os.path.getsize(p)})
                    except OSError:
                        continue
                    count += 1
                    if count >= 500:
                        return out
            return out
        raise errors.unsupported(
            f'function {module}.{member} is not implemented in this prototype')

    def _call_user(self, fn: Dict[str, Any], args, kwargs) -> Any:
        self._depth += 1
        if self._depth > _MAX_CALL_DEPTH:
            self._depth -= 1
            raise errors.runtime_error(
                f"function call depth exceeded {_MAX_CALL_DEPTH} "
                "(possible runaway recursion)")
        params = fn.get("params") or []
        shadowed: Dict[str, Any] = {}
        try:
            for i, p in enumerate(params):
                pname = p.get("name")
                if i < len(args):
                    shadowed[pname] = args[i]
                elif pname in kwargs:
                    shadowed[pname] = kwargs[pname]
                elif p.get("default") is not None:
                    shadowed[pname] = self.eval(p["default"], None)
                else:
                    raise errors.type_error(
                        f'function "{fn.get("name")}": missing argument "{pname}"')
            backup = {k: self.env.get(k, _MISSING) for k in shadowed}
            self.env.update(shadowed)
            try:
                self._exec_block(fn.get("body") or [], self._result or RunResult())
                return None
            except ReturnSignal as ret:
                return ret.value
            finally:
                for k, v in backup.items():
                    if v is _MISSING:
                        self.env.pop(k, None)
                    else:
                        self.env[k] = v
        finally:
            self._depth -= 1

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def truthy(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, (str, list, dict)):
            return len(value) > 0
        return True

    @staticmethod
    def typeof(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            return "str"
        if isinstance(value, list):
            return "list"
        if isinstance(value, dict):
            return "map"
        return type(value).__name__

    @staticmethod
    def to_display(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, float):
            return f"{value:g}"
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False, default=str)
        return str(value)


_MISSING = object()

_MODULE_NAMESPACES = {"mem", "disk", "net", "reg", "log", "sys"}


def _fields_of(registry: ModuleRegistry, record_type: str) -> str:
    for entry in registry.catalog():
        if entry["record_type"] == record_type:
            return ", ".join(entry["fields"][:16])
    return "<unknown>"


def _sort_key(value: Any):
    if value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (1, value)
    return (2, str(value).lower())


def _csv_cell(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return "" if value is None else value


def _brief_filters(filters) -> List[str]:
    out = []
    for f in filters or []:
        try:
            out.append(json.dumps(f, ensure_ascii=False, default=str)[:120])
        except Exception:
            out.append("<filter>")
    return out


def _html_table(rows: List[Any], case_id: str) -> str:
    import html as _html
    flat = [r if isinstance(r, dict) else {"value": r} for r in rows]
    cols: List[str] = []
    for r in flat:
        for k in r.keys():
            if k not in cols:
                cols.append(k)
    head = "".join(f"<th>{_html.escape(c)}</th>" for c in cols)
    body = []
    for r in flat[:2000]:
        cells = "".join(
            f"<td>{_html.escape('' if r.get(c) is None else str(r.get(c)))}</td>"
            for c in cols)
        body.append(f"<tr>{cells}</tr>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>JOCKY Export — {_html.escape(case_id)}</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;padding:20px}}
table{{border-collapse:collapse;background:#fff;width:100%;font-size:12.5px}}
th{{background:#13315c;color:#fff;padding:6px 9px;text-align:left}}
td{{border-bottom:1px solid #e4eaf1;padding:5px 9px}}</style></head>
<body><h2>JOCKY Export — {_html.escape(case_id)}</h2>
<p>{len(rows)} records</p>
<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>
</body></html>"""


# --------------------------------------------------------------------------
# Builtins (manual Appendix B subset)
# --------------------------------------------------------------------------

def _bi_len(vm: JockyVM, x: Any) -> int:
    if isinstance(x, (str, list, dict)):
        return len(x)
    raise errors.type_error(f"len() requires str/list/map (got {vm.typeof(x)})")


def _bi_str(vm: JockyVM, x: Any) -> str:
    return vm.to_display(x)


def _bi_int(vm: JockyVM, x: Any) -> int:
    try:
        return int(float(x)) if isinstance(x, str) and "." in x else int(x)
    except (TypeError, ValueError) as exc:
        raise errors.type_error(f'int("{x}") conversion failed') from exc


def _bi_float(vm: JockyVM, x: Any) -> float:
    try:
        return float(x)
    except (TypeError, ValueError) as exc:
        raise errors.type_error(f'float("{x}") conversion failed') from exc


def _bi_bool(vm: JockyVM, x: Any) -> bool:
    return vm.truthy(x)


def _bi_range(vm: JockyVM, *args) -> list:
    try:
        return list(range(*[int(a) for a in args]))
    except (TypeError, ValueError) as exc:
        raise errors.type_error("range() requires integers") from exc


def _bi_hash(vm: JockyVM, x: Any, algo: str = "sha256") -> str:
    algo = str(algo).lower()
    if algo not in ("sha256", "md5", "sha1"):
        raise errors.invalid_filter(f'hash algorithm "{algo}" not supported')
    if isinstance(x, str) and os.path.isfile(x):
        h = hashlib.new(algo)
        with open(x, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    return hashlib.new(algo, vm.to_display(x).encode("utf-8")).hexdigest()


def _bi_typeof(vm: JockyVM, x: Any) -> str:
    return vm.typeof(x)


def _bi_env(vm: JockyVM, key: str) -> str:
    import os as _os
    return _os.environ.get(str(key), "")


def _bi_sleep(vm: JockyVM, ms: int) -> None:
    time.sleep(max(0, int(ms)) / 1000)


def _bi_now(vm: JockyVM) -> str:
    return now_iso()


def _bi_epoch(vm: JockyVM) -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _bi_upper(vm: JockyVM, x: Any) -> str:
    return vm.to_display(x).upper()


def _bi_lower(vm: JockyVM, x: Any) -> str:
    return vm.to_display(x).lower()


def _bi_keys(vm: JockyVM, x: Any) -> list:
    if not isinstance(x, dict):
        raise errors.type_error(f"keys() requires a map (got {vm.typeof(x)})")
    return list(x.keys())


_BUILTINS = {
    "len": _bi_len, "str": _bi_str, "int": _bi_int, "float": _bi_float,
    "bool": _bi_bool, "range": _bi_range, "hash": _bi_hash,
    "typeof": _bi_typeof, "env": _bi_env, "sleep": _bi_sleep,
    "now": _bi_now, "epoch": _bi_epoch,
    "upper": _bi_upper, "lower": _bi_lower, "keys": _bi_keys,
}
