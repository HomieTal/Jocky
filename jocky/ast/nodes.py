"""AST node definitions for the JOCKY language.

Every node carries the source line (1-based) so that validation and
runtime errors can point at the offending statement, as required by the
JOCKY manual's error-handling contract.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class Node:
    """Base class for all AST nodes."""

    def __init__(self, line: int = 0, col: int = 0):
        self.line = max(1, line or 1)
        self.col = col or 0

    def fields(self) -> Dict[str, Any]:
        return {
            k: getattr(self, k)
            for k in self.__dict__
            if not k.startswith("_") and k not in ("line", "col")
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        inner = ", ".join(f"{k}={v!r}" for k, v in self.fields().items())
        return f"{type(self).__name__}({inner}) @L{self.line}"


# --------------------------------------------------------------------------
# Directives
# --------------------------------------------------------------------------

class Authorization(Node):
    def __init__(self, fields: Dict[str, str], line: int = 0):
        super().__init__(line)
        self.fields = fields


class Requires(Node):
    def __init__(self, items: List[str], line: int = 0):
        super().__init__(line)
        self.items = items  # e.g. ["privilege.user", "PROCESS_READ"]


class PlatformDecl(Node):
    def __init__(self, name: str, line: int = 0):
        super().__init__(line)
        self.name = name  # "windows" | "linux" | "macos"


class PluginDecl(Node):
    def __init__(self, name: str, line: int = 0):
        super().__init__(line)
        self.name = name


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------

class Literal(Node):
    def __init__(self, value: Any, line: int = 0):
        super().__init__(line)
        self.value = value


class Name(Node):
    """Possibly dotted identifier, e.g. ``process.memory_mb`` or ``procs``."""

    def __init__(self, path: str, line: int = 0):
        super().__init__(line)
        self.path = path


class FString(Node):
    """Interpolated string: parts are ('lit', text) or ('expr', Node)."""

    def __init__(self, parts: List[Tuple[str, Any]], line: int = 0):
        super().__init__(line)
        self.parts = parts


class ListLit(Node):
    def __init__(self, items: List[Node], line: int = 0):
        super().__init__(line)
        self.items = items


class MapLit(Node):
    def __init__(self, pairs: List[Tuple[str, Node]], line: int = 0):
        super().__init__(line)
        self.pairs = pairs


class BinOp(Node):
    def __init__(self, op: str, left: Node, right: Node, line: int = 0):
        super().__init__(line)
        self.op = op
        self.left = left
        self.right = right


class Compare(Node):
    def __init__(self, op: str, left: Node, right: Node, line: int = 0):
        super().__init__(line)
        self.op = op  # == != < > <= >= in notin matches contains startswith endswith
        self.left = left
        self.right = right


class BoolOp(Node):
    def __init__(self, op: str, values: List[Node], line: int = 0):
        super().__init__(line)
        self.op = op  # 'and' | 'or'
        self.values = values


class UnaryOp(Node):
    def __init__(self, op: str, operand: Node, line: int = 0):
        super().__init__(line)
        self.op = op  # 'not' | '-' | '~' | '!'
        self.operand = operand


class Index(Node):
    def __init__(self, obj: Node, index: Node, line: int = 0):
        super().__init__(line)
        self.obj = obj
        self.index = index


class Slice(Node):
    def __init__(self, obj: Node, start: Optional[Node], stop: Optional[Node], line: int = 0):
        super().__init__(line)
        self.obj = obj
        self.start = start
        self.stop = stop


class Member(Node):
    def __init__(self, obj: Node, name: str, line: int = 0):
        super().__init__(line)
        self.obj = obj
        self.name = name


class Call(Node):
    def __init__(self, callee: Node, args: List[Node], kwargs: Dict[str, Node], line: int = 0):
        super().__init__(line)
        self.callee = callee
        self.args = args
        self.kwargs = kwargs


class CollectExpr(Node):
    """``collect <module>.<entity>(args?)`` or ``snapshot ...``."""

    def __init__(self, module: str, entity: str, args: List[Node],
                 kwargs: Dict[str, Node], snapshot: bool, line: int = 0):
        super().__init__(line)
        self.module = module
        self.entity = entity
        self.args = args
        self.kwargs = kwargs
        self.snapshot = snapshot


# --------------------------------------------------------------------------
# Pipeline stages
# --------------------------------------------------------------------------

class WhereStage(Node):
    def __init__(self, expr: Node, line: int = 0):
        super().__init__(line)
        self.expr = expr


class SortStage(Node):
    def __init__(self, field: str, descending: bool, line: int = 0):
        super().__init__(line)
        self.field = field
        self.descending = descending


class LimitStage(Node):
    def __init__(self, count: int, line: int = 0):
        super().__init__(line)
        self.count = count


class Pipeline(Node):
    def __init__(self, source: Node, stages: List[Node], line: int = 0):
        super().__init__(line)
        self.source = source
        self.stages = stages


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------

class LetStmt(Node):
    def __init__(self, name: str, value: Node, const: bool = False,
                 type_ann: Optional[str] = None, line: int = 0):
        super().__init__(line)
        self.name = name
        self.value = value
        self.const = const
        self.type_ann = type_ann


class AssignStmt(Node):
    def __init__(self, name: str, value: Node, line: int = 0):
        super().__init__(line)
        self.name = name
        self.value = value


class PrintStmt(Node):
    def __init__(self, expr: Node, line: int = 0):
        super().__init__(line)
        self.expr = expr


class AlertStmt(Node):
    def __init__(self, severity: str, expr: Node, line: int = 0):
        super().__init__(line)
        self.severity = severity  # LOW | MEDIUM | HIGH | CRITICAL
        self.expr = expr


class ExportStmt(Node):
    def __init__(self, expr: Optional[Node], fmt: str, path: Optional[str], line: int = 0):
        super().__init__(line)
        self.expr = expr
        self.fmt = fmt  # json | csv | html
        self.path = path


class IfStmt(Node):
    def __init__(self, branches: List[Tuple[Node, List[Node]]],
                 else_body: Optional[List[Node]], line: int = 0):
        super().__init__(line)
        self.branches = branches
        self.else_body = else_body or []


class ForeachStmt(Node):
    def __init__(self, var: str, iterable: Node, body: List[Node], line: int = 0):
        super().__init__(line)
        self.var = var
        self.iterable = iterable
        self.body = body


class WhileStmt(Node):
    def __init__(self, cond: Node, body: List[Node], line: int = 0):
        super().__init__(line)
        self.cond = cond
        self.body = body


class FuncDef(Node):
    def __init__(self, name: str, params: List[Tuple[str, Optional[Node]]],
                 body: List[Node], line: int = 0):
        super().__init__(line)
        self.name = name
        self.params = params  # [(name, default_expr_or_None)]
        self.body = body


class ReturnStmt(Node):
    def __init__(self, expr: Optional[Node], line: int = 0):
        super().__init__(line)
        self.expr = expr


class BreakStmt(Node):
    pass


class ContinueStmt(Node):
    pass


class ExprStmt(Node):
    def __init__(self, expr: Node, line: int = 0):
        super().__init__(line)
        self.expr = expr


class Program(Node):
    def __init__(self, directives: List[Node], statements: List[Node], line: int = 1):
        super().__init__(line)
        self.directives = directives
        self.statements = statements
