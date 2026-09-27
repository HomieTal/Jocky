"""JOCKY parser: Lark LALR(1) grammar + newline postlexer + AST transformer.

Pipeline: .jky source -> Lark tokens -> postlexer -> parse tree -> AST.
"""

from __future__ import annotations

import os
from typing import Iterator, List, Optional, Tuple

from lark import Lark, Token, Transformer, v_args
from lark.exceptions import LexError, ParseError, UnexpectedInput

from jocky.ast import nodes as A

GRAMMAR_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "grammar", "jocky.lark")

# --------------------------------------------------------------------------
# Postlexer
#
# The JOCKY manual style places pipeline clauses on their own lines:
#
#     let suspicious = procs
#       where process.memory_mb > 500
#         and process.is_signed == false
#
# We therefore drop NEWLINE tokens:
#   * inside ( ) and [ ] brackets,
#   * directly after a comma or an opening brace,
#   * directly before a continuation keyword (where/and/or/sort/limit/...),
# so they can never terminate a statement in those positions.
# --------------------------------------------------------------------------

CONTINUATION_NEXT = {
    "WHERE", "SORT", "LIMIT", "AND", "OR", "PIPE", "TO", "BY", "ASC",
    "DESC", "ELSE", "ELIF", "IN",
}
CONTINUATION_PREV = {"COMMA", "LBRACE"}

OPEN_BRACKETS = {"LPAR", "LSQB"}
CLOSE_BRACKETS = {"RPAR", "RSQB"}


class JockyPostLex:
    """Filters the token stream before parsing (Lark PostLex protocol)."""

    always_accept = ("_NL",)

    def process(self, stream: Iterator[Token]) -> Iterator[Token]:
        prev: Optional[Token] = None
        pending: Optional[Token] = None
        depth = 0
        it = iter(stream)
        while True:
            if pending is not None:
                tok, pending = pending, None
            else:
                try:
                    tok = next(it)
                except StopIteration:
                    return
            if tok.type == "_NL":
                try:
                    nxt = next(it)
                except StopIteration:
                    nxt = None
                skip = (depth > 0
                        or (prev is not None and prev.type in CONTINUATION_PREV)
                        or (nxt is not None and nxt.type in CONTINUATION_NEXT))
                if not skip:
                    yield tok
                if nxt is not None:
                    pending = nxt
                continue
            if tok.type in OPEN_BRACKETS:
                depth += 1
            elif tok.type in CLOSE_BRACKETS and depth > 0:
                depth -= 1
            yield tok
            prev = tok


# --------------------------------------------------------------------------
# String / number literal decoding
# --------------------------------------------------------------------------

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\",
            "0": "\0", "b": "\b", "f": "\f"}


def decode_string(token_text: str) -> str:
    """Decode a quoted JOCKY string literal (token includes the quotes)."""
    body = token_text[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            if nxt == "u" and i + 5 < len(body):
                try:
                    out.append(chr(int(body[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def raw_string(token_text: str) -> str:
    return token_text[2:-1]


def parse_int(token_text: str) -> int:
    low = token_text.lower()
    if low.startswith("0x"):
        return int(token_text, 16)
    if low.startswith("0b"):
        return int(token_text, 2)
    if low.startswith("0o"):
        return int(token_text, 8)
    return int(token_text)


# --------------------------------------------------------------------------
# Transformer: Lark tree -> JOCKY AST
# --------------------------------------------------------------------------

_CMP_MAP = {
    "EQ": "==", "NEQ": "!=", "LT": "<", "GT": ">", "LE": "<=", "GE": ">=",
    "IN": "in", "MATCHES": "matches", "CONTAINS": "contains",
    "STARTSWITH": "startswith", "ENDSWITH": "endswith",
}


@v_args(meta=True)
class _AstBuilder(Transformer):

    def __init__(self, parser_ref=None):
        super().__init__()
        self._parser_ref = parser_ref

    # -- top level -----------------------------------------------------------

    def start(self, meta, items):
        return [i for i in items if i is not None]

    def sep(self, meta, items):
        return None

    def directive(self, meta, items):
        return items[0]

    # -- directives ----------------------------------------------------------

    def authorization_block(self, meta, items):
        fields = {}
        for it in items:
            if isinstance(it, tuple):
                fields[it[0]] = it[1]
        return A.Authorization(fields, line=meta.line)

    def auth_field(self, meta, items):
        name = str(items[0])
        value = items[-1]
        return (name, value)

    def field_value(self, meta, items):
        tok = items[0]
        if tok.type == "STRING":
            return decode_string(tok.value)
        if tok.type == "INT":
            return str(parse_int(tok.value))
        return str(float(tok.value))

    def requires_directive(self, meta, items):
        vals = [str(t) for t in items
                if hasattr(t, "type") and t.type in ("PRIVILEGE", "CAPABILITY")]
        return A.Requires(vals, line=meta.line)

    def platform_directive(self, meta, items):
        ident = [t for t in items if hasattr(t, "type") and t.type == "IDENT"]
        return A.PlatformDecl(str(ident[-1]), line=meta.line)

    def plugin_directive(self, meta, items):
        s = [t for t in items if hasattr(t, "type") and t.type == "STRING"]
        return A.PluginDecl(decode_string(s[-1].value), line=meta.line)

    # -- statements ------------------------------------------------------------

    def let_stmt(self, meta, items):
        name = str(items[1])
        value = items[-1]
        return A.LetStmt(name, value, const=False, line=meta.line)

    def const_stmt(self, meta, items):
        name = str(items[1])
        value = items[-1]
        return A.LetStmt(name, value, const=True, line=meta.line)

    def assign_stmt(self, meta, items):
        return A.AssignStmt(str(items[0]), items[-1], line=meta.line)

    def func_def(self, meta, items):
        name = str(items[1])
        params: List[Tuple[str, Optional[A.Node]]] = []
        body: List[A.Node] = []
        for it in items[2:]:
            if isinstance(it, list) and it and isinstance(it[0], tuple):
                params = it
            elif isinstance(it, list):
                body = it
        return A.FuncDef(name, params, body, line=meta.line)

    def params(self, meta, items):
        return [p for p in items if isinstance(p, tuple)]

    def param(self, meta, items):
        name = str(items[0])
        default = None
        for it in items[1:]:
            if isinstance(it, A.Node):
                default = it
        return (name, default)

    def type(self, meta, items):
        return str(items[0])

    def if_stmt(self, meta, items):
        branches: List[Tuple[A.Node, List[A.Node]]] = []
        else_body: List[A.Node] = []
        cond: Optional[A.Node] = None
        mode = "if"
        for it in items:
            if isinstance(it, list):
                if mode == "else":
                    else_body = it
                elif cond is not None:
                    branches.append((cond, it))
                    cond = None
            elif isinstance(it, A.Node):
                cond = it
            elif hasattr(it, "type"):
                mode = str(it)
        return A.IfStmt(branches, else_body, line=meta.line)

    def block(self, meta, items):
        return [i for i in items if isinstance(i, A.Node)]

    def while_stmt(self, meta, items):
        cond = None
        body: List[A.Node] = []
        for it in items:
            if isinstance(it, list):
                body = it
            elif isinstance(it, A.Node):
                cond = it
        return A.WhileStmt(cond, body, line=meta.line)

    def foreach_stmt(self, meta, items):
        var = str(items[1])
        iterable = None
        body: List[A.Node] = []
        for it in items[2:]:
            if isinstance(it, list):
                body = it
            elif isinstance(it, A.Node):
                iterable = it
        return A.ForeachStmt(var, iterable, body, line=meta.line)

    def export_stmt(self, meta, items):
        expr: Optional[A.Node] = None
        fmt = "json"
        path: Optional[str] = None
        toks = list(items)
        for idx, it in enumerate(toks):
            if hasattr(it, "type"):
                if it.type == "TO" and idx + 2 < len(toks):
                    fmt = str(toks[idx + 1])
                    path = decode_string(toks[idx + 2].value)
            elif isinstance(it, A.Node):
                expr = it
        return A.ExportStmt(expr, fmt, path, line=meta.line)

    def export_format(self, meta, items):
        return str(items[0]).lower()

    def severity(self, meta, items):
        return str(items[0])

    def alert_stmt(self, meta, items):
        severity = "MEDIUM"
        expr: Optional[A.Node] = None
        for it in items:
            if isinstance(it, str) and it in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                severity = it
            elif hasattr(it, "type") and it.type.startswith("SEV_"):
                severity = str(it)
            elif isinstance(it, A.Node):
                expr = it
        return A.AlertStmt(severity, expr, line=meta.line)

    def print_stmt(self, meta, items):
        return A.PrintStmt(items[-1], line=meta.line)

    def return_stmt(self, meta, items):
        expr = items[-1] if items and isinstance(items[-1], A.Node) else None
        return A.ReturnStmt(expr, line=meta.line)

    def break_stmt(self, meta, items):
        return A.BreakStmt(line=meta.line)

    def continue_stmt(self, meta, items):
        return A.ContinueStmt(line=meta.line)

    def expr_stmt(self, meta, items):
        return A.ExprStmt(items[-1], line=meta.line)

    # -- pipeline stages --------------------------------------------------------

    def stage(self, meta, items):
        for it in items:
            if isinstance(it, A.Node):
                return it
        return items[-1]

    def where_clause(self, meta, items):
        return A.WhereStage(items[-1], line=meta.line)

    def sort_clause(self, meta, items):
        field = ""
        desc = False
        for it in items:
            if isinstance(it, A.Name):
                field = it.path
            elif hasattr(it, "type") and it.type == "DESC":
                desc = True
        return A.SortStage(field, desc, line=meta.line)

    def limit_clause(self, meta, items):
        n = [t for t in items if hasattr(t, "type") and t.type == "INT"]
        return A.LimitStage(parse_int(n[0].value), line=meta.line)

    # -- expressions --------------------------------------------------------------

    def pipeline(self, meta, items):
        nodes = [i for i in items if isinstance(i, A.Node)]
        stages = [i for i in nodes if isinstance(i, (A.WhereStage, A.SortStage, A.LimitStage))]
        source = nodes[0] if nodes else None
        if not stages:
            return source
        return A.Pipeline(source, stages, line=meta.line)

    def disjunction(self, meta, items):
        vals = [i for i in items if isinstance(i, A.Node)]
        if len(vals) == 1:
            return vals[0]
        return A.BoolOp("or", vals, line=meta.line)

    def conjunction(self, meta, items):
        vals = [i for i in items if isinstance(i, A.Node)]
        if len(vals) == 1:
            return vals[0]
        return A.BoolOp("and", vals, line=meta.line)

    def inversion(self, meta, items):
        nots = [t for t in items if hasattr(t, "type") and t.type == "NOT"]
        val = [i for i in items if isinstance(i, A.Node)][0]
        for _ in nots:
            val = A.UnaryOp("not", val, line=meta.line)
        return val

    def compare_rest(self, meta, items):
        op_tok = [t for t in items if hasattr(t, "type")][0]
        right = [i for i in items if isinstance(i, A.Node)][0]
        return ("cmp", _CMP_MAP.get(op_tok.type, str(op_tok)), right, meta.line)

    def not_word_rest(self, meta, items):
        op_tok = [t for t in items if hasattr(t, "type")
                  and t.type in _CMP_MAP][0]
        right = [i for i in items if isinstance(i, A.Node)][0]
        return ("cmp", "not" + _CMP_MAP.get(op_tok.type, str(op_tok)), right, meta.line)

    def comparison(self, meta, items):
        nodes = [i for i in items if isinstance(i, A.Node)]
        rests = [i for i in items if isinstance(i, tuple)]
        if not rests:
            return nodes[0]
        left = nodes[0]
        for rest in rests:
            _, op, right, line = rest
            left = A.Compare(op, left, right, line=line)
        return left

    def _fold_binop(self, meta, items, ops):
        vals = [i for i in items if isinstance(i, A.Node)]
        toks = [str(t) for t in items if hasattr(t, "type")]
        if len(vals) == 1:
            return vals[0]
        result = vals[0]
        vi = 1
        for tok in toks:
            result = A.BinOp(tok, result, vals[vi], line=meta.line)
            vi += 1
        return result

    def sum(self, meta, items):
        return self._fold_binop(meta, items, {"+", "-"})

    def term(self, meta, items):
        return self._fold_binop(meta, items, {"*", "/", "//", "%"})

    def factor(self, meta, items):
        vals = [i for i in items if isinstance(i, A.Node)]
        if len(vals) == 1:
            return vals[0]
        return A.BinOp("**", vals[0], vals[1], line=meta.line)

    def unary(self, meta, items):
        op_toks = [t for t in items if hasattr(t, "type")
                   and t.type in ("MINUS", "TILDE", "BANG")]
        val = [i for i in items if isinstance(i, A.Node)]
        if not op_toks:
            return val[0]
        node = val[0]
        for t in reversed(op_toks):
            op = {"MINUS": "-", "TILDE": "~", "BANG": "not"}[t.type]
            node = A.UnaryOp(op, node, line=meta.line)
        return node

    def postfix(self, meta, items):
        base = [i for i in items if isinstance(i, A.Node)][0]
        trailers = [i for i in items if isinstance(i, tuple)]
        node = base
        for tr in trailers:
            kind = tr[0]
            if kind == "call":
                _, pos, kw = tr
                if isinstance(node, A.CollectExpr):
                    node.args = pos
                    node.kwargs = kw
                else:
                    node = A.Call(node, pos, kw, line=meta.line)
            elif kind == "index":
                node = A.Index(node, tr[1], line=meta.line)
            elif kind == "slice":
                node = A.Slice(node, tr[1], tr[2], line=meta.line)
            elif kind == "member":
                node = A.Member(node, tr[1], line=meta.line)
        return node

    def trailer(self, meta, items):
        kinds = [t.type for t in items if hasattr(t, "type")]
        if "DOT" in kinds:
            ident = [t for t in items if hasattr(t, "type") and t.type == "IDENT"]
            return ("member", str(ident[0]))
        if "COLON" in kinds:
            nodes = [i for i in items if isinstance(i, A.Node)]
            if len(nodes) == 2:
                return ("slice", nodes[0], nodes[1])
            if nodes:
                # a[:x] or a[x:]
                if kinds.index("COLON") == 1:
                    return ("slice", None, nodes[0])
                return ("slice", nodes[0], None)
            return ("slice", None, None)
        if "LPAR" in kinds:
            argl = [i for i in items if isinstance(i, tuple)]
            if argl:
                pos, kw = argl[0]
            else:
                pos, kw = [], {}
            return ("call", pos, kw)
        # index
        nodes = [i for i in items if isinstance(i, A.Node)]
        return ("index", nodes[0])

    def arglist(self, meta, items):
        pos: List[A.Node] = []
        kw = {}
        for it in items:
            if isinstance(it, tuple):
                kw[it[0]] = it[1]
            elif isinstance(it, A.Node):
                pos.append(it)
        return (pos, kw)

    def argument(self, meta, items):
        if len(items) >= 2 and hasattr(items[0], "type") and items[0].type == "IDENT":
            return (str(items[0]), items[-1])
        return items[-1]

    def literal(self, meta, items):
        tok = items[0]
        t = tok.type
        if t == "INT":
            return A.Literal(parse_int(tok.value), line=tok.line)
        if t == "FLOAT":
            return A.Literal(float(tok.value), line=tok.line)
        if t == "STRING":
            return A.Literal(decode_string(tok.value), line=tok.line)
        if t == "RSTRING":
            return A.Literal(raw_string(tok.value), line=tok.line)
        if t == "TRUE":
            return A.Literal(True, line=tok.line)
        if t == "FALSE":
            return A.Literal(False, line=tok.line)
        return A.Literal(None, line=tok.line)  # NULL

    def fstring(self, meta, items):
        tok = items[0]
        body = tok.value[2:-1]
        parts: List[Tuple[str, object]] = []
        buf: List[str] = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "{":
                if buf:
                    parts.append(("lit", _decode_frag("".join(buf)), ""))
                    buf = []
                depth = 1
                j = i + 1
                expr_src: List[str] = []
                while j < len(body) and depth > 0:
                    c = body[j]
                    if c in "{([":
                        depth += 1
                    elif c in "})]":
                        depth -= 1
                        if depth == 0:
                            break
                    expr_src.append(c)
                    j += 1
                src = "".join(expr_src).strip()
                # optional format spec after a top-level ':'
                spec = ""
                bdepth = 0
                for k, c in enumerate(src):
                    if c in "{([":
                        bdepth += 1
                    elif c in "})]":
                        bdepth -= 1
                    elif c == ":" and bdepth == 0:
                        spec = src[k + 1:].strip()
                        src = src[:k].strip()
                        break
                if src and self._parser_ref is not None:
                    parts.append(("expr",
                                  self._parser_ref.parse_expression(src, line=tok.line),
                                  spec))
                i = j + 1
                continue
            buf.append(ch)
            i += 1
        if buf:
            parts.append(("lit", _decode_frag("".join(buf)), ""))
        return A.FString(parts, line=tok.line)

    def name(self, meta, items):
        parts = [str(t) for t in items if getattr(t, "type", "") == "IDENT"]
        line = items[0].line if items and hasattr(items[0], "line") else meta.line
        return A.Name(".".join(parts), line=line)

    def collect_expr(self, meta, items):
        toks = [t for t in items if hasattr(t, "type")]
        snapshot = bool(toks) and toks[0].type == "SNAPSHOT"
        mp = [i for i in items if isinstance(i, tuple)][0]
        return A.CollectExpr(mp[0], mp[1], [], {}, snapshot, line=meta.line)

    def module_path(self, meta, items):
        idents = [str(t) for t in items if getattr(t, "type", "") == "IDENT"]
        return (idents[0], idents[1])

    def list_literal(self, meta, items):
        return A.ListLit([i for i in items if isinstance(i, A.Node)], line=meta.line)

    def map_literal(self, meta, items):
        pairs = [i for i in items if isinstance(i, tuple)]
        return A.MapLit(pairs, line=meta.line)

    def map_pair(self, meta, items):
        key = decode_string(items[0].value)
        return (key, items[-1])

    def expr_test(self, meta, items):
        return items[-1]

    def primary(self, meta, items):
        # parenthesized expression: LPAR expr RPAR — unwrap
        nodes = [i for i in items if isinstance(i, A.Node)]
        return nodes[-1]


def _decode_frag(text: str) -> str:
    return decode_string('"' + text.replace('"', '\\"') + '"')


# --------------------------------------------------------------------------
# Parser facade
# --------------------------------------------------------------------------

class JockyParser:
    """Lark-based JOCKY parser producing a jocky.ast Program."""

    _lark_instance: Optional[Lark] = None

    def __init__(self):
        if JockyParser._lark_instance is None:
            with open(GRAMMAR_PATH, "r", encoding="utf-8") as fh:
                grammar = fh.read()
            JockyParser._lark_instance = Lark(
                grammar,
                parser="lalr",
                start=["start", "expr_test"],
                postlex=JockyPostLex(),
                propagate_positions=True,
                maybe_placeholders=False,
            )
        self._lark = JockyParser._lark_instance
        self._transformer = _AstBuilder(self)

    def parse_expression(self, source: str, line: int = 1) -> A.Node:
        tree = self._lark.parse(source.strip(), start="expr_test")
        node = self._transformer.transform(tree)
        _bump_line(node, line)
        return node

    def parse(self, source: str) -> A.Program:
        tree = self._lark.parse(source, start="start")
        items = self._transformer.transform(tree)
        directives: List[A.Node] = []
        statements: List[A.Node] = []
        for it in items:
            if isinstance(it, (A.Authorization, A.Requires, A.PlatformDecl, A.PluginDecl)):
                directives.append(it)
            elif isinstance(it, A.Node):
                statements.append(it)
        return A.Program(directives, statements)


def _bump_line(node, line: int):
    if isinstance(node, (list, tuple)):
        for n in node:
            _bump_line(n, line)
        return
    if isinstance(node, A.Node):
        if getattr(node, "line", 1) <= 1:
            node.line = line
        for val in vars(node).values():
            if isinstance(val, (A.Node, list, tuple)):
                _bump_line(val, line)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class JockySyntaxError(Exception):
    """Syntax error with source line information (JOCKY error E101)."""

    def __init__(self, message: str, line: int = 0, col: int = 0,
                 context: str = ""):
        self.message = message
        self.line = line
        self.col = col
        self.context = context
        super().__init__(self.format())

    def format(self) -> str:
        loc = f"line {self.line}" + (f", column {self.col}" if self.col else "")
        out = f"[E101 PARSE_ERROR] {self.message}" + (f" ({loc})" if loc else "")
        if self.context:
            out += "\n    | " + self.context
        return out


def _context_line(source: str, line_no: int) -> str:
    if not line_no:
        return ""
    lines = source.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1][:200]
    return ""


def parse_source(source: str) -> A.Program:
    """Parse JOCKY source text into an AST Program, with friendly errors."""
    parser = JockyParser()
    try:
        return parser.parse(source)
    except UnexpectedInput as exc:
        line = getattr(exc, "line", 0) or 0
        col = getattr(exc, "column", 0) or 0
        tok = getattr(exc, "token", None)
        expected = ""
        try:
            exp = list(exc.expected or [])[:10]
            if exp:
                expected = "; expected one of: " + ", ".join(sorted(str(e) for e in exp))
        except Exception:
            pass
        found = f", found {tok!r}" if tok is not None else ""
        friendly = "invalid JOCKY syntax"
        if isinstance(exc, Exception) and "EOF" in str(type(exc).__name__):
            friendly = "unexpected end of file — missing '}' or unclosed bracket"
        raise JockySyntaxError(f"{friendly}{found}{expected}", line=line, col=col,
                               context=_context_line(source, line)) from exc
    except (LexError, ParseError) as exc:
        raise JockySyntaxError(f"invalid JOCKY syntax: {exc}") from exc
