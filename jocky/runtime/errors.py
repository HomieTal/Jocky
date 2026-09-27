"""JOCKY error codes (manual Appendix C) plus prototype extensions.

Manual codes:
    E001 AUTH_MISSING        E050 NAME_ERROR
    E002 AUTH_EXPIRED        E060 COLLECT_FAILED
    E003 AUTH_INVALID_SIG    E070 EXPORT_FAILED
    E010 PRIV_DENIED         E080 IOC_PARSE_ERROR
    E020 PLATFORM_MISMATCH   E090 NETWORK_ERROR
    E030 MODULE_NOT_FOUND    E100 RUNTIME_ERROR
    E040 TYPE_ERROR

Prototype extensions (documented in README):
    E004 AUTH_SCOPE_DENIED   E104 MALFORMED_IR
    E101 PARSE_ERROR         E105 EVIDENCE_WRITE_FAILED
    E102 INVALID_FIELD       E106 UNSUPPORTED_FEATURE
    E103 INVALID_FILTER      E107 CAPABILITY_DENIED
"""

from __future__ import annotations

from typing import Optional


class JockyError(Exception):
    """A JOCKY runtime/compile error carrying a manual error code + source line."""

    def __init__(self, code: str, name: str, message: str, line: int = 0,
                 context: str = ""):
        self.code = code
        self.name = name
        self.message = message
        self.line = line
        self.context = context
        super().__init__(self.format())

    def format(self) -> str:
        loc = f" at line {self.line}" if self.line else ""
        out = f"[{self.code} {self.name}] {self.message}{loc}"
        if self.context:
            out += "\n    | " + self.context
        return out


# --- manual error constructors -------------------------------------------

def auth_missing(msg: str, line: int = 0) -> JockyError:
    return JockyError("E001", "AUTH_MISSING", msg, line)


def auth_expired(msg: str, line: int = 0) -> JockyError:
    return JockyError("E002", "AUTH_EXPIRED", msg, line)


def auth_invalid(msg: str, line: int = 0) -> JockyError:
    return JockyError("E003", "AUTH_INVALID_SIG", msg, line)


def auth_scope_denied(msg: str, line: int = 0) -> JockyError:
    return JockyError("E004", "AUTH_SCOPE_DENIED", msg, line)


def priv_denied(msg: str, line: int = 0) -> JockyError:
    return JockyError("E010", "PRIV_DENIED", msg, line)


def platform_mismatch(msg: str, line: int = 0) -> JockyError:
    return JockyError("E020", "PLATFORM_MISMATCH", msg, line)


def module_not_found(msg: str, line: int = 0) -> JockyError:
    return JockyError("E030", "MODULE_NOT_FOUND", msg, line)


def type_error(msg: str, line: int = 0) -> JockyError:
    return JockyError("E040", "TYPE_ERROR", msg, line)


def name_error(msg: str, line: int = 0) -> JockyError:
    return JockyError("E050", "NAME_ERROR", msg, line)


def collect_failed(msg: str, line: int = 0) -> JockyError:
    return JockyError("E060", "COLLECT_FAILED", msg, line)


def export_failed(msg: str, line: int = 0) -> JockyError:
    return JockyError("E070", "EXPORT_FAILED", msg, line)


def runtime_error(msg: str, line: int = 0) -> JockyError:
    return JockyError("E100", "RUNTIME_ERROR", msg, line)


# --- prototype extension constructors --------------------------------------

def invalid_field(msg: str, line: int = 0) -> JockyError:
    return JockyError("E102", "INVALID_FIELD", msg, line)


def invalid_filter(msg: str, line: int = 0) -> JockyError:
    return JockyError("E103", "INVALID_FILTER", msg, line)


def malformed_ir(msg: str, line: int = 0) -> JockyError:
    return JockyError("E104", "MALFORMED_IR", msg, line)


def evidence_write_failed(msg: str, line: int = 0) -> JockyError:
    return JockyError("E105", "EVIDENCE_WRITE_FAILED", msg, line)


def unsupported(msg: str, line: int = 0) -> JockyError:
    return JockyError("E106", "UNSUPPORTED_FEATURE", msg, line)


def capability_denied(msg: str, line: int = 0) -> JockyError:
    return JockyError("E107", "CAPABILITY_DENIED", msg, line)
