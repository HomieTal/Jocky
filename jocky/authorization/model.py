"""JOCKY authorization model (manual §1.5, Appendix A).

Every executable script must carry an @authorization block:

    @authorization {
        case_id: "DEMO-001"
        investigator: "Demo Analyst"
        authorized_by: "Self-Test"
        scope: "mem, net, reg, log"
        valid_until: "2026-12-31T23:59:59Z"
    }

The runtime refuses execution when the block is missing, incomplete,
expired, or when a requested module is outside the declared scope.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Optional, Set

from jocky.runtime import errors

REQUIRED_FIELDS = ("case_id", "investigator", "authorized_by", "scope", "valid_until")

# scope aliases -> canonical module namespaces
_SCOPE_ALIASES = {
    "mem": "mem", "memory": "mem",
    "net": "net", "network": "net",
    "disk": "disk", "file": "disk", "files": "disk", "filesystem": "disk", "fs": "disk",
    "reg": "reg", "registry": "reg",
    "log": "log", "logs": "log", "eventlog": "log", "events": "log",
    "sys": "sys", "system": "sys", "sysinfo": "sys",
}


def normalize_scope(scope_text: str) -> Set[str]:
    """Parse 'mem, net, registry' -> {'mem','net','reg'} (unknown names kept as-is)."""
    out: Set[str] = set()
    for token in scope_text.replace(";", ",").split(","):
        token = token.strip().lower()
        if not token:
            continue
        out.add(_SCOPE_ALIASES.get(token, token))
    return out


def _parse_iso8601(value: str) -> Optional[_dt.datetime]:
    v = value.strip()
    try:
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = _dt.datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt
    except ValueError:
        return None


@dataclass
class Authorization:
    case_id: str = ""
    investigator: str = ""
    organization: str = ""
    authorized_by: str = ""
    scope: str = ""
    valid_until: str = ""
    extra: dict = field(default_factory=dict)
    line: int = 0

    # ------------------------------------------------------------------

    @classmethod
    def from_fields(cls, fields: dict, line: int = 0) -> "Authorization":
        known = {"case_id", "investigator", "organization", "authorized_by",
                 "scope", "valid_until"}
        auth = cls(line=line)
        for key, value in fields.items():
            if key in known:
                setattr(auth, key, str(value))
            else:
                auth.extra[key] = value
        return auth

    def scope_modules(self) -> Set[str]:
        return normalize_scope(self.scope)

    def valid_until_dt(self) -> Optional[_dt.datetime]:
        return _parse_iso8601(self.valid_until)

    # ------------------------------------------------------------------

    def validate(self, now: Optional[_dt.datetime] = None) -> None:
        """Raise E001/E003/E002 for missing, malformed or expired authorization."""
        now = now or _dt.datetime.now(_dt.timezone.utc)
        missing = [f for f in REQUIRED_FIELDS if not getattr(self, f, "").strip()]
        if missing:
            raise errors.auth_missing(
                "authorization block is missing required field(s): "
                + ", ".join(missing)
                + " (required: " + ", ".join(REQUIRED_FIELDS) + ")",
                line=self.line)
        if not self.scope_modules():
            raise errors.auth_missing("authorization scope is empty", line=self.line)
        until = self.valid_until_dt()
        if until is None:
            raise errors.auth_invalid(
                f'valid_until "{self.valid_until}" is not an ISO-8601 timestamp '
                '(expected e.g. "2026-12-31T23:59:59Z")', line=self.line)
        if until < now:
            raise errors.auth_expired(
                f"authorization expired on {self.valid_until} "
                f"(current time {now.strftime('%Y-%m-%dT%H:%M:%SZ')})",
                line=self.line)

    def check_module_in_scope(self, module: str, line: int = 0) -> None:
        """Raise E004 when a collect targets a module outside the declared scope."""
        if module not in self.scope_modules():
            allowed = ", ".join(sorted(self.scope_modules()))
            raise errors.auth_scope_denied(
                f'module "{module}" is outside the authorized scope '
                f'(declared scope: {allowed or "<empty>"}) — widen the scope '
                "field in @authorization or remove the collect statement",
                line=line)
