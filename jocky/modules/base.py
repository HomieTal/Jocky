"""Base class and runtime context for JOCKY forensic collectors.

Every collector is strictly read-only: it observes system state and never
mutates it. Collectors return a list of plain dict records shaped after
the forensic types defined in manual §5.3.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class CollectContext:
    """Runtime services handed to collectors (logging + safety limits)."""

    def __init__(self, log: Optional[Callable[[str], None]] = None,
                 progress: Optional[Callable[[str], None]] = None):
        self.log = log or (lambda msg: None)
        self.progress = progress or (lambda msg: None)


class Collector:
    """A single collectible entity, e.g. ``collect mem.processes``."""

    #: "mem", "net", "reg", "log", "disk", "sys"
    module: str = ""
    #: "processes", "connections", ...
    entity: str = ""
    #: human title shown in results / reports
    title: str = ""
    #: forensic record type prefix used in where clauses ("process", ...)
    record_type: str = ""
    #: documented record fields (manual §5.3 + module chapters)
    fields: List[str] = []
    #: preferred columns for the results viewer
    columns: List[str] = []
    #: optional argument spec: {name: {"type": "str|int|float|bool", "default": ...}}
    arg_spec: Dict[str, Dict[str, Any]] = {}

    def collect(self, args: List[Any], kwargs: Dict[str, Any],
                ctx: CollectContext) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # ------------------------------------------------------------------

    def resolve_args(self, args: List[Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Merge positional + keyword args against arg_spec into a kwargs dict."""
        spec_names = list(self.arg_spec.keys())
        resolved: Dict[str, Any] = {}
        for name, spec in self.arg_spec.items():
            resolved[name] = spec.get("default")
        for i, value in enumerate(args):
            if i < len(spec_names):
                resolved[spec_names[i]] = value
        for key, value in kwargs.items():
            if key not in self.arg_spec:
                from jocky.runtime import errors
                raise errors.invalid_filter(
                    f'collect {self.module}.{self.entity}: unknown argument "{key}" '
                    f"(accepted: {', '.join(spec_names) or '<none>'})")
            resolved[key] = value
        for name, spec in self.arg_spec.items():
            value = resolved[name]
            if value is None and spec.get("required"):
                from jocky.runtime import errors
                raise errors.collect_failed(
                    f'collect {self.module}.{self.entity}: argument "{name}" is required')
            if value is not None:
                resolved[name] = self._coerce(name, value, spec.get("type", "str"))
        return resolved

    def _coerce(self, name: str, value: Any, want: str) -> Any:
        if want == "str" and not isinstance(value, str):
            return str(value)
        if want in ("int", "float"):
            try:
                return float(value) if want == "float" else int(value)
            except (TypeError, ValueError):
                from jocky.runtime import errors
                raise errors.invalid_filter(
                    f'collect {self.module}.{self.entity}: argument "{name}" '
                    f"must be a number") from None
        if want == "bool":
            if isinstance(value, bool):
                return value
            from jocky.runtime import errors
            raise errors.invalid_filter(
                f'collect {self.module}.{self.entity}: argument "{name}" must be true/false')
        return value
