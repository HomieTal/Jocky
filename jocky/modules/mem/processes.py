"""mem module: process forensics (read-only, manual §8.1).

Implements the manual's `process` forensic type (§5.3): pid, ppid, name,
path, cmdline, memory_mb, cpu_pct, is_signed, has_unsigned_code,
create_time, user, modules, connections. CPU usage is measured with a
short two-pass sampling window. Access-denied fields degrade gracefully.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from jocky.modules.base import CollectContext, Collector
from jocky.modules import winutil

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

_PROCESS_ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "memory_info",
                  "create_time", "username", "status", "num_threads"]


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


class ProcessesCollector(Collector):
    module = "mem"
    entity = "processes"
    title = "Running Processes"
    record_type = "process"
    fields = ["pid", "ppid", "name", "path", "cmdline", "memory_mb", "cpu_pct",
              "is_signed", "signature_status", "has_unsigned_code", "create_time",
              "user", "status", "threads", "modules", "modules_count",
              "connections", "connections_count", "parent_name"]
    columns = ["pid", "name", "memory_mb", "cpu_pct", "user", "is_signed",
               "path", "create_time"]
    arg_spec = {
        "cpu_sample": {"type": "float", "default": 0.25},
        "with_modules": {"type": "bool", "default": True},
        "with_connections": {"type": "bool", "default": True},
    }

    def __init__(self):
        self._sig = winutil.SignatureCache()

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        if psutil is None:
            from jocky.runtime import errors
            raise errors.collect_failed("psutil is not available on this host")
        opts = self.resolve_args(args, kwargs)
        ctx.progress("enumerating processes...")

        # pass 1: snapshot attributes + prime CPU counters
        procs: List = []
        for proc in psutil.process_iter(attrs=_PROCESS_ATTRS):
            info = proc.info
            if info.get("pid") is None:
                continue
            try:
                proc.cpu_percent(interval=None)  # prime
            except Exception:
                pass
            procs.append((proc, info))

        if opts["cpu_sample"]:
            time.sleep(float(opts["cpu_sample"]))

        # connections by pid for the owning-process view
        conn_by_pid: Dict[int, int] = {}
        if opts["with_connections"]:
            for c in _safe(lambda: psutil.net_connections(kind="inet"), []) or []:
                pid = getattr(c, "pid", None)
                if pid:
                    conn_by_pid[pid] = conn_by_pid.get(pid, 0) + 1

        name_by_pid = {info["pid"]: (info.get("name") or "") for _, info in procs}
        ncpu = _safe(lambda: psutil.cpu_count(), 1) or 1
        records: List[Dict[str, Any]] = []
        for proc, info in procs:
            pid = info["pid"]
            cpu = 0.0
            if opts["cpu_sample"]:
                cpu = _safe(lambda p=proc: p.cpu_percent(interval=None), 0.0) or 0.0
            exe = info.get("exe") or ""
            # kernel pseudo-processes report a pseudo-path ("Registry",
            # "MemCompression") — they have no executable file
            if exe and not os.path.isfile(exe):
                exe = ""
            mem = info.get("memory_info")
            modules: List[str] = []
            if opts["with_modules"] and pid is not None:
                maps = _safe(lambda p=proc: p.memory_maps(), None)
                if maps:
                    seen = []
                    for m in maps[:400]:
                        path_ = getattr(m, "path", "") or ""
                        if path_ and path_ not in seen:
                            seen.append(path_)
                    modules = [p.split("\\")[-1] for p in seen][:60]
            status = self._sig.verify(exe) if exe else "unknown"
            records.append({
                "pid": pid,
                "ppid": info.get("ppid"),
                "name": info.get("name") or "",
                "path": exe or "",
                "cmdline": " ".join(info.get("cmdline") or []) if info.get("cmdline") else "",
                "memory_mb": round(getattr(mem, "rss", 0) / 1048576, 1) if mem else None,
                "cpu_pct": round(min(cpu / max(ncpu, 1), 100.0), 1),
                "is_signed": status in ("signed", "catalog"),
                "signature_status": status,
                # not detectable from user space in the prototype:
                "has_unsigned_code": False,
                "create_time": winutil.ts_to_iso(info["create_time"]) if info.get("create_time") else "",
                "user": info.get("username") or "",
                "status": info.get("status") or "",
                "threads": info.get("num_threads"),
                "modules": modules,
                "modules_count": len(modules),
                "connections": [],
                "connections_count": conn_by_pid.get(pid, 0),
                "parent_name": name_by_pid.get(info.get("ppid"), ""),
            })
        ctx.progress(f"{len(records)} processes enumerated; verifying signatures...")
        self._sig.flush()
        for rec in records:
            st = self._sig.final_status(rec["path"]) if rec["path"] else "unknown"
            rec["signature_status"] = st
            rec["is_signed"] = st in ("signed", "catalog")
        records.sort(key=lambda r: (r.get("memory_mb") or 0), reverse=True)
        return records


class FindProcessBuiltin:
    """mem.find_process(name) — manual Appendix B."""

    def __init__(self, collector: ProcessesCollector):
        self._collector = collector

    def __call__(self, name: str) -> Optional[Dict[str, Any]]:
        ctx = CollectContext()
        for rec in self._collector.collect([], {}, ctx):
            if rec.get("name", "").lower() == name.lower():
                return rec
        return None
