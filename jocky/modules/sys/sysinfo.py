"""sys module: host system information (read-only, manual §1.2 host block)."""

from __future__ import annotations

import datetime as _dt
import os
import platform
import socket
from typing import Any, Dict, List

from jocky.modules.base import CollectContext, Collector

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def _windows_product_name() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product, _ = winreg.QueryValueEx(key, "ProductName")
            try:
                display, _ = winreg.QueryValueEx(key, "DisplayVersion")
                return f"{product} ({display})"
            except OSError:
                return str(product)
    except Exception:
        return f"{platform.system()} {platform.release()}"


class SysInfoCollector(Collector):
    module = "sys"
    entity = "info"
    title = "System Information"
    record_type = "system"
    fields = ["hostname", "domain", "os", "version", "build", "arch",
              "processor", "cores", "memory_total_mb", "memory_used_mb",
              "boot_time", "uptime_hours", "user", "elevated", "python"]
    columns = ["hostname", "os", "version", "arch", "user", "elevated",
               "memory_total_mb", "uptime_hours"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        uname = platform.uname()
        record: Dict[str, Any] = {
            "hostname": uname.node or socket.gethostname(),
            "domain": os.environ.get("USERDOMAIN", ""),
            "os": _windows_product_name(),
            "version": uname.version,
            "build": platform.version(),
            "arch": uname.machine or "AMD64",
            "processor": uname.processor or platform.processor(),
            "cores": os.cpu_count(),
            "memory_total_mb": None,
            "memory_used_mb": None,
            "boot_time": "",
            "uptime_hours": None,
            "user": os.environ.get("USERNAME", ""),
            "elevated": None,
            "python": platform.python_version(),
        }
        if psutil is not None:
            try:
                vm = psutil.virtual_memory()
                record["memory_total_mb"] = round(vm.total / 1048576, 1)
                record["memory_used_mb"] = round(vm.used / 1048576, 1)
            except Exception:
                pass
            try:
                boot = psutil.boot_time()
                record["boot_time"] = _dt.datetime.fromtimestamp(
                    boot, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                record["uptime_hours"] = round(
                    (_dt.datetime.now(_dt.timezone.utc).timestamp() - boot) / 3600, 1)
            except Exception:
                pass
        try:
            from jocky.runtime.capabilities import is_elevated
            record["elevated"] = is_elevated()
        except Exception:
            pass
        return [record]
