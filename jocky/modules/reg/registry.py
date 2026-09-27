"""reg module: Windows registry forensics (read-only, manual §11).

Windows-only. Collectors never write to the registry.

- reg.autoruns   — Run / RunOnce keys (HKLM + HKU) with signature status
- reg.services   — service metadata from HKLM\\SYSTEM\\CurrentControlSet\\Services
- reg.mru        — Explorer ComDlg32 OpenSave MRU (most recently used files)
- reg.userassist — GUI program execution with ROT13-decoded names (§11.4)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jocky.modules.base import CollectContext, Collector
from jocky.modules import winutil

try:
    import winreg
except ImportError:  # pragma: no cover — non-Windows
    winreg = None


def _require_windows(line: int = 0):
    if winreg is None:
        from jocky.runtime import errors
        raise errors.platform_mismatch(
            "the reg module is Windows-only (manual §11) — this host is not Windows",
            line)


_HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE if winreg else None,
          "HKCU": winreg.HKEY_CURRENT_USER if winreg else None,
          "HKU": winreg.HKEY_USERS if winreg else None,
          "HKCR": winreg.HKEY_CLASSES_ROOT if winreg else None}

_VALUE_TYPES = {winreg.REG_SZ: "REG_SZ", winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
                winreg.REG_BINARY: "REG_BINARY", winreg.REG_DWORD: "REG_DWORD",
                winreg.REG_QWORD: "REG_QWORD", winreg.REG_MULTI_SZ: "REG_MULTI_SZ"} \
    if winreg else {}


def _hive_key(hive: str):
    try:
        return _HIVES[hive.upper()]
    except KeyError:
        from jocky.runtime import errors
        raise errors.invalid_filter(
            f'unknown registry hive "{hive}" (use HKLM, HKCU, HKU or HKCR)') from None


def _open_key(path: str):
    """Open 'HKLM\\SOFTWARE\\...' read-only; raises collect_failed if missing."""
    _require_windows()
    hive, _, sub = path.partition("\\")
    key = _hive_key(hive)
    try:
        return winreg.OpenKey(key, sub, 0, winreg.KEY_READ)
    except FileNotFoundError:
        from jocky.runtime import errors
        raise errors.collect_failed(f'registry key not found: "{path}"') from None
    except PermissionError:
        from jocky.runtime import errors
        raise errors.collect_failed(
            f'access denied reading registry key "{path}" '
            "(try running JOCKY as Administrator)") from None


def _stringify(value) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return value.hex()
    if isinstance(value, list):
        return " | ".join(str(v) for v in value)
    return str(value)


def _user_hives() -> List[str]:
    """All HKU user hives available (S-1-5-...)."""
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                    i += 1
                except OSError:
                    break
                if sub.startswith("S-1-") and sub.count("-") >= 3:
                    out.append(f"HKU\\{sub}")
    except Exception:
        pass
    return out or ["HKCU"]


class _RegBase(Collector):
    def _query_values(self, path: str) -> List[Dict[str, str]]:
        """All values of one key as {location, value, data, type}."""
        rows = []
        with _open_key(path) as key:
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
                rows.append({
                    "location": f"{path}\\{name}" if name else path,
                    "value": name or "(Default)",
                    "data": _stringify(data),
                    "type": _VALUE_TYPES.get(vtype, str(vtype)),
                })
        return rows


class AutorunsCollector(_RegBase):
    module = "reg"
    entity = "autoruns"
    title = "Registry Autoruns"
    record_type = "entry"
    fields = ["location", "value", "data", "type", "hive", "is_signed",
              "signature_status", "command"]
    columns = ["value", "data", "location", "signature_status"]

    _RUN_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    def __init__(self):
        self._sig = winutil.SignatureCache()

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        _require_windows()
        ctx.progress("reading Run / RunOnce autorun keys...")
        records: List[Dict[str, Any]] = []
        bases: List[str] = []
        for hive in _user_hives():
            bases.append(f"{hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
            # 32-bit view on 64-bit Windows
            bases.append(f"{hive}\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion")
        bases.append(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion")
        bases.append(r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion")
        seen_paths = set()
        for base in bases:
            for tail in (r"\Run", r"\RunOnce"):
                path = base + tail
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                try:
                    rows = self._query_values(path)
                except Exception:
                    continue
                for row in rows:
                    records.append(self._decorate(row))
        ctx.progress(f"{len(records)} autorun entries; verifying signatures...")
        self._sig.flush()
        for rec in records:
            st = self._sig.final_status(rec.get("_exe", ""))
            rec["signature_status"] = winutil.signature_label(st)
            rec["is_signed"] = st in ("signed", "catalog")
        return records

    def _decorate(self, row: Dict[str, str]) -> Dict[str, Any]:
        data = row["data"]
        exe = ""
        m = data.strip()
        if m:
            # strip quotes / arguments to get the executable path
            if m.startswith('"'):
                exe = m.split('"')[1]
            else:
                exe = m.split(" /")[0].split(" -")[0].strip()
        hive = row["location"].split("\\", 1)[0]
        return {
            "location": row["location"],
            "value": row["value"],
            "data": data,
            "type": row["type"],
            "hive": hive,
            "command": data,
            "_exe": exe,
            "signature_status": "Unknown",
            "is_signed": None,
        }


class ServicesCollector(_RegBase):
    module = "reg"
    entity = "services"
    title = "Windows Services"
    record_type = "entry"
    fields = ["location", "value", "data", "type", "service", "display_name",
              "image_path", "start_mode"]
    columns = ["service", "display_name", "image_path", "start_mode"]
    arg_spec = {"limit": {"type": "int", "default": 0}}

    _START_MODES = {0: "Boot", 1: "System", 2: "Automatic",
                    3: "Manual", 4: "Disabled"}

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        _require_windows()
        opts = self.resolve_args(args, kwargs) if (args or kwargs) else {}
        base = r"HKLM\SYSTEM\CurrentControlSet\Services"
        ctx.progress("enumerating service registry keys...")
        records: List[Dict[str, Any]] = []
        with _open_key(base) as key:
            i = 0
            names = []
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
                names.append(sub)
        for name in names:
            path = f"{base}\\{name}"
            values = {}
            try:
                with _open_key(path) as sk:
                    j = 0
                    while True:
                        try:
                            vn, vd, vt = winreg.EnumValue(sk, j)
                            j += 1
                        except OSError:
                            break
                        values[vn] = vd
            except Exception:
                continue
            start = values.get("Start")
            image = _stringify(values.get("ImagePath", ""))
            records.append({
                "location": path,
                "value": "ImagePath",
                "data": image,
                "type": "REG_EXPAND_SZ",
                "service": name,
                "display_name": _stringify(values.get("DisplayName", "")),
                "image_path": image,
                "start_mode": self._START_MODES.get(start, str(start) if start is not None else ""),
            })
            if opts.get("limit") and len(records) >= int(opts["limit"]):
                break
        return records


class MruCollector(_RegBase):
    module = "reg"
    entity = "mru"
    title = "OpenSave MRU (Explorer)"
    record_type = "entry"
    fields = ["location", "value", "data", "type", "timestamp", "path"]
    columns = ["data", "location", "timestamp"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        _require_windows()
        ctx.progress("reading OpenSave MRU...")
        records: List[Dict[str, Any]] = []
        targets = [r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"]
        legacy = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
        targets.append(legacy)
        for base in targets:
            try:
                with _open_key(base) as key:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, i)
                            i += 1
                        except OSError:
                            break
                        sub_path = f"{base}\\{sub}"
                        try:
                            with _open_key(sub_path) as sk:
                                j = 0
                                while True:
                                    try:
                                        vn, vd, vt = winreg.EnumValue(sk, j)
                                        j += 1
                                    except OSError:
                                        break
                                    records.append({
                                        "location": f"{sub_path}\\{vn}",
                                        "value": vn,
                                        "data": _extract_pidl_path(vd) or _stringify(vd),
                                        "type": _VALUE_TYPES.get(vt, str(vt)),
                                        "timestamp": "",
                                        "path": _extract_pidl_path(vd) or "",
                                    })
                        except Exception:
                            continue
            except Exception:
                continue
        return records


def _extract_pidl_path(data: bytes) -> str:
    """Best-effort extraction of a readable path from a PIDL blob."""
    if not isinstance(data, bytes):
        return ""
    try:
        text = data.decode("utf-16-le", errors="ignore")
        chunks = [c for c in text.split("\x00") if len(c) > 3 and "\\" in c]
        if chunks:
            return chunks[-1]
    except Exception:
        pass
    return ""


class UserAssistCollector(Collector):
    """reg.userassist — ROT13-decoded GUI execution history (manual §11.4)."""

    module = "reg"
    entity = "userassist"
    title = "UserAssist (GUI Program Execution)"
    record_type = "entry"
    fields = ["location", "value", "data", "type", "program", "run_count",
              "focus_count", "last_run", "session_id"]
    columns = ["program", "run_count", "last_run", "focus_count", "location"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        _require_windows()
        records: List[Dict[str, Any]] = []
        for hive in _user_hives():
            base = (f"{hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                    "Explorer\\UserAssist")
            try:
                with _open_key(base) as key:
                    i = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(key, i)
                            i += 1
                        except OSError:
                            break
                        count_path = f"{base}\\{guid}\\Count"
                        try:
                            with _open_key(count_path) as sk:
                                j = 0
                                while True:
                                    try:
                                        vn, vd, vt = winreg.EnumValue(sk, j)
                                        j += 1
                                    except OSError:
                                        break
                                    records.append(self._decode(count_path, vn, vd))
                        except Exception:
                            continue
            except Exception:
                continue
        return records

    def _decode(self, location: str, raw_name: str, data: bytes) -> Dict[str, Any]:
        program = winutil.rot13(raw_name)
        run_count = focus_count = session_id = None
        last_run = ""
        if isinstance(data, bytes) and len(data) >= 16:
            run_count = int.from_bytes(data[4:8], "little")
            focus_count = int.from_bytes(data[8:12], "little")
            ft = int.from_bytes(data[12:16], "little") if len(data) >= 16 else 0
            # FILETIME (UTC) of last execution
            if ft > 0:
                import datetime as _dt
                epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
                dt = epoch + _dt.timedelta(microseconds=ft // 10)
                if dt.year >= 1970:
                    last_run = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                session_id = int.from_bytes(data[16:20], "little")
            except Exception:
                pass
        return {
            "location": f"{location}\\{program}",
            "value": program,
            "data": program,
            "type": "UserAssist",
            "program": program,
            "run_count": run_count,
            "focus_count": focus_count,
            "last_run": last_run,
            "session_id": session_id,
        }
