"""disk module: file-system forensics (read-only, manual §9.1, §9.5).

collect disk.files(path: "C:\\\\Users", depth: 3, extension: ".exe",
                   hash: true, hidden: false, modified_within_hours: 24)

Enumerates metadata only; hashing is opt-in per file and never modifies
the file. The manual's `file` forensic type (§5.3): path, name, size_bytes,
md5, sha256, created, modified, accessed, is_hidden, is_deleted, owner.
"""

from __future__ import annotations

import hashlib
import os
import stat as _stat
from typing import Any, Dict, List, Optional

from jocky.modules.base import CollectContext, Collector
from jocky.modules import winutil

_HASH_CAP_BYTES = 256 * 1048576     # refuse to hash files > 256 MB
_OWNER_LOOKUPS_MAX = 2000


def _hash_file(path: str, algos: List[str]) -> Dict[str, str]:
    out = {a: "" for a in algos}
    try:
        size = os.path.getsize(path)
        if size > _HASH_CAP_BYTES:
            return {a: f"<skipped: {size} bytes>" for a in algos}
        md5 = hashlib.md5() if "md5" in algos else None
        sha = hashlib.sha256() if "sha256" in algos else None
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                if sha:
                    sha.update(chunk)
                if md5:
                    md5.update(chunk)
        if sha:
            out["sha256"] = sha.hexdigest()
        if md5:
            out["md5"] = md5.hexdigest()
    except OSError:
        pass
    return out


class FilesCollector(Collector):
    module = "disk"
    entity = "files"
    title = "File System Artifacts"
    record_type = "file"
    fields = ["path", "name", "size_bytes", "md5", "sha256", "created",
              "modified", "accessed", "is_hidden", "is_deleted", "owner",
              "extension", "is_signed", "signature_status"]
    columns = ["name", "size_bytes", "modified", "is_hidden", "extension", "path"]
    arg_spec = {
        "path": {"type": "str", "default": None, "required": True},
        "depth": {"type": "int", "default": 3},
        "extension": {"type": "str", "default": ""},
        "hash": {"type": "bool", "default": False},
        "md5": {"type": "bool", "default": False},
        "hidden": {"type": "bool", "default": True},
        "modified_within_hours": {"type": "float", "default": 0.0},
        "max_files": {"type": "int", "default": 5000},
    }

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        opts = self.resolve_args(args, kwargs)
        root = str(opts["path"])
        if not os.path.exists(root):
            from jocky.runtime import errors
            raise errors.collect_failed(
                f'path "{root}" does not exist (collect disk.files)')
        if os.path.isfile(root):
            roots = [root]
        else:
            roots = [root]
        ext_filter = str(opts["extension"] or "").lower()
        if ext_filter and not ext_filter.startswith("."):
            ext_filter = "." + ext_filter
        depth = int(opts["depth"])
        want_hidden = bool(opts["hidden"])
        want_hash = bool(opts["hash"])
        want_md5 = bool(opts["md5"])
        within_hours = float(opts["modified_within_hours"] or 0)
        max_files = int(opts["max_files"])

        algos = ["sha256"] if want_hash else []
        if want_md5:
            algos.append("md5")

        ctx.progress(f"walking {root} (depth {depth})...")
        records: List[Dict[str, Any]] = []
        owner_cache: Dict[str, str] = {}
        owner_lookups = 0
        now = winutil.now_iso()

        def walk(directory: str, level: int):
            nonlocal owner_lookups
            if len(records) >= max_files or (depth and level > depth):
                return
            try:
                with os.scandir(directory) as it:
                    entries = list(it)
            except (PermissionError, OSError):
                return
            for entry in entries:
                if len(records) >= max_files:
                    return
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                is_hidden = bool(_stat.FILE_ATTRIBUTE_HIDDEN & getattr(
                    st, "st_file_attributes", 0)) if hasattr(st, "st_file_attributes") \
                    else entry.name.startswith(".")
                if is_dir:
                    walk(entry.path, level + 1)
                    continue
                if not want_hidden and is_hidden:
                    continue
                extension = os.path.splitext(entry.name)[1].lower()
                if ext_filter and extension != ext_filter:
                    continue
                modified_iso = winutil.ts_to_iso(st.st_mtime)
                if within_hours > 0:
                    try:
                        mtime = st.st_mtime
                        import datetime as _dt
                        age_h = (_dt.datetime.now(_dt.timezone.utc).timestamp() - mtime) / 3600
                        if age_h > within_hours:
                            continue
                    except Exception:
                        pass
                record = {
                    "path": entry.path,
                    "name": entry.name,
                    "size_bytes": st.st_size,
                    "md5": "",
                    "sha256": "",
                    "created": winutil.ts_to_iso(st.st_ctime),
                    "modified": modified_iso,
                    "accessed": winutil.ts_to_iso(st.st_atime),
                    "is_hidden": is_hidden,
                    "is_deleted": False,   # only true for MFT-recovered entries
                    "owner": "",
                    "extension": extension,
                    "is_signed": None,
                    "signature_status": "Unknown",
                }
                records.append(record)
                if algos:
                    digests = _hash_file(entry.path, algos)
                    record.update(digests)
                # owner: best effort, capped
                if owner_lookups < _OWNER_LOOKUPS_MAX:
                    owner_lookups += 1
                    owner = _file_owner(entry.path, owner_cache)
                    record["owner"] = owner

        for r in roots:
            walk(r, 1)
        ctx.progress(f"{len(records)} files enumerated")
        return records


def _file_owner(path: str, cache: Dict[str, str]) -> str:
    """Read-only owner lookup via GetNamedSecurityInfoW (ctypes)."""
    if path in cache:
        return cache[path]
    try:
        import ctypes
        from ctypes.wintypes import DWORD, HANDLE, LPVOID  # noqa: F401
        SE_FILE_OBJECT = 1
        OWNER_SECURITY_INFORMATION = 0x00000001
        sid = ctypes.c_void_p()
        rc = ctypes.windll.advapi32.GetNamedSecurityInfoW(
            path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            ctypes.byref(sid), None, None, None, None)
        if rc != 0 or not sid:
            cache[path] = ""
            return ""
        name = ctypes.c_wchar_p()
        domain = ctypes.c_wchar_p()
        name_len = ctypes.c_ulong()
        domain_len = ctypes.c_ulong()
        use = ctypes.c_ulong()
        ok = ctypes.windll.advapi32.LookupAccountSidW(
            None, sid, None, ctypes.byref(name_len), None, ctypes.byref(domain_len),
            ctypes.byref(use))
        name_buf = ctypes.create_unicode_buffer(name_len.value or 1)
        domain_buf = ctypes.create_unicode_buffer(domain_len.value or 1)
        ok = ctypes.windll.advapi32.LookupAccountSidW(
            None, sid, name_buf, ctypes.byref(name_len), domain_buf,
            ctypes.byref(domain_len), ctypes.byref(use))
        ctypes.windll.advapi32.LocalFree(sid)
        if ok:
            owner = f"{domain_buf.value}\\{name_buf.value}" if domain_buf.value \
                else name_buf.value
            cache[path] = owner
            return owner
    except Exception:
        pass
    cache[path] = ""
    return ""
