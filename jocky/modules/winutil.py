"""Windows user-space helpers for JOCKY collectors (all read-only).

- Authenticode verification via WinVerifyTrust (embedded signatures)
- Batched Get-AuthenticodeSignature fallback for catalog-signed OS files
- OEM-safe capture of Windows console tools (arp / route / ipconfig / wevtutil)
- FILETIME decoding for registry forensic artifacts
"""

from __future__ import annotations

import datetime as _dt
import subprocess
from ctypes import (POINTER, Structure, Union, byref, c_ubyte, c_void_p,
                    c_wchar_p, windll, wintypes)
from typing import Dict, List, Optional, Tuple

_LPCWSTR = c_wchar_p
_DWORD = wintypes.DWORD
_HANDLE = wintypes.HANDLE


def decode_console_bytes(data: bytes) -> str:
    """Decode Windows console-tool output (OEM codepage)."""
    for enc in ("oem", "mbcs", "utf-8", "cp437"):
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def run_capture(cmd: List[str], timeout: float = 30.0) -> Tuple[int, str]:
    """Run a read-only Windows console command and capture its text output."""
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    out = decode_console_bytes(proc.stdout)
    err = decode_console_bytes(proc.stderr)
    return proc.returncode, (out + ("\n" + err if err.strip() else "")).strip()


# --------------------------------------------------------------------------
# Authenticode: embedded signature check (WinVerifyTrust)
# --------------------------------------------------------------------------

class _GUID(Structure):
    _fields_ = [("Data1", _DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", c_ubyte * 8)]


def _guid(d1: int, d2: int, d3: int, d4: List[int]) -> _GUID:
    g = _GUID()
    g.Data1, g.Data2, g.Data3 = d1, d2, d3
    for i, b in enumerate(d4):
        g.Data4[i] = b
    return g


WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
ERROR_SUCCESS = 0

_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _guid(
    0xAAC9, 0xCD44, 0x11D0, [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE])


class _WINTRUST_FILE_INFO(Structure):
    _fields_ = [("cbStruct", _DWORD), ("pcwszFilePath", _LPCWSTR),
                ("hFile", _HANDLE), ("pgKnownSubject", c_void_p)]


class _WINTRUST_UNION(Union):
    _fields_ = [("pFile", POINTER(_WINTRUST_FILE_INFO)), ("pCatalog", c_void_p),
                ("pBlob", c_void_p), ("pSgnr", c_void_p), ("pCert", c_void_p)]


class _WINTRUST_DATA(Structure):
    _anonymous_ = ("Union",)
    _fields_ = [
        ("cbStruct", _DWORD),
        ("pPolicyCallbackData", c_void_p),
        ("pSIPStateData", c_void_p),
        ("dwUIChoice", _DWORD),
        ("fdwRevocationChecks", _DWORD),
        ("dwUnionChoice", _DWORD),
        ("Union", _WINTRUST_UNION),
        ("dwStateAction", _DWORD),
        ("hWVTStateData", _HANDLE),
        ("pwszURLReference", _LPCWSTR),
        ("dwProvFlags", _DWORD),
        ("dwUIContext", _DWORD),
        ("pSignatureSettings", c_void_p),
    ]


_wintrust = None
try:
    _wintrust = windll.wintrust
except OSError:  # non-Windows (tests on other platforms)
    _wintrust = None


def has_embedded_signature(path: str) -> bool:
    """True when the file carries a valid embedded Authenticode signature.

    Catalog-signed OS files (svchost.exe etc.) return False here; use
    SignatureCache for the full picture.
    """
    if _wintrust is None:
        return False
    try:
        info = _WINTRUST_FILE_INFO()
        info.cbStruct = _DWORD.__size__()
        info.pcwszFilePath = path
        data = _WINTRUST_DATA()
        data.cbStruct = _DWORD.__size__()
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.pFile = byref(info)
        rc = _wintrust.WinVerifyTrust(0, byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                      byref(data))
        data.dwStateAction = WTD_STATEACTION_CLOSE
        _wintrust.WinVerifyTrust(0, byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                 byref(data))
        return rc == ERROR_SUCCESS
    except Exception:
        return False


# --------------------------------------------------------------------------
# Catalog-signed OS files: one-shot batched PowerShell fallback
# --------------------------------------------------------------------------

def batch_signature_status(paths: List[str]) -> Dict[str, str]:
    """Ask PowerShell (one process) about many files at once.

    Returns {path: "signed"|"catalog"|"unsigned"|"unknown"}. PowerShell's
    Get-AuthenticodeSignature consults security catalogs, so Windows OS
    binaries without embedded signatures verify as Valid here.
    """
    if not paths:
        return {}
    unique = sorted(set(p for p in paths if p))
    status: Dict[str, str] = {}
    chunk_size = 120
    for i in range(0, len(unique), chunk_size):
        chunk = unique[i:i + chunk_size]
        ps_lines = ["$ErrorActionPreference='SilentlyContinue'",
                    "$paths = @(" + ",".join("'" + p.replace("'", "''") + "'"
                                             for p in chunk) + ")",
                    "Get-AuthenticodeSignature -FilePath $paths -ErrorAction SilentlyContinue |"
                    " ForEach-Object { \"$($_.Path)`t$($_.Status)\" }"]
        try:
            rc, out = run_capture(["powershell", "-NoProfile", "-NonInteractive",
                                   "-Command", "\n".join(ps_lines)], timeout=60)
        except Exception:
            rc, out = 1, ""
        if rc == 0 or out.strip():
            for line in out.splitlines():
                line = line.strip()
                if "\t" not in line:
                    continue
                p, st = line.split("\t", 1)
                p = p.strip()
                st = st.strip()
                if st == "Valid":
                    status[p] = "catalog"  # embedded check already failed
                elif st in ("NotSigned", "UnknownError", "HashMismatch", "NotTrusted"):
                    status[p] = "unsigned" if st == "NotSigned" else "unknown"
                else:
                    status[p] = "unknown"
    return status


class SignatureCache:
    """Per-run cache resolving a file path -> signature status.

    Statuses: "signed" (embedded), "catalog" (OS catalog), "unsigned",
    "unknown". is_signed is True for signed/catalog.
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._pending: List[str] = []
        self._powershell_done = False

    def verify(self, path: Optional[str]) -> str:
        if not path:
            return "unknown"
        path_l = path.lower()
        if path_l in self._cache:
            return self._cache[path_l]
        if has_embedded_signature(path):
            self._cache[path_l] = "signed"
            return "signed"
        # no embedded signature: might be catalog-signed; resolved in bulk
        if path_l not in self._pending:
            self._pending.append(path_l)
        self._cache[path_l] = "unknown"
        return "unknown"

    def flush(self) -> None:
        """Resolve all pending (embedded-unsigned) paths via one batch check."""
        if not self._pending or self._powershell_done:
            self._powershell_done = True
            return
        self._powershell_done = True
        pending = list(self._pending)
        self._pending.clear()
        results = batch_signature_status(pending)
        for path_l in pending:
            got = results.get(path_l) or results.get(path_l.replace("/", "\\"))
            if got is None:
                norm = {k.lower(): v for k, v in results.items()}
                got = norm.get(path_l)
            self._cache[path_l] = got or "unknown"

    def final_status(self, path: Optional[str]) -> str:
        if not path:
            return "unknown"
        return self._cache.get(path.lower(), "unknown")


def signature_label(status: str) -> str:
    return {"signed": "Signed", "catalog": "Catalog-signed",
            "unsigned": "Unsigned", "unknown": "Unknown"}.get(status, "Unknown")


# --------------------------------------------------------------------------
# FILETIME / registry decoding helpers
# --------------------------------------------------------------------------

_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def filetime_to_iso(ft_bytes: bytes) -> Optional[str]:
    """Windows FILETIME (8 little-endian bytes) -> ISO-8601 UTC, or None."""
    try:
        value = int.from_bytes(ft_bytes[:8], "little")
        if value <= 0:
            return None
        dt = _EPOCH + _dt.timedelta(microseconds=value // 10)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def ts_to_iso(timestamp: float) -> str:
    return _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)
