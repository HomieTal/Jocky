"""JOCKY capability policy (least privilege, manual §1.3 Principle 3).

Capability flow before any operation executes:

    Requested Operation -> Declared Scope -> Authorization
        -> Capability Policy -> Execution

The prototype grants only read-only capabilities; anything else is
structurally impossible. Privilege directives (@requires privilege.admin)
are checked against the actual process token elevation.
"""

from __future__ import annotations

import ctypes
from typing import Optional, Set

from jocky.runtime import errors

PROCESS_READ = "PROCESS_READ"
NETWORK_READ = "NETWORK_READ"
REGISTRY_READ = "REGISTRY_READ"
EVENTLOG_READ = "EVENTLOG_READ"
FILE_READ = "FILE_READ"
HASH_FILE = "HASH_FILE"
EVIDENCE_EXPORT = "EVIDENCE_EXPORT"
SYSTEM_READ = "SYSTEM_READ"

ALL_CAPABILITIES = (
    PROCESS_READ, NETWORK_READ, REGISTRY_READ, EVENTLOG_READ,
    FILE_READ, HASH_FILE, EVIDENCE_EXPORT, SYSTEM_READ,
)

# The prototype is a read-only forensic runtime: these capabilities are
# always granted by the capability policy (they cannot escalate anything).
POLICY_GRANT: Set[str] = set(ALL_CAPABILITIES)

# module -> capability required to collect from it
MODULE_CAPABILITY = {
    "mem": PROCESS_READ,
    "net": NETWORK_READ,
    "reg": REGISTRY_READ,
    "log": EVENTLOG_READ,
    "disk": FILE_READ,
    "sys": SYSTEM_READ,
}

_CAP_DESC = {
    PROCESS_READ: "enumerate processes and module metadata",
    NETWORK_READ: "read connection, DNS, ARP and routing tables",
    REGISTRY_READ: "read registry autoruns, services, MRU and UserAssist",
    EVENTLOG_READ: "query the Windows event log",
    FILE_READ: "enumerate file metadata",
    HASH_FILE: "compute SHA-256/MD5 hashes of files",
    EVIDENCE_EXPORT: "write evidence artifacts to the evidence directory",
    SYSTEM_READ: "read host system information",
}


def capability_for_module(module: str) -> str:
    return MODULE_CAPABILITY.get(module, PROCESS_READ)


def is_valid_capability(name: str) -> bool:
    return name in ALL_CAPABILITIES or name.startswith("privilege.")


def is_elevated() -> bool:
    """True when the current process token is elevated (Administrator)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class CapabilityEnforcer:
    """Checks each runtime operation against declared requirements + policy."""

    def __init__(self, requires: Optional[list] = None):
        self.requires: list = list(requires or [])
        self.required_privilege = "privilege.user"
        for item in self.requires:
            if isinstance(item, str) and item.startswith("privilege."):
                self.required_privilege = item

    # ------------------------------------------------------------------

    def check_privilege(self, line: int = 0) -> None:
        """E010 PRIV_DENIED when @requires privilege.admin is declared but
        the process is not elevated. No silent escalation, ever."""
        if self.required_privilege == "privilege.admin" and not is_elevated():
            raise errors.priv_denied(
                "script declares @requires privilege.admin but JOCKY is "
                "running as a standard user — re-launch JOCKY as "
                "Administrator or change the directive to privilege.user",
                line=line)

    def check_capability(self, capability: str, line: int = 0) -> None:
        """Verify a capability is granted by the capability policy."""
        if capability not in POLICY_GRANT:
            raise errors.capability_denied(
                f'capability "{capability}" is not granted by the JOCKY '
                "capability policy (read-only runtime)", line=line)

    def check_module(self, module: str, line: int = 0) -> str:
        """Scope + capability check for a collect. Returns the capability."""
        capability = capability_for_module(module)
        self.check_capability(capability, line)
        return capability
