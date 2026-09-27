"""JOCKY - Just One Comprehensive Key-forensics Yield.

A domain-specific forensic scripting language for authorized digital
forensics and incident response, per the "JOCKY Forensic Language -
Complete Manual".

Windows-only prototype (SIH 2026).
"""

__version__ = "1.0.0"
APP_NAME = "JOCKY Forensic Workbench"
APP_TAGLINE = "Just One Comprehensive Key-forensics Yield"
VARIANT = "windows/amd64"
JIR_VERSION = "1.0"
JRF_VERSION = "1.0"
JAL_VERSION = "1.0"


def version_string() -> str:
    return f"JOCKY {__version__} ({VARIANT})"
