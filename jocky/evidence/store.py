"""JOCKY evidence system: .jrf evidence files, .jal action log, integrity.

Every collection writes one .jrf evidence record (manual §16.1-16.2, §3.4):
SHA-256 data hash, host fingerprint, collector metadata and a Merkle chain
(parent_hash) linking sequential evidence records. Every runtime action is
appended to the .jal action log (manual §3.4, glossary "Action Log").
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import socket
import platform
import uuid
from typing import Any, Dict, List, Optional

from jocky import JAL_VERSION, JRF_VERSION
from jocky.runtime import errors


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False,
                   default=str).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_fingerprint() -> str:
    """SHA-256 of hostname+OS+MAC (manual §16.1 host_id)."""
    mac = ""
    try:
        mac = uuid.getnode().to_bytes(6, "big").hex()
    except Exception:
        pass
    return "sha256:" + sha256_text(f"{socket.gethostname()}|{platform.platform()}|{mac}")


def safe_filename(name: str) -> str:
    keep = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return keep[-120:] if len(keep) > 120 else keep


class ActionLog:
    """The .jal action log: one JSON line per runtime action."""

    def __init__(self, path: str, case_id: str, investigator: str):
        self.path = path
        self.case_id = case_id
        self.investigator = investigator
        self.entries: List[Dict[str, Any]] = []
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8"):
                pass
        except OSError:
            pass

    def add(self, command: str, capability: str, result: str,
            success: bool, duration_ms: int = 0, artifact: str = "",
            artifact_sha256: str = "", detail: str = "") -> Dict[str, Any]:
        entry = {
            "timestamp": now_iso(),
            "case_id": self.case_id,
            "investigator": self.investigator,
            "command": command,
            "capability": capability,
            "result": result,
            "success": bool(success),
            "duration_ms": duration_ms,
            "artifact": artifact,
            "sha256": artifact_sha256,
            "detail": detail,
        }
        self.entries.append(entry)
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass
        return entry


class EvidenceStore:
    """Writes .jrf evidence records with chain of custody metadata."""

    def __init__(self, evidence_dir: str, case_id: str, investigator: str,
                 action_log: ActionLog):
        self.dir = evidence_dir
        self.case_id = case_id
        self.investigator = investigator
        self.action_log = action_log
        self.parent_hash = ""          # Merkle chain: hash of previous record
        self.records: List[Dict[str, Any]] = []
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:
            raise errors.evidence_write_failed(
                f"cannot create evidence directory '{self.dir}': {exc}") from None

    # ------------------------------------------------------------------

    def write_artifact(self, name: str, payload: Any, operation: str,
                       collected_artifact: str,
                       source_metadata: Optional[dict] = None) -> Dict[str, Any]:
        """Persist collected data as <name>.jrf and return the record."""
        record_body = {
            "jrf_version": JRF_VERSION,
            "record_id": str(uuid.uuid4()),
            "case_id": self.case_id,
            "investigator": self.investigator,
            "collected_at": now_iso(),
            "host": {
                "hostname": socket.gethostname(),
                "os": f"{platform.system()} {platform.release()}",
                "version": platform.version(),
                "arch": platform.machine(),
                "host_id": host_fingerprint(),
            },
            "operation": operation,
            "collected_artifact": collected_artifact,
            "source_metadata": source_metadata or {},
            "evidence": payload,
        }
        body_json = json.dumps(record_body, indent=2, ensure_ascii=False, default=str)
        data_hash = "sha256:" + sha256_text(body_json)

        record = {
            "jrf_version": JRF_VERSION,
            "record_id": record_body["record_id"],
            "case_id": self.case_id,
            "investigator": self.investigator,
            "hostname": record_body["host"]["hostname"],
            "windows_version": record_body["host"]["os"] + " " + record_body["host"]["version"],
            "timestamp": record_body["collected_at"],
            "operation": operation,
            "collected_artifact": collected_artifact,
            "data_hash": data_hash,
            "parent_hash": self.parent_hash,
            "source_metadata": source_metadata or {},
            "result_file": "",
            "integrity_status": "VERIFIED",
        }
        record_json = json.dumps(record, indent=2, ensure_ascii=False, default=str)
        record["record_hash"] = "sha256:" + sha256_text(record_json)

        fname = safe_filename(name) + ".jrf"
        path = os.path.join(self.dir, fname)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"record": record, "evidence": payload},
                                    indent=2, ensure_ascii=False, default=str))
        except OSError as exc:
            raise errors.evidence_write_failed(
                f"cannot write evidence file '{path}': {exc}") from None
        record["result_file"] = path
        record["file_sha256"] = "sha256:" + sha256_file(path)
        self.parent_hash = record["record_hash"]
        self.records.append(record)
        self.action_log.add(command=operation, capability="EVIDENCE_EXPORT",
                            result="evidence written", success=True, artifact=path,
                            artifact_sha256=record["file_sha256"],
                            detail=f"{collected_artifact}: {len(payload) if isinstance(payload, list) else 1} records")
        return record

    # ------------------------------------------------------------------

    def verify_all(self) -> Dict[str, Any]:
        """Re-hash every artifact and compare against the recorded hash."""
        artifacts = len(self.records)
        verified = 0
        modified = 0
        for rec in self.records:
            path = rec.get("result_file") or ""
            if path and os.path.exists(path):
                if "sha256:" + sha256_file(path) == rec.get("file_sha256"):
                    verified += 1
                    rec["integrity_status"] = "VERIFIED"
                else:
                    modified += 1
                    rec["integrity_status"] = "MODIFIED"
            else:
                modified += 1
                rec["integrity_status"] = "MISSING"
        status = "VERIFIED" if modified == 0 and artifacts > 0 else \
            ("NO ARTIFACTS" if artifacts == 0 else "FAILED")
        return {"artifacts": artifacts, "verified": verified,
                "modified": modified, "missing": artifacts - verified - modified,
                "status": status}

    def integrity_summary(self) -> str:
        v = self.verify_all()
        lines = ["Evidence Integrity", "-" * 40,
                 f"Artifacts: {v['artifacts']}",
                 f"Verified:  {v['verified']}",
                 f"Modified:  {v['modified']}",
                 f"Status:    {v['status']}"]
        return "\n".join(lines)


def write_case_journal(evidence_dir: str, case_id: str, investigator: str,
                       evidence: List[Dict[str, Any]], alerts: List[Dict[str, Any]],
                       ir: Optional[dict] = None, ir_path: str = "",
                       script_path: str = "") -> Dict[str, Any]:
    """Write <case_id>_session.jrf — the run-level chain-of-custody record."""
    log = ActionLog(os.path.join(evidence_dir, "action.log"), case_id, investigator)
    store = EvidenceStore(evidence_dir, case_id, investigator, log)
    record = store.write_artifact(
        name=f"{safe_filename(case_id)}_session",
        payload={"alerts": alerts,
                 "evidence_records": [
                     {k: v for k, v in r.items() if k != "source_metadata"}
                     for r in evidence]},
        operation="SESSION_JOURNAL",
        collected_artifact="run-level evidence index",
        source_metadata={"script": script_path, "ir": ir_path,
                         "merkle_root": store.parent_hash},
    )
    return {"store": store, "record": record}
