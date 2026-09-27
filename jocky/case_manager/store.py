"""JOCKY case management: local SQLite storage (no external server).

A case holds: case id, investigator, authorization record, execution
history, evidence paths, alerts, reports and integrity information.
Database path: <evidence_dir>/cases.db (portable with the evidence).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional


class CaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id      TEXT PRIMARY KEY,
                investigator TEXT NOT NULL,
                organization TEXT DEFAULT '',
                authorized_by TEXT DEFAULT '',
                scope        TEXT DEFAULT '',
                valid_until  TEXT DEFAULT '',
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS executions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id      TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                script       TEXT DEFAULT '',
                ir_path      TEXT DEFAULT '',
                status       TEXT DEFAULT 'RUNNING',
                ok           INTEGER DEFAULT 0,
                statements   INTEGER DEFAULT 0,
                duration_ms  INTEGER DEFAULT 0,
                detail       TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id      TEXT NOT NULL,
                execution_id INTEGER,
                artifact     TEXT NOT NULL,
                operation    TEXT DEFAULT '',
                collected_at TEXT NOT NULL,
                sha256       TEXT DEFAULT '',
                integrity    TEXT DEFAULT 'VERIFIED'
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id      TEXT NOT NULL,
                execution_id INTEGER,
                severity     TEXT NOT NULL,
                message      TEXT NOT NULL,
                raised_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id      TEXT NOT NULL,
                path         TEXT NOT NULL,
                format       TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                sha256       TEXT DEFAULT ''
            );
            """)

    # ------------------------------------------------------------------

    def upsert_case(self, case_id: str, investigator: str, organization: str = "",
                    authorized_by: str = "", scope: str = "",
                    valid_until: str = "") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cases (case_id, investigator, organization, authorized_by,"
                " scope, valid_until, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(case_id) DO UPDATE SET investigator=excluded.investigator,"
                " organization=excluded.organization, authorized_by=excluded.authorized_by,"
                " scope=excluded.scope, valid_until=excluded.valid_until,"
                " updated_at=excluded.updated_at",
                (case_id, investigator, organization, authorized_by, scope,
                 valid_until, now, now))

    def start_execution(self, case_id: str, script: str, ir_path: str) -> int:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO executions (case_id, started_at, script, ir_path, status)"
                " VALUES (?,?,?,?, 'RUNNING')", (case_id, now, script, ir_path))
            return int(cur.lastrowid)

    def finish_execution(self, execution_id: int, ok: bool, statements: int,
                         duration_ms: int, status: str, detail: str = "") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "UPDATE executions SET finished_at=?, ok=?, statements=?,"
                " duration_ms=?, status=?, detail=? WHERE id=?",
                (now, 1 if ok else 0, statements, duration_ms, status, detail,
                 execution_id))

    def add_evidence(self, case_id: str, execution_id: int, artifact: str,
                     operation: str, sha256: str, integrity: str = "VERIFIED") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO evidence (case_id, execution_id, artifact, operation,"
                " collected_at, sha256, integrity) VALUES (?,?,?,?,?,?,?)",
                (case_id, execution_id, artifact, operation, now, sha256, integrity))

    def add_alert(self, case_id: str, execution_id: int, severity: str,
                  message: str) -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO alerts (case_id, execution_id, severity, message,"
                " raised_at) VALUES (?,?,?,?,?)",
                (case_id, execution_id, severity, message, now))

    def add_report(self, case_id: str, path: str, fmt: str, sha256: str) -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO reports (case_id, path, format, generated_at, sha256)"
                " VALUES (?,?,?,?,?)", (case_id, path, fmt, now, sha256))

    # ------------------------------------------------------------------

    def case_summary(self, case_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE case_id=?",
                                (case_id,)).fetchone()
            executions = conn.execute(
                "SELECT * FROM executions WHERE case_id=? ORDER BY id DESC LIMIT 50",
                (case_id,)).fetchall()
            evidence = conn.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC LIMIT 200",
                (case_id,)).fetchall()
            alerts = conn.execute(
                "SELECT * FROM alerts WHERE case_id=? ORDER BY id DESC LIMIT 200",
                (case_id,)).fetchall()
            reports = conn.execute(
                "SELECT * FROM reports WHERE case_id=? ORDER BY id DESC LIMIT 50",
                (case_id,)).fetchall()
            by_sev: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for a in alerts:
                by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
            integrity = {"artifacts": len(evidence), "verified": 0, "modified": 0}
            for e in evidence:
                if e["integrity"] == "VERIFIED":
                    integrity["verified"] += 1
                else:
                    integrity["modified"] += 1
            return {
                "case": dict(case) if case else None,
                "executions": [dict(r) for r in executions],
                "evidence": [dict(r) for r in evidence],
                "alerts": [dict(r) for r in alerts],
                "reports": [dict(r) for r in reports],
                "alert_counts": by_sev,
                "integrity": integrity,
            }

    def list_cases(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]
