"""JOCKY investigation report generation (manual §16.4).

Export -> JSON (machine-readable, full detail) and
Export -> HTML (human-readable, self-contained, no external assets).
"""

from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, List, Optional

from jocky.runtime import errors


def make_session(result, vm, script_path: str, ir_path: str) -> Dict[str, Any]:
    """Assemble a report-ready session dict from a finished interpreter run."""
    auth = vm.auth
    host = {}
    for coll in result.collections:
        if coll["key"] == "sys.info" and coll["rows"]:
            host = coll["rows"][0]
            break
    if not host:
        import platform as _p
        import socket as _s
        host = {"hostname": _s.gethostname(), "os": f"{_p.system()} {_p.release()}",
                "version": _p.version(), "arch": _p.machine(), "host_id": ""}
    return {
        "title": f"Investigation Report — {auth.case_id}",
        "case_id": auth.case_id,
        "investigator": auth.investigator,
        "organization": auth.organization,
        "authorized_by": auth.authorized_by,
        "scope": auth.scope,
        "valid_until": auth.valid_until,
        "script_path": script_path,
        "ir_path": ir_path,
        "evidence_dir": vm.evidence_dir,
        "host": host,
        "timeline": [
            {"time": rec.get("timestamp", ""),
             "operation": rec.get("operation", ""),
             "artifact": (rec.get("result_file") or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
             "records": (rec.get("source_metadata") or {}).get("rows", ""),
             "status": rec.get("integrity_status", "")}
            for rec in result.evidence_records
        ],
        "findings": [{"severity": a["severity"], "kind": "alert",
                      "summary": a["message"]} for a in result.alerts],
        "alerts": result.alerts,
        "evidence_records": result.evidence_records,
        "merkle_root": result.merkle_root,
        "action_log_summary": {
            "entries": (vm.action_log.entries if vm.action_log else []),
            "alert_counts": result.alert_counts,
        },
        "integrity": vm.evidence.verify_all() if vm.evidence else {},
        "generated_at": result.generated_at,
    }


def build_report_document(session: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "report_version": "1.0",
        "title": session.get("title") or f"JOCKY Investigation Report — {session.get('case_id', '')}",
        "case_information": {
            "case_id": session.get("case_id", ""),
            "investigator": session.get("investigator", ""),
            "organization": session.get("organization", ""),
            "authorized_by": session.get("authorized_by", ""),
            "scope": session.get("scope", ""),
            "valid_until": session.get("valid_until", ""),
            "script": session.get("script_path", ""),
            "evidence_directory": session.get("evidence_dir", ""),
        },
        "host_information": session.get("host", {}),
        "collection_timeline": session.get("timeline", []),
        "findings": session.get("findings", []),
        "alerts": session.get("alerts", []),
        "evidence": [
            {k: v for k, v in rec.items() if k != "source_metadata"}
            for rec in session.get("evidence_records", [])
        ],
        "evidence_hashes": [
            {"artifact": rec.get("result_file", ""),
             "sha256": rec.get("file_sha256", ""),
             "data_hash": rec.get("data_hash", ""),
             "integrity": rec.get("integrity_status", "")}
            for rec in session.get("evidence_records", [])
        ],
        "merkle_root": session.get("merkle_root", ""),
        "action_log_summary": session.get("action_log_summary", {}),
        "integrity_verification": session.get("integrity", {}),
        "generated_at": session.get("generated_at", ""),
    }


def export_json(session: Dict[str, Any], path: str) -> str:
    doc = build_report_document(session)
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False, default=str)
    except OSError as exc:
        raise errors.export_failed(f"cannot write JSON report '{path}': {exc}") from None
    return path


_ESC = html.escape


def _tbl(headers: List[str], rows: List[List[Any]], max_rows: int = 300) -> str:
    head = "".join(f"<th>{_ESC(str(h))}</th>" for h in headers)
    body_rows = []
    for row in rows[:max_rows]:
        cells = "".join(f"<td>{_ESC('' if v is None else str(v))}</td>" for v in row)
        body_rows.append(f"<tr>{cells}</tr>")
    more = ""
    if len(rows) > max_rows:
        more = f"<p class='muted'>… {len(rows) - max_rows} more rows not shown</p>"
    return (f"<table><thead><tr>{head}</tr></thead><tbody>"
            + ("".join(body_rows) or "<tr><td colspan='%d' class='muted'>no rows</td></tr>" % max(1, len(headers)))
            + f"</tbody></table>{more}")


def export_html(session: Dict[str, Any], path: str) -> str:
    doc = build_report_document(session)
    ci = doc["case_information"]
    hi = doc["host_information"]
    integ = doc["integrity_verification"]

    timeline_rows = [[t.get("time", ""), t.get("operation", ""),
                      t.get("artifact", ""), t.get("records", ""),
                      t.get("status", "")] for t in doc["collection_timeline"]]
    alert_rows = [[a.get("raised_at", ""), a.get("severity", ""),
                   a.get("message", "")] for a in doc["alerts"]]
    evidence_rows = [[e.get("timestamp", ""), e.get("operation", ""),
                      e.get("collected_artifact", ""), e.get("result_file", ""),
                      e.get("data_hash", ""), e.get("integrity_status", "")]
                     for e in doc["evidence"]]
    hash_rows = [[h.get("artifact", ""), h.get("sha256", ""),
                  h.get("integrity", "")] for h in doc["evidence_hashes"]]
    log_rows = [[l.get("timestamp", ""), l.get("command", ""),
                 l.get("capability", ""), l.get("result", ""),
                 "OK" if l.get("success") else "FAIL",
                 f"{l.get('duration_ms', 0)} ms"] for l in
                doc["action_log_summary"].get("entries", [])]
    findings_rows = [[f.get("severity", ""), f.get("kind", ""),
                      f.get("summary", "")] for f in doc["findings"]]

    integ = doc["integrity_verification"]
    status = integ.get("status", "UNKNOWN")
    status_cls = "ok" if status == "VERIFIED" else "bad"

    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{_ESC(doc['title'])}</title>
<style>
 body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f4f6f8; color: #1d2733; }}
 .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
 header {{ background: linear-gradient(120deg, #0b2545, #13315c 60%, #1d4e89); color: #fff;
          padding: 28px 24px; border-radius: 0 0 10px 10px; }}
 header h1 {{ margin: 0 0 4px; font-size: 22px; letter-spacing: .5px; }}
 header .sub {{ color: #bcd0ea; font-size: 13px; }}
 h2 {{ font-size: 16px; color: #0b2545; border-bottom: 2px solid #d7e3f4; padding-bottom: 6px;
      margin-top: 34px; }}
 table {{ border-collapse: collapse; width: 100%; background: #fff; font-size: 12.5px;
         box-shadow: 0 1px 2px rgba(0,0,0,.06); }}
 th {{ background: #13315c; color: #fff; text-align: left; padding: 7px 9px; }}
 td {{ border-bottom: 1px solid #e4eaf1; padding: 6px 9px; vertical-align: top;
      word-break: break-word; }}
 tr:hover td {{ background: #f2f7fd; }}
 .cards {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0; }}
 .card {{ background: #fff; border-radius: 8px; padding: 14px 18px; min-width: 150px;
         box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
 .card .n {{ font-size: 24px; font-weight: 700; color: #0b2545; }}
 .card .l {{ font-size: 11px; color: #5c6f85; text-transform: uppercase; letter-spacing: .8px; }}
 .ok {{ color: #177245; font-weight: 700; }} .bad {{ color: #b3261e; font-weight: 700; }}
 .sev-low {{ color: #5c6f85; font-weight: 600; }} .sev-med {{ color: #b07d0a; font-weight: 600; }}
 .sev-high {{ color: #c2410c; font-weight: 700; }} .sev-crit {{ color: #b3261e; font-weight: 700; }}
 .muted {{ color: #7a8aa0; font-style: italic; }}
 footer {{ margin: 40px 0 12px; color: #7a8aa0; font-size: 11px; }}
 code, .hash {{ font-family: Consolas, monospace; font-size: 11px; }}
</style></head><body>
<header><div class="wrap" style="padding:0">
 <h1>JOCKY — {_ESC(doc['title'])}</h1>
 <div class="sub">Just One Comprehensive Key-forensics Yield · Forensic Investigation Report ·
 {_ESC(doc['generated_at'])}</div>
</div></header>
<div class="wrap">

<div class="cards">
 <div class="card"><div class="n">{_ESC(ci.get('case_id') or '—')}</div><div class="l">Case ID</div></div>
 <div class="card"><div class="n">{len(doc['evidence'])}</div><div class="l">Evidence records</div></div>
 <div class="card"><div class="n">{len(doc['alerts'])}</div><div class="l">Alerts</div></div>
 <div class="card"><div class="n {status_cls}">{_ESC(status)}</div><div class="l">Integrity</div></div>
</div>

<h2>1. Case Information &amp; Authorization</h2>
{_tbl(['Field', 'Value'], [
  ['Case ID', ci.get('case_id')], ['Investigator', ci.get('investigator')],
  ['Organization', ci.get('organization')], ['Authorized by', ci.get('authorized_by')],
  ['Scope', ci.get('scope')], ['Valid until', ci.get('valid_until')],
  ['Script', ci.get('script')], ['Evidence directory', ci.get('evidence_directory')],
])}

<h2>2. Host Information</h2>
{_tbl(['Field', 'Value'], [
  ['Hostname', hi.get('hostname')], ['OS', hi.get('os')],
  ['Version', hi.get('version')], ['Architecture', hi.get('arch')],
  ['Host fingerprint', f"<span class='hash'>{_ESC(hi.get('host_id', ''))}</span>"],
])}

<h2>3. Collection Timeline</h2>
{_tbl(['Time (UTC)', 'Operation', 'Artifact', 'Records', 'Status'], timeline_rows)}

<h2>4. Findings &amp; Alerts</h2>
{_tbl(['Raised (UTC)', 'Severity', 'Message'], alert_rows)}
{_tbl(['Severity', 'Kind', 'Summary'], findings_rows)}

<h2>5. Evidence Records (chain of custody)</h2>
{_tbl(['Timestamp', 'Operation', 'Collected artifact', 'Result file (.jrf)',
       'Data hash', 'Integrity'], evidence_rows)}

<h2>6. Evidence SHA-256 Integrity</h2>
{_tbl(['Artifact', 'SHA-256', 'Integrity'], hash_rows)}
<p>Integrity status: <span class="{status_cls}">{_ESC(status)}</span>
 ({integ.get('verified', 0)} verified / {integ.get('artifacts', 0)} artifacts,
 {integ.get('modified', 0)} modified)</p>

<h2>7. Action Log Summary</h2>
{_tbl(['Timestamp', 'Command', 'Capability', 'Result', 'Outcome', 'Duration'], log_rows)}

<h2>8. Merkle Chain Root</h2>
<p><span class="hash">{_ESC(doc.get('merkle_root') or '—')}</span><br>
<span class="muted">Each evidence record embeds the hash of its predecessor; the root
commits the whole session.</span></p>

<footer>Generated by JOCKY Forensic Workbench · prototype · read-only user-space collection ·
authorized use only</footer>
</div></body></html>"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)
    except OSError as exc:
        raise errors.export_failed(f"cannot write HTML report '{path}': {exc}") from None
    return path
