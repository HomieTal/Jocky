"""JOCKY Forensic Workbench — main window (PySide6)."""

from __future__ import annotations

import json
import os
import platform as _platform
import socket as _socket
import sys
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont, QIcon
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
                               QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QPlainTextEdit, QPushButton, QSplitter, QTableView,
                               QTabWidget, QVBoxLayout, QWidget)

from jocky import APP_NAME, APP_TAGLINE, __version__
from jocky.case_manager.store import CaseManager
from jocky.compiler.api import compile_source, save_ir
from jocky.modules.registry import ModuleRegistry
from jocky.reports.generate import export_html, export_json, make_session
from jocky.runtime.interpreter import JockyVM
from jocky.ui.widgets import (CodeEditor, JockyHighlighter, RecordsTableModel,
                              style_sheet)

NEW_SCRIPT_TEMPLATE = '''# new_investigation.jky
# JOCKY forensic script — authorized use only (manual §1.5)

@authorization {
    case_id: "CASE-001"
    investigator: "Your Name"
    organization: "Your Organization"
    authorized_by: "Authorizing Officer"
    scope: "sys, mem, net"
    valid_until: "2026-12-31T23:59:59Z"
}

@requires privilege.user
@platform windows

print "=== Investigation started ==="

# Collect running processes with the highest memory usage
let procs = collect mem.processes
    where process.memory_mb > 100
    sort by process.memory_mb desc
    limit 20
print "processes over 100 MB: " + len(procs)

# Flag unsigned executables
let unsigned = collect mem.processes
    where process.is_signed == false and process.path != ""
if len(unsigned) > 0 {
    alert HIGH f"{len(unsigned)} unsigned executables are running"
}

export procs to json "processes.json"
print "=== done ==="
'''


def _default_evidence_dir() -> str:
    base = os.environ.get("JOCKY_EVIDENCE_DIR")
    if base:
        return base
    return os.path.join(os.path.expanduser("~"), "JOCKYEvidence")


def _find_demo_script() -> Optional[str]:
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    meipass = getattr(sys, "_MEIPASS", "")
    candidates = [
        os.path.join(exe_dir, "examples", "demo.jky"),
        os.path.join(exe_dir, "demo.jky"),
        os.path.join(meipass, "examples", "demo.jky") if meipass else "",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "examples", "demo.jky"),
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return None


class RunWorker(QThread):
    """Executes compile + run off the UI thread."""

    output = Signal(str)
    progress = Signal(str)
    finished_run = Signal(object, object)   # RunResult, JockyVM
    failed = Signal(str)                    # formatted error

    def __init__(self, source: str, script_path: str, evidence_dir: str,
                 save_ir_to: str, parent=None):
        super().__init__(parent)
        self._source = source
        self._script_path = script_path
        self._evidence_dir = evidence_dir
        self._ir_path = save_ir_to

    def run(self):  # noqa: D102
        try:
            compiled = compile_source(self._source,
                                      source_file=os.path.basename(self._script_path))
            save_ir(compiled.ir, self._ir_path)
            vm = JockyVM(ModuleRegistry(),
                         print_fn=self.output.emit,
                         progress_fn=self.progress.emit)
            result = vm.run(compiled.ir, script_path=self._script_path,
                            ir_path=self._ir_path, evidence_dir=self._evidence_dir)
            result.warnings = compiled.warnings
            self.finished_run.emit(result, vm)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{__version__}")
        self.resize(1280, 820)
        self.setStyleSheet(style_sheet())

        self.current_file: Optional[str] = None
        self.evidence_dir = _default_evidence_dir()
        self.last_result: Any = None
        self.last_vm: Optional[JockyVM] = None
        self.last_ir: Optional[dict] = None
        self.case_manager: Optional[CaseManager] = None
        self.executions: Dict[int, int] = {}

        self._build_ui()
        self._load_initial_script()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 8, 12, 8)
        root.setSpacing(8)

        # --- header -----------------------------------------------------
        header = QHBoxLayout()
        brand_box = QVBoxLayout()
        brand = QLabel("JOCKY")
        brand.setObjectName("brand")
        tagline = QLabel(APP_TAGLINE + "  ·  Forensic Workbench (Windows prototype)")
        tagline.setObjectName("tagline")
        brand_box.addWidget(brand)
        brand_box.addWidget(tagline)
        header.addLayout(brand_box)
        header.addStretch(1)
        self.status_label = QLabel("READY")
        self.status_label.setObjectName("statusLabel")
        header.addWidget(self.status_label)
        root.addLayout(header)

        # --- case row -----------------------------------------------------
        case_row = QHBoxLayout()
        case_row.addWidget(QLabel("Case ID"))
        self.case_id_edit = QLineEdit("DEMO-001")
        self.case_id_edit.setMaximumWidth(140)
        case_row.addWidget(self.case_id_edit)
        case_row.addWidget(QLabel("Investigator"))
        self.investigator_edit = QLineEdit("Demo Analyst")
        self.investigator_edit.setMaximumWidth(180)
        case_row.addWidget(self.investigator_edit)
        case_row.addWidget(QLabel("Evidence directory"))
        self.evidence_edit = QLineEdit(self.evidence_dir)
        case_row.addWidget(self.evidence_edit, 1)
        browse = QPushButton("Browse…")
        browse.setMaximumWidth(90)
        browse.clicked.connect(self._choose_evidence_dir)
        case_row.addWidget(browse)
        open_dir = QPushButton("Open Folder")
        open_dir.setMaximumWidth(110)
        open_dir.clicked.connect(self._open_evidence_folder)
        case_row.addWidget(open_dir)
        root.addLayout(case_row)

        # --- toolbar row --------------------------------------------------
        actions_row = QHBoxLayout()
        for text, slot, obj_name in (
                ("New", self._new_script, None),
                ("Open…", self._open_script, None),
                ("Save", self._save_script, None),
                ("Validate", self._validate, None),
                ("Compile", self._compile, None),
                ("Run", self._run, "runBtn"),
                ("Export JSON", self._export_json, None),
                ("Export HTML", self._export_html, None)):
            btn = QPushButton(text)
            if obj_name:
                btn.setObjectName(obj_name)
            btn.clicked.connect(slot)
            actions_row.addWidget(btn)
        actions_row.addStretch(1)
        root.addLayout(actions_row)

        # --- tabs -----------------------------------------------------------
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # Editor tab
        editor_tab = QWidget()
        ev = QVBoxLayout(editor_tab)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.editor = CodeEditor()
        self.editor.setPlainText(NEW_SCRIPT_TEMPLATE)
        self._highlighter = JockyHighlighter(self.editor.document())
        splitter.addWidget(self.editor)
        console_box = QWidget()
        cv = QVBoxLayout(console_box)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.addWidget(QLabel("Execution console"))
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)
        cv.addWidget(self.console)
        splitter.addWidget(console_box)
        splitter.setSizes([520, 240])
        ev.addWidget(splitter)
        self.tabs.addTab(editor_tab, "Script")

        # Results tab
        results_tab = QWidget()
        rv = QVBoxLayout(results_tab)
        row = QHBoxLayout()
        row.addWidget(QLabel("Collection"))
        self.collection_combo = QComboBox()
        self.collection_combo.setMinimumWidth(320)
        self.collection_combo.currentIndexChanged.connect(self._show_collection)
        row.addWidget(self.collection_combo)
        row.addStretch(1)
        row.addWidget(QLabel("Search"))
        self.search_edit = QLineEdit()
        self.search_edit.setMaximumWidth(260)
        self.search_edit.setPlaceholderText("filter rows…")
        self.search_edit.textChanged.connect(self._show_collection)
        row.addWidget(self.search_edit)
        self.collection_info = QLabel("")
        row.addWidget(self.collection_info)
        rv.addLayout(row)
        self.results_table = QTableView()
        self.results_table.setSortingEnabled(True)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self._records_model = RecordsTableModel([], [])
        self.results_table.setModel(self._records_model)
        rv.addWidget(self.results_table)
        self.tabs.addTab(results_tab, "Results")

        # Evidence tab
        evidence_tab = QWidget()
        evv = QVBoxLayout(evidence_tab)
        self.integrity_label = QLabel("Evidence Integrity\n" + "-" * 40)
        self.integrity_label.setObjectName("statusLabel")
        evv.addWidget(self.integrity_label)
        self.evidence_table = QTableView()
        self.evidence_table.setSortingEnabled(True)
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.verticalHeader().setVisible(False)
        self._evidence_model = RecordsTableModel([], [])
        self.evidence_table.setModel(self._evidence_model)
        evv.addWidget(self.evidence_table)
        self.tabs.addTab(evidence_tab, "Evidence")

        # Action log tab
        log_tab = QWidget()
        lv = QVBoxLayout(log_tab)
        self.log_summary = QLabel("Action log (.jal) — every runtime action")
        lv.addWidget(self.log_summary)
        self.log_table = QTableView()
        self.log_table.setSortingEnabled(True)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.verticalHeader().setVisible(False)
        self._log_model = RecordsTableModel([], [])
        self.log_table.setModel(self._log_model)
        lv.addWidget(self.log_table)
        self.tabs.addTab(log_tab, "Action Log")

        # IR tab
        ir_tab = QWidget()
        iv = QVBoxLayout(ir_tab)
        self.ir_label = QLabel("JOCKY IR (.jir)")
        iv.addWidget(self.ir_label)
        self.ir_view = QPlainTextEdit()
        self.ir_view.setReadOnly(True)
        iv.addWidget(self.ir_view)
        self.tabs.addTab(ir_tab, "IR")

        # Case tab
        case_tab = QWidget()
        cav = QVBoxLayout(case_tab)
        self.case_view = QPlainTextEdit()
        self.case_view.setReadOnly(True)
        cav.addWidget(self.case_view)
        self.tabs.addTab(case_tab, "Case")

        self.statusBar().showMessage(
            "Read-only user-space collection · every action is logged and hashed")

    # ------------------------------------------------------------------

    def _load_initial_script(self):
        demo = _find_demo_script()
        if demo:
            self._load_file(demo)
        else:
            self._new_script()

    # ------------------------------------------------------------------
    # File actions
    # ------------------------------------------------------------------

    def _new_script(self):
        self.editor.setPlainText(NEW_SCRIPT_TEMPLATE)
        self.current_file = None
        self._set_status("NEW")

    def _open_script(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open JOCKY script", self._script_dir(), "JOCKY scripts (*.jky);;All files (*)")
        if path:
            self._load_file(path)

    def _script_dir(self) -> str:
        if self.current_file:
            return os.path.dirname(self.current_file)
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        demo = _find_demo_script()
        return os.path.dirname(demo) if demo else exe_dir

    def _load_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            QMessageBox.critical(self, "JOCKY", f"Cannot open script:\n{exc}")
            return
        self.editor.setPlainText(text)
        self.current_file = path
        self.setWindowTitle(f"JOCKY — {os.path.basename(path)}")
        self._set_status("LOADED " + os.path.basename(path))

    def _save_script(self, choose: bool = False):
        if choose or not self.current_file:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save JOCKY script", self._script_dir() or "investigation.jky",
                "JOCKY scripts (*.jky)")
            if not path:
                return
            self.current_file = path
        try:
            with open(self.current_file, "w", encoding="utf-8") as fh:
                fh.write(self.editor.toPlainText())
        except OSError as exc:
            QMessageBox.critical(self, "JOCKY", f"Cannot save script:\n{exc}")
            return
        self._set_status("SAVED " + os.path.basename(self.current_file))

    # ------------------------------------------------------------------
    # Compile / validate / run
    # ------------------------------------------------------------------

    def _source(self) -> str:
        return self.editor.toPlainText()

    def _set_status(self, text: str, error: bool = False):
        self.status_label.setText(text)
        self.status_label.setStyleSheet(
            "color: #f48fb1;" if error else "color: #4fc3f7;")

    def _validate(self):
        try:
            compiled = compile_source(self._source(),
                                      source_file=os.path.basename(self.current_file or "script.jky"))
        except Exception as exc:  # noqa: BLE001
            self._set_status("VALIDATION FAILED", error=True)
            self.console.appendPlainText(f"[COMPILE ERROR]\n{exc}\n")
            QMessageBox.critical(self, "JOCKY — Validation", str(exc))
            return
        msgs = [f"Validation OK — {len(compiled.ir['instructions'])} instruction(s)."]
        msgs += [f"warning: {w}" for w in compiled.warnings]
        self._set_status("VALID")
        self.console.appendPlainText("\n".join(msgs) + "\n")
        QMessageBox.information(self, "JOCKY — Validation", "\n".join(msgs))

    def _compile(self):
        self.evidence_dir = self.evidence_edit.text().strip() or _default_evidence_dir()
        try:
            os.makedirs(self.evidence_dir, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self, "JOCKY", f"Cannot create evidence directory:\n{exc}")
            return
        try:
            compiled = compile_source(self._source(),
                                      source_file=os.path.basename(self.current_file or "script.jky"))
        except Exception as exc:  # noqa: BLE001
            self._set_status("COMPILE FAILED", error=True)
            self.console.appendPlainText(f"[COMPILE ERROR]\n{exc}\n")
            QMessageBox.critical(self, "JOCKY — Compile", str(exc))
            return
        name = os.path.splitext(os.path.basename(self.current_file or "script"))[0]
        ir_path = os.path.join(self.evidence_dir, name + ".jir")
        try:
            save_ir(compiled.ir, ir_path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "JOCKY", str(exc))
            return
        self.last_ir = compiled.ir
        self.ir_view.setPlainText(json.dumps(compiled.ir, indent=2, ensure_ascii=False,
                                             default=str))
        self.ir_label.setText(f"JOCKY IR (.jir) — {ir_path}")
        self.tabs.setCurrentIndex(3)
        self._set_status("COMPILED " + os.path.basename(ir_path))
        self.console.appendPlainText(f"compiled -> {ir_path}\n")

    def _run(self):
        if self._worker_running():
            return
        self.evidence_dir = self.evidence_edit.text().strip() or _default_evidence_dir()
        self.case_id = self.case_id_edit.text().strip() or "UNSET-CASE"
        try:
            os.makedirs(self.evidence_dir, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self, "JOCKY", f"Cannot create evidence directory:\n{exc}")
            return
        # persist the script next to evidence for chain of custody
        if not self.current_file:
            self._save_script()
        self.case_manager = CaseManager(os.path.join(self.evidence_dir, "cases.db"))

        script_path = self.current_file or "inline.jky"
        ir_path = os.path.join(
            self.evidence_dir,
            os.path.splitext(os.path.basename(script_path))[0] + ".jir")
        self.console.appendPlainText(
            f"--- RUN {os.path.basename(script_path)} (case {self.case_id}) ---")
        self._set_status("RUNNING…")
        self._run_btn_set(False)
        self._worker = RunWorker(self._source(), script_path, self.evidence_dir, ir_path)
        self._worker.output.connect(self.console.appendPlainText)
        self._worker.progress.connect(lambda s: self.statusBar().showMessage(s, 5000))
        self._worker.finished_run.connect(self._run_finished)
        self._worker.failed.connect(self._run_failed)
        self._worker.start()

    def _worker_running(self) -> bool:
        return getattr(self, "_worker", None) is not None and self._worker.isRunning()

    def _run_btn_set(self, enabled: bool):
        for btn in self.findChildren(QPushButton):
            if btn.objectName() == "runBtn":
                btn.setEnabled(enabled)

    def _run_failed(self, message: str):
        self._run_btn_set(True)
        self._set_status("FAILED", error=True)
        self.console.appendPlainText(f"[ERROR]\n{message}\n")
        QMessageBox.critical(self, "JOCKY — Run", message)

    def _run_finished(self, result, vm):
        self._run_btn_set(True)
        self.last_result = result
        self.last_vm = vm
        self._persist_case(result, vm)

        # console
        for alert in result.alerts:
            self.console.appendPlainText(f"[ALERT:{alert['severity']}] {alert['message']}")
        self.console.appendPlainText(
            f"--- {result.status}: {result.statements} statements, "
            f"{result.duration_ms} ms, {len(result.evidence_records)} evidence "
            f"artifact(s), merkle root {result.merkle_root[:19]}… ---\n")

        # results
        self.collection_combo.blockSignals(True)
        self.collection_combo.clear()
        for coll in result.collections:
            self.collection_combo.addItem(
                f"{coll['key']} — {coll['title']} ({len(coll['rows'])})", coll)
        self.collection_combo.blockSignals(False)
        if result.collections:
            self.collection_combo.setCurrentIndex(0)
            self._show_collection(0)

        # evidence
        evidence_rows = [{
            "timestamp": rec.get("timestamp", ""),
            "operation": rec.get("operation", ""),
            "records": (rec.get("source_metadata") or {}).get("rows", ""),
            "artifact": (rec.get("result_file") or "").replace("\\", "/").split("/")[-1],
            "data_hash": rec.get("data_hash", ""),
            "integrity": rec.get("integrity_status", ""),
        } for rec in result.evidence_records]
        self._evidence_model.set_rows(
            evidence_rows,
            ["timestamp", "operation", "records", "artifact", "data_hash", "integrity"])
        if vm.evidence is not None:
            integ = vm.evidence.verify_all()
            self.integrity_label.setText(
                f"Evidence Integrity\n{'-' * 40}\n"
                f"Artifacts: {integ['artifacts']}\n"
                f"Verified:  {integ['verified']}\n"
                f"Modified:  {integ['modified']}\n"
                f"Status:    {integ['status']}")

        # action log
        log_rows = [{
            "timestamp": e.get("timestamp", ""),
            "command": e.get("command", ""),
            "capability": e.get("capability", ""),
            "result": e.get("result", ""),
            "ok": e.get("success"),
            "duration_ms": e.get("duration_ms", 0),
            "sha256": (e.get("sha256") or "")[:26] + ("…" if e.get("sha256") else ""),
        } for e in (vm.action_log.entries if vm.action_log else [])]
        self._log_model.set_rows(
            log_rows, ["timestamp", "command", "capability", "result", "ok",
                       "duration_ms", "sha256"])
        self.log_summary.setText(
            f"Action log (.jal) — {len(log_rows)} entries · "
            f"{os.path.join(self.evidence_dir, 'action.log')}")

        # IR
        ir_path = os.path.join(
            self.evidence_dir,
            os.path.splitext(os.path.basename(self.current_file or "script"))[0] + ".jir")
        try:
            with open(ir_path, "r", encoding="utf-8") as fh:
                self.ir_view.setPlainText(fh.read())
            self.ir_label.setText(f"JOCKY IR (.jir) — {ir_path}")
        except OSError:
            pass

        # case tab
        self._refresh_case_tab()

        if result.ok:
            self._set_status(f"COMPLETED — {len(result.evidence_records)} artifacts")
            self.tabs.setCurrentIndex(1)
        else:
            self._set_status(result.status, error=True)
            if result.error is not None:
                self.console.appendPlainText(result.error.format() + "\n")
                QMessageBox.warning(self, "JOCKY — Run refused/failed",
                                    result.error.format())

    # ------------------------------------------------------------------
    # Results viewer
    # ------------------------------------------------------------------

    def _show_collection(self, index: int):
        coll = self.collection_combo.itemData(index)
        if coll is None:
            self._records_model.set_rows([], [])
            self.collection_info.setText("")
            return
        needle = self.search_edit.text().strip().lower()
        rows = coll["rows"]
        if needle:
            rows = [r for r in rows if needle in json.dumps(
                {k: v for k, v in r.items() if not isinstance(v, (list, dict))},
                default=str).lower()]
        self._records_model.set_rows(rows, coll.get("columns") or [])
        self.collection_info.setText(
            f"{len(rows)} of {len(coll['rows'])} records · artifact {coll.get('artifact', '')}")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _require_run(self) -> bool:
        if self.last_result is None or not self.last_result.ok:
            QMessageBox.information(
                self, "JOCKY — Export",
                "Run an authorized investigation first — the report is "
                "generated from the finished run's evidence.")
            return False
        return True

    def _export_json(self):
        if not self._require_run():
            return
        session = make_session(self.last_result, self.last_vm,
                               self.current_file or "script.jky", "")
        base = os.path.join(
            self.evidence_dir,
            f"{session['case_id']}_report_{self.last_result.generated_at.replace(':', '')}")
        path = base + ".json"
        try:
            export_json(session, path)
            self.case_manager.add_report(session["case_id"], path, "json", "")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "JOCKY — Export", str(exc))
            return
        self.console.appendPlainText(f"JSON report -> {path}\n")
        QMessageBox.information(self, "JOCKY — Export", f"JSON report written:\n{path}")

    def _export_html(self):
        if not self._require_run():
            return
        session = make_session(self.last_result, self.last_vm,
                               self.current_file or "script.jky", "")
        base = os.path.join(
            self.evidence_dir,
            f"{session['case_id']}_report_{self.last_result.generated_at.replace(':', '')}")
        path = base + ".html"
        try:
            export_html(session, path)
            self.case_manager.add_report(session["case_id"], path, "html", "")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "JOCKY — Export", str(exc))
            return
        self.console.appendPlainText(f"HTML report -> {path}\n")
        QMessageBox.information(self, "JOCKY — Export", f"HTML report written:\n{path}")

    # ------------------------------------------------------------------
    # Case management
    # ------------------------------------------------------------------

    def _persist_case(self, result, vm):
        if self.case_manager is None:
            return
        auth = vm.auth
        self.case_manager.upsert_case(
            auth.case_id, auth.investigator, auth.organization, auth.authorized_by,
            auth.scope, auth.valid_until)
        exec_id = self.case_manager.start_execution(
            auth.case_id, self.current_file or "", "")
        self.executions[result.generated_at] = exec_id
        for rec in result.evidence_records:
            self.case_manager.add_evidence(
                auth.case_id, exec_id, rec.get("result_file", ""),
                rec.get("operation", ""), rec.get("file_sha256", "")
                or rec.get("data_hash", ""), rec.get("integrity_status", ""))
        for alert in result.alerts:
            self.case_manager.add_alert(auth.case_id, exec_id, alert["severity"],
                                        alert["message"])
        self.case_manager.finish_execution(
            exec_id, result.ok, result.statements, result.duration_ms,
            result.status, result.detail or (result.error.format()
                                             if result.error else ""))

    def _refresh_case_tab(self):
        if self.case_manager is None:
            self.case_view.setPlainText("No case loaded yet — run an investigation.")
            return
        case_id = self.case_id_edit.text().strip() or "DEMO-001"
        summary = self.case_manager.case_summary(case_id)
        lines = [f"CASE {case_id}", "=" * 60]
        case = summary.get("case")
        if case:
            lines += [
                f"Investigator : {case.get('investigator')}",
                f"Organization : {case.get('organization')}",
                f"Authorized by: {case.get('authorized_by')}",
                f"Scope        : {case.get('scope')}",
                f"Valid until  : {case.get('valid_until')}",
                f"Created      : {case.get('created_at')}",
            ]
        integ = summary.get("integrity") or {}
        lines += ["", f"Evidence: {integ.get('artifacts', 0)} artifact(s), "
                      f"{integ.get('verified', 0)} verified, "
                      f"{integ.get('modified', 0)} modified"]
        counts = summary.get("alert_counts") or {}
        lines.append(f"Alerts   : "
                     + ", ".join(f"{sev} {n}" for sev, n in counts.items() if n)
                     + f" (total {len(summary.get('alerts') or [])})")
        lines.append("")
        lines.append("EXECUTION HISTORY")
        lines.append("-" * 60)
        for e in summary.get("executions") or []:
            lines.append(f"  {e['started_at']}  {e['status']:<10} "
                         f"{e['statements']} stmts {e['duration_ms']} ms  "
                         f"{os.path.basename(e['script'] or '')}")
        lines.append("")
        lines.append("EVIDENCE (latest first)")
        lines.append("-" * 60)
        for ev in (summary.get("evidence") or [])[:30]:
            lines.append(f"  {ev['collected_at']}  [{ev['integrity']}] "
                         f"{ev['operation']}  {os.path.basename(ev['artifact'])}")
        lines.append("")
        lines.append("REPORTS")
        lines.append("-" * 60)
        for r in summary.get("reports") or []:
            lines.append(f"  {r['generated_at']}  [{r['format']}] {r['path']}")
        self.case_view.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _choose_evidence_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select evidence directory", self.evidence_edit.text())
        if path:
            self.evidence_edit.setText(path)

    def _open_evidence_folder(self):
        path = self.evidence_edit.text().strip()
        if path and os.path.isdir(path):
            os.startfile(path)  # noqa: S606 — Windows explorer
