"""JOCKY Forensic Workbench — GUI entry point."""

from __future__ import annotations

import os
import sys


def _selftest() -> int:
    """Headless verification for the frozen executable (JOCKY.exe --selftest).

    Compiles + runs the bundled demo script in-process and writes a log to
    %TEMP%\\JOCKY_selftest.log. Exit code 0 = all checks passed.
    """
    import tempfile
    import traceback

    log_path = os.path.join(tempfile.gettempdir(), "JOCKY_selftest.log")
    lines = []

    def check(name, fn):
        try:
            detail = fn()
            lines.append(f"[ OK ] {name}" + (f" — {detail}" if detail else ""))
        except Exception as exc:  # noqa: BLE001
            lines.append(f"[FAIL] {name}: {exc}")
            lines.append(traceback.format_exc())
            return False
        return True

    ok = True

    def _compile_demo():
        from jocky.compiler.api import compile_source
        demo = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                            "examples", "demo.jky")
        if not os.path.isfile(demo):
            demo = os.path.join(getattr(sys, "_MEIPASS", "."),
                                "examples", "demo.jky")
        with open(demo, "r", encoding="utf-8") as fh:
            src = fh.read()
        res = compile_source(src, source_file="demo.jky")
        return f"{len(res.ir['instructions'])} instructions"

    def _run_tiny():
        from jocky.modules.registry import ModuleRegistry
        from jocky.runtime.interpreter import JockyVM
        from jocky.compiler.api import compile_source
        src = ("@authorization { case_id: \"SELFTEST\" investigator: \"t\" "
               "authorized_by: \"t\" scope: \"sys\" "
               "valid_until: \"2099-01-01T00:00:00Z\" }\n"
               "let h = collect sys.info\nprint len(h)\n")
        compiled = compile_source(src, "selftest.jky")
        vm = JockyVM(ModuleRegistry())
        result = vm.run(compiled.ir, script_path="selftest.jky", ir_path="",
                        evidence_dir=os.path.join(tempfile.gettempdir(),
                                                  "JOCKY_selftest_ev"))
        if not result.ok:
            raise RuntimeError(result.detail or "run failed")
        return f"{len(result.evidence_records)} evidence records"

    ok &= check("compile demo.jky", _compile_demo)
    ok &= check("run authorized collection", _run_tiny)

    def _gui_import():
        from jocky.ui.main_window import MainWindow  # noqa: F401
        return "MainWindow importable"

    ok &= check("GUI modules", _gui_import)

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    sys.exit(0 if ok else 1)


def main() -> int:
    if "--selftest" in sys.argv:
        return _selftest()

    from PySide6.QtWidgets import QApplication

    from jocky import APP_NAME, APP_TAGLINE, __version__

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(f"JOCKY {__version__}")
    app.setOrganizationName("JOCKY Project")

    from jocky.ui.main_window import MainWindow
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

