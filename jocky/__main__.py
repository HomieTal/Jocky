"""JOCKY command-line interface.

    python -m jocky run demo.jky [--evidence-dir DIR]
    python -m jocky compile demo.jky [-o demo.jir]
    python -m jocky validate demo.jky
    python -m jocky doctor
    python -m jocky version
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from jocky import APP_NAME, APP_TAGLINE, __version__, version_string


def _default_evidence_dir() -> str:
    base = os.environ.get("JOCKY_EVIDENCE_DIR")
    if base:
        return base
    return os.path.join(os.path.expanduser("~"), "JOCKYEvidence")


def cmd_validate(args) -> int:
    from jocky.compiler.api import compile_source
    try:
        with open(args.script, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"[E070] cannot read script: {exc}")
        return 2
    try:
        res = compile_source(source, source_file=os.path.basename(args.script))
    except Exception as exc:
        print(f"VALIDATION FAILED\n{exc}")
        return 1
    for w in res.warnings:
        print(f"warning: {w}")
    print(f"VALID — {len(res.ir['instructions'])} instruction(s) compiled")
    return 0


def cmd_compile(args) -> int:
    from jocky.compiler.api import compile_source, save_ir
    try:
        with open(args.script, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"[E070] cannot read script: {exc}")
        return 2
    try:
        res = compile_source(source, source_file=os.path.basename(args.script))
    except Exception as exc:
        print(f"COMPILE FAILED\n{exc}")
        return 1
    out = args.output or os.path.splitext(args.script)[0] + ".jir"
    save_ir(res.ir, out)
    print(f"compiled -> {out} ({len(res.ir['instructions'])} instructions)")
    for w in res.warnings:
        print(f"warning: {w}")
    return 0


def cmd_run(args) -> int:
    from jocky.compiler.api import compile_source, save_ir
    from jocky.modules.registry import ModuleRegistry
    from jocky.runtime.interpreter import JockyVM

    script = args.script
    try:
        with open(script, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"[E070] cannot read script: {exc}")
        return 2

    evidence_dir = args.evidence_dir or _default_evidence_dir()
    print(f"{version_string()} — {APP_TAGLINE}")
    print(f"script:    {script}")
    print(f"evidence:  {evidence_dir}")

    try:
        res = compile_source(source, source_file=os.path.basename(script))
    except Exception as exc:
        print(f"COMPILE FAILED\n{exc}")
        return 1
    for w in res.warnings:
        print(f"warning: {w}")

    ir_path = os.path.join(evidence_dir,
                           os.path.splitext(os.path.basename(script))[0] + ".jir")
    save_ir(res.ir, ir_path)
    print(f"IR:        {ir_path}")

    vm = JockyVM(ModuleRegistry(),
                 print_fn=lambda s: print(f"  | {s}"),
                 progress_fn=lambda s: print(f"  · {s}"))
    result = vm.run(res.ir, script_path=script, ir_path=ir_path,
                    evidence_dir=evidence_dir)

    print(f"\nstatus:    {result.status}")
    print(f"duration:  {result.duration_ms} ms, {result.statements} statements")
    for alert in result.alerts:
        print(f"  [ALERT:{alert['severity']}] {alert['message']}")
    if result.evidence_records:
        integ = vm.evidence.verify_all()
        print(f"evidence:  {integ['artifacts']} artifact(s), {integ['verified']} "
              f"verified, status {integ['status']}")
    print(f"action log: {os.path.join(evidence_dir, 'action.log')}")
    if not result.ok:
        if result.error is not None:
            print(f"\n{result.error.format()}")
        return 1
    return 0


def cmd_doctor(args) -> int:
    print(version_string())
    checks = []
    try:
        import lark  # noqa: F401
        checks.append(("lark", lark.__version__, True))
    except Exception as exc:  # noqa: BLE001
        checks.append(("lark", str(exc), False))
    try:
        import psutil
        checks.append(("psutil", psutil.__version__, True))
    except Exception as exc:  # noqa: BLE001
        checks.append(("psutil", str(exc), False))
    try:
        import winreg  # noqa: F401
        checks.append(("winreg", "available", True))
    except Exception as exc:  # noqa: BLE001
        checks.append(("winreg", str(exc), False))
    try:
        import ctypes
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        checks.append(("privilege", "administrator" if elevated else "standard user",
                       True))
    except Exception as exc:  # noqa: BLE001
        checks.append(("privilege", str(exc), False))
    ev = _default_evidence_dir()
    try:
        os.makedirs(ev, exist_ok=True)
        checks.append(("evidence dir", ev + " writable", os.access(ev, os.W_OK)))
    except OSError as exc:
        checks.append(("evidence dir", str(exc), False))
    from jocky.modules.registry import ModuleRegistry
    mods = ModuleRegistry()
    checks.append(("modules", ", ".join(mods.modules()), True))
    ok = True
    for name, detail, good in checks:
        mark = "OK " if good else "FAIL"
        ok = ok and good
        print(f"  [{mark}] {name}: {detail}")
    print("JOCKY is ready for forensic operations." if ok
          else "Some components failed; the GUI may still run with reduced modules.")
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="jocky", description=f"{APP_NAME} — {APP_TAGLINE}")
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="compile and execute a .jky script")
    p_run.add_argument("script")
    p_run.add_argument("--evidence-dir", default=None)
    p_run.set_defaults(fn=cmd_run)

    p_c = sub.add_parser("compile", help="compile .jky -> .jir without executing")
    p_c.add_argument("script")
    p_c.add_argument("-o", "--output", default=None)
    p_c.set_defaults(fn=cmd_compile)

    p_v = sub.add_parser("validate", help="validate syntax + authorization")
    p_v.add_argument("script")
    p_v.set_defaults(fn=cmd_validate)

    p_d = sub.add_parser("doctor", help="health check")
    p_d.set_defaults(fn=cmd_doctor)

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.cmd == "version" or args.cmd is None:
        print(version_string())
        if args.cmd is None:
            parser.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
