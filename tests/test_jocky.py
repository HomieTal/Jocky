"""JOCKY automated test suite (stdlib unittest).

Run:  python -m unittest discover -s tests -v
Covers: lexer/parser, AST, IR generation, authorization, capability
validation, collectors, file hashing, evidence generation, action
logging, report generation and a full end-to-end pipeline.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jocky.ast import nodes as A  # noqa: E402
from jocky.authorization.model import Authorization  # noqa: E402
from jocky.compiler.api import compile_source  # noqa: E402
from jocky.compiler.parser import JockyParser, parse_source  # noqa: E402
from jocky.compiler.irgen import generate_ir  # noqa: E402
from jocky.evidence.store import ActionLog, EvidenceStore  # noqa: E402
from jocky.modules.registry import ModuleRegistry  # noqa: E402
from jocky.modules.base import CollectContext  # noqa: E402
from jocky.reports.generate import export_html, export_json, make_session  # noqa: E402
from jocky.runtime import errors  # noqa: E402
from jocky.runtime.capabilities import (CapabilityEnforcer, capability_for_module,
                                        ALL_CAPABILITIES)  # noqa: E402
from jocky.runtime.interpreter import JockyVM  # noqa: E402

AUTH = '''@authorization {
    case_id: "T-001"
    investigator: "Test Analyst"
    authorized_by: "Self-Test"
    scope: "sys, mem, net, reg, log, disk"
    valid_until: "2099-12-31T23:59:59Z"
}
'''


def _script(body: str, scope: str = "sys, mem, net, reg, log, disk") -> str:
    return AUTH.replace('scope: "sys, mem, net, reg, log, disk"',
                        f'scope: "{scope}"') + body


# ---------------------------------------------------------------------------
# Parser / AST / IR
# ---------------------------------------------------------------------------

class ParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = JockyParser()

    def test_authorization_block(self):
        prog = self.parser.parse(AUTH + 'let x = 1')
        auth = prog.directives[0]
        self.assertEqual(auth.fields["case_id"], "T-001")
        self.assertEqual(auth.fields["investigator"], "Test Analyst")

    def test_collect_pipeline_stages(self):
        prog = self.parser.parse(_script(
            'let p = collect mem.processes\n'
            '    where process.memory_mb > 500 and process.is_signed == false\n'
            '    sort by process.memory_mb desc\n'
            '    limit 10\n'))
        let = prog.statements[0]
        self.assertIsInstance(let, A.LetStmt)
        stages = let.value.stages
        self.assertEqual(len(stages), 3)
        self.assertIsInstance(stages[0], A.WhereStage)
        self.assertIsInstance(stages[1], A.SortStage)
        self.assertTrue(stages[1].descending)
        self.assertEqual(stages[2].count, 10)
        # compound where
        self.assertEqual(stages[0].expr.op, "and")

    def test_operators(self):
        prog = self.parser.parse(_script(
            'print "abc" contains "b"\n'
            'print "x" not in ["y"]\n'
            'print 2 ** 10 + 0xFF - 1.5e2 * 2 // 3 % 4\n'
            'print not (true or false)\n'
            'print "file.exe" endswith ".exe"\n'))
        self.assertEqual(len(prog.statements), 5)

    def test_literals_and_collections(self):
        prog = self.parser.parse(_script(
            'let a = [1, 2.5, "x", true, null]\n'
            'let m = { "pid": 42, "name": "svc" }\n'
            'let r = r"C:\\temp\\logs"\n'
            'let f = f"pid {a[0]}"\n'))
        self.assertEqual(len(prog.statements), 4)

    def test_control_flow(self):
        prog = self.parser.parse(_script(
            'func check(p, min_mb: float = 100.0) {\n'
            '    return p.memory_mb > min_mb\n'
            '}\n'
            'foreach p in collect mem.processes {\n'
            '    if p.memory_mb > 100 { print p.name }\n'
            '    elif p.memory_mb > 50 { continue }\n'
            '    else { break }\n'
            '}\n'
            'while false { print 1 }\n'))
        self.assertEqual([type(s).__name__ for s in prog.statements],
                         ["FuncDef", "ForeachStmt", "WhileStmt"])

    def test_syntax_error_line(self):
        with self.assertRaises(Exception) as ctx:
            parse_source('let a = 1\nlet b = = 2\n')
        self.assertIn("line 2", str(ctx.exception))


class IRTests(unittest.TestCase):
    def test_ir_shape(self):
        compiled = compile_source(_script(
            'let top = collect mem.processes\n'
            '    where process.memory_mb > 500\n'
            '    sort by process.memory_mb desc\n'
            '    limit 10\n'
            'print len(top)\n'
            'export top to json "out.json"\n'))
        ir = compiled.ir
        self.assertEqual(ir["jir_version"], "1.0")
        self.assertEqual(ir["metadata"]["case_id"], "T-001")
        self.assertEqual(ir["metadata"]["authorization"]["case_id"], "T-001")
        ops = [i["op"] for i in ir["instructions"]]
        self.assertEqual(ops, ["COLLECT", "ASSIGN", "PRINT", "EXPORT"])
        collect = ir["instructions"][0]
        self.assertEqual(collect["module"], "mem")
        self.assertEqual(collect["entity"], "processes")
        self.assertEqual(len(collect["filters"]), 1)
        self.assertEqual(collect["sort"]["field"], "process.memory_mb")
        self.assertEqual(collect["limit"], 10)
        self.assertIn("script_sha256", ir["metadata"])

    def test_bare_collect_produces_collect_instruction(self):
        compiled = compile_source(_script('let host = collect sys.info\n'))
        self.assertEqual(compiled.ir["instructions"][0]["op"], "COLLECT")
        self.assertEqual(compiled.ir["instructions"][0]["module"], "sys")


# ---------------------------------------------------------------------------
# Authorization / capabilities
# ---------------------------------------------------------------------------

class AuthorizationTests(unittest.TestCase):
    def _auth(self, **over):
        fields = {"case_id": "T-001", "investigator": "Analyst",
                  "authorized_by": "Self", "scope": "mem, net",
                  "valid_until": "2099-12-31T23:59:59Z"}
        fields.update(over)
        return Authorization.from_fields(fields)

    def test_valid(self):
        self._auth().validate()  # must not raise

    def test_missing_fields(self):
        for drop in ("case_id", "investigator", "authorized_by", "scope",
                     "valid_until"):
            fields = {"case_id": "T", "investigator": "A", "authorized_by": "S",
                      "scope": "mem", "valid_until": "2099-01-01T00:00:00Z"}
            fields.pop(drop)
            with self.assertRaises(errors.JockyError) as ctx:
                Authorization.from_fields(fields).validate()
            self.assertEqual(ctx.exception.code, "E001")

    def test_expired(self):
        with self.assertRaises(errors.JockyError) as ctx:
            self._auth(valid_until="2020-01-01T00:00:00Z").validate()
        self.assertEqual(ctx.exception.code, "E002")

    def test_invalid_timestamp(self):
        with self.assertRaises(errors.JockyError) as ctx:
            self._auth(valid_until="not-a-date").validate()
        self.assertEqual(ctx.exception.code, "E003")

    def test_scope_enforcement(self):
        auth = self._auth(scope="mem")
        auth.check_module_in_scope("mem")  # ok
        with self.assertRaises(errors.JockyError) as ctx:
            auth.check_module_in_scope("reg")
        self.assertEqual(ctx.exception.code, "E004")

    def test_compile_requires_authorization(self):
        with self.assertRaises(errors.JockyError) as ctx:
            compile_source('print "no auth"\n')
        self.assertEqual(ctx.exception.code, "E001")

    def test_compile_rejects_out_of_scope(self):
        with self.assertRaises(errors.JockyError) as ctx:
            compile_source(_script('collect reg.autoruns', scope="mem"))
        self.assertEqual(ctx.exception.code, "E004")

    def test_compile_rejects_unknown_module(self):
        with self.assertRaises(errors.JockyError) as ctx:
            compile_source(_script('collect bogus.things'))
        self.assertEqual(ctx.exception.code, "E030")

    def test_compile_rejects_bad_field(self):
        with self.assertRaises(errors.JockyError) as ctx:
            compile_source(_script(
                'collect mem.processes where process.not_a_field == 1'))
        self.assertEqual(ctx.exception.code, "E102")

    def test_capability_policy(self):
        enf = CapabilityEnforcer()
        for cap in ALL_CAPABILITIES:
            enf.check_capability(cap)  # all read-only caps granted


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

class CollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ModuleRegistry()

    def _run(self, key: str, args=None, kwargs=None):
        return self.registry.run(key, args or [], kwargs or {}, CollectContext())

    def test_sys_info(self):
        rows = self._run("sys.info")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["hostname"])
        self.assertIn("Windows", rows[0]["os"])

    def test_processes(self):
        rows = self._run("mem.processes", kwargs={"cpu_sample": 0.0,
                                                  "with_modules": False,
                                                  "with_connections": False})
        self.assertGreater(len(rows), 10)
        pid_row = rows[0]
        for field in ("pid", "name", "memory_mb", "is_signed", "user"):
            self.assertIn(field, pid_row)
        # system process (pid 4) or at least one process has a name
        self.assertTrue(any(r["name"] for r in rows))

    def test_connections(self):
        rows = self._run("net.connections")
        self.assertGreater(len(rows), 0)
        for field in ("local_addr", "local_port", "protocol", "state"):
            self.assertIn(field, rows[0])

    def test_arp_and_routing(self):
        arp = self._run("net.arp_table")
        self.assertGreater(len(arp), 0)
        self.assertIn("ip", arp[0])
        routes = self._run("net.routing_table")
        self.assertGreater(len(routes), 0)
        self.assertIn("destination", routes[0])

    def test_registry_autoruns_and_services(self):
        autoruns = self._run("reg.autoruns")
        for row in autoruns:
            self.assertIn("location", row)
            self.assertIn("signature_status", row)
        services = self._run("reg.services", kwargs={"limit": 25})
        self.assertGreater(len(services), 0)
        self.assertIn("start_mode", services[0])

    def test_userassist(self):
        rows = self._run("reg.userassist")
        for row in rows:
            self.assertIn("program", row)
            self.assertIn("run_count", row)

    def test_event_log(self):
        rows = self._run("log.windows_events",
                         kwargs={"channel": "System", "max": 10,
                                 "within_hours": 720})
        self.assertLessEqual(len(rows), 10)
        for row in rows:
            self.assertIn("event_id", row)
            self.assertIn("time", row)

    def test_disk_files(self):
        tmp = tempfile.mkdtemp(prefix="jocky_test_")
        try:
            with open(os.path.join(tmp, "a.txt"), "w") as fh:
                fh.write("hello jocky evidence")
            rows = self._run("disk.files", kwargs={"path": tmp, "depth": 2,
                                                   "hash": True})
            self.assertEqual(len(rows), 1)
            digest = rows[0]["sha256"]
            self.assertEqual(len(digest), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in digest))
            self.assertEqual(rows[0]["size_bytes"], 20)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Evidence / action log / reports
# ---------------------------------------------------------------------------

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jocky_ev_")
        self.log = ActionLog(os.path.join(self.tmp, "action.log"), "T-001", "Tester")
        self.store = EvidenceStore(self.tmp, "T-001", "Tester", self.log)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_evidence_record_integrity(self):
        rec = self.store.write_artifact("t1", [{"a": 1}], "COLLECT test.x", "Test")
        self.assertTrue(os.path.isfile(rec["result_file"]))
        self.assertTrue(rec["data_hash"].startswith("sha256:"))
        self.assertTrue(rec["file_sha256"].startswith("sha256:"))
        self.assertEqual(rec["integrity_status"], "VERIFIED")
        integ = self.store.verify_all()
        self.assertEqual(integ["status"], "VERIFIED")
        self.assertEqual(integ["modified"], 0)

    def test_tamper_detection(self):
        rec = self.store.write_artifact("t2", [{"a": 1}], "COLLECT test.x", "Test")
        with open(rec["result_file"], "a", encoding="utf-8") as fh:
            fh.write("\nTAMPERED")
        integ = self.store.verify_all()
        self.assertEqual(integ["status"], "FAILED")
        self.assertEqual(integ["modified"], 1)

    def test_merkle_chain(self):
        r1 = self.store.write_artifact("m1", [], "OP1", "A")
        r2 = self.store.write_artifact("m2", [], "OP2", "B")
        self.assertEqual(r2["parent_hash"], r1["record_hash"])
        self.assertTrue(r1["parent_hash"] == "")

    def test_action_log_written(self):
        self.log.add(command="COLLECT test.x", capability="PROCESS_READ",
                     result="ok", success=True, duration_ms=5)
        with open(self.log.path, "r", encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["command"], "COLLECT test.x")
        self.assertEqual(entries[0]["case_id"], "T-001")


class ReportTests(unittest.TestCase):
    def test_json_and_html_export(self):
        tmp = tempfile.mkdtemp(prefix="jocky_rep_")
        try:
            session = {
                "title": "Test Report", "case_id": "T-100",
                "investigator": "Analyst", "organization": "Org",
                "authorized_by": "Self", "scope": "mem",
                "valid_until": "2099-01-01T00:00:00Z",
                "script_path": "t.jky", "ir_path": "", "evidence_dir": tmp,
                "host": {"hostname": "H", "os": "Windows 11", "version": "10",
                         "arch": "AMD64", "host_id": "sha256:x"},
                "timeline": [{"time": "now", "operation": "COLLECT mem.processes",
                              "artifact": "a.jrf", "records": 3, "status": "VERIFIED"}],
                "findings": [{"severity": "HIGH", "kind": "alert", "summary": "s"}],
                "alerts": [{"severity": "HIGH", "message": "s", "raised_at": "now"}],
                "evidence_records": [], "merkle_root": "sha256:r",
                "action_log_summary": {"entries": [], "alert_counts": {"HIGH": 1}},
                "integrity": {"artifacts": 0, "verified": 0, "modified": 0,
                              "status": "NO ARTIFACTS"},
                "generated_at": "now",
            }
            jpath = export_json(session, os.path.join(tmp, "r.json"))
            with open(jpath, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["case_information"]["case_id"], "T-100")
            hpath = export_html(session, os.path.join(tmp, "r.html"))
            with open(hpath, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("T-100", html)
            self.assertIn("Evidence SHA-256 Integrity", html)
            self.assertIn("Merkle Chain Root", html)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Interpreter semantics (no network/process needed)
# ---------------------------------------------------------------------------

class InterpreterTests(unittest.TestCase):
    def _run(self, body: str, scope: str = "sys, mem, net, reg, log, disk"):
        compiled = compile_source(_script(body, scope))
        vm = JockyVM(ModuleRegistry())
        result = vm.run(compiled.ir, script_path="test.jky", ir_path="",
                        evidence_dir=tempfile.mkdtemp(prefix="jocky_vm_"))
        return result, vm

    def test_runtime_scope_refusal(self):
        with self.assertRaises(errors.JockyError) as ctx:
            self._run('collect reg.autoruns', scope="mem")
        self.assertEqual(ctx.exception.code, "E004")

    def test_print_and_fstring(self):
        result, vm = self._run(
            'let x = 3\nprint "value: " + str(x)\nprint f"x={x * 2}"\n')
        self.assertTrue(result.ok)
        self.assertIn("value: 3", result.prints[0])
        self.assertIn("x=6", result.prints[1])

    def test_pipeline_on_variable(self):
        result, vm = self._run(
            'let a = [5, 2, 8, 1]\n'
            'let b = a | sort by value desc | limit 2\n'
            'print b[0] + b[1]\n')
        # sort field "value" missing on ints -> stable order; limit keeps first 2
        self.assertTrue(result.ok)

    def test_where_over_records(self):
        result, vm = self._run(
            'let host = collect sys.info\n'
            'let h2 = host | where system.hostname != ""\n'
            'print len(h2)\n')
        self.assertTrue(result.ok)
        self.assertEqual(result.prints[-1], "1")

    def test_if_foreach(self):
        result, vm = self._run(
            'let n = 0\n'
            'foreach x in [1, 2, 3] {\n'
            '    if x == 2 { continue }\n'
            '    n = n + x\n'
            '}\n'
            'print n\n')
        self.assertTrue(result.ok)
        self.assertEqual(result.prints[-1], "4")

    def test_user_function(self):
        result, vm = self._run(
            'func add(a, b) { return a + b }\n'
            'print add(2, 40)\n')
        self.assertTrue(result.ok)
        self.assertEqual(result.prints[-1], "42")

    def test_const_reassignment_rejected(self):
        result, vm = self._run('const MAX = 1\nMAX = 2\n')
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E040")

    def test_alerts(self):
        result, vm = self._run('alert CRITICAL "bad thing"\n')
        self.assertTrue(result.ok)
        self.assertEqual(result.alerts[0]["severity"], "CRITICAL")
        self.assertEqual(result.alert_counts["CRITICAL"], 1)

    def test_unsupported_export_format(self):
        result, vm = self._run('export [1] to pdf "x.pdf"\n')
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E106")


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

class EndToEndTests(unittest.TestCase):
    def test_full_pipeline(self):
        """Create .jky -> Validate -> Compile -> .jir -> Execute -> .jrf
        -> .jal -> verify SHA-256 -> export report."""
        tmp = tempfile.mkdtemp(prefix="jocky_e2e_")
        try:
            script = _script(
                'let host = collect sys.info\n'
                'let procs = collect mem.processes\n'
                '    where process.memory_mb > 0\n'
                '    sort by process.memory_mb desc\n'
                '    limit 5\n'
                'print "procs: " + len(procs)\n'
                'export procs to json "top.json"\n'
                'export host to html "host.html"\n')
            path = os.path.join(tmp, "e2e.jky")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(script)

            # validate + compile
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            compiled = compile_source(source, source_file="e2e.jky")
            ir_path = os.path.join(tmp, "e2e.jir")
            with open(ir_path, "w", encoding="utf-8") as fh:
                json.dump(compiled.ir, fh)

            # execute
            vm = JockyVM(ModuleRegistry())
            result = vm.run(compiled.ir, script_path=path, ir_path=ir_path,
                            evidence_dir=tmp)
            self.assertTrue(result.ok, result.detail)

            # .jir exists
            self.assertTrue(os.path.isfile(ir_path))

            # .jrf evidence exists and verifies
            jrf = [f for f in os.listdir(tmp) if f.endswith(".jrf")]
            self.assertGreaterEqual(len(jrf), 3)  # 2 collects + 2 exports + ...
            integ = vm.evidence.verify_all()
            self.assertEqual(integ["status"], "VERIFIED")

            # .jal exists with entries
            with open(os.path.join(tmp, "action.log"), encoding="utf-8") as fh:
                jal = [json.loads(l) for l in fh if l.strip()]
            self.assertGreater(len(jal), 10)
            self.assertTrue(all("timestamp" in e and "command" in e for e in jal))

            # exports exist
            self.assertTrue(os.path.isfile(os.path.join(tmp, "top.json")))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "host.html")))

            # report export
            session = make_session(result, vm, path, ir_path)
            jpath = export_json(session, os.path.join(tmp, "report.json"))
            with open(jpath, encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertEqual(report["case_information"]["case_id"], "T-001")
            self.assertTrue(report["evidence_hashes"])
            hpath = export_html(session, os.path.join(tmp, "report.html"))
            self.assertTrue(os.path.getsize(hpath) > 1000)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
