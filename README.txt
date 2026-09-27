================================================================================
  JOCKY — Just One Comprehensive Key-forensics Yield
  Forensic Scripting Language · Forensic Workbench · Windows Prototype (SIH 2026)
================================================================================

JOCKY is a domain-specific forensic scripting language for AUTHORIZED digital
forensics and incident response. Scripts (.jky) are compiled by a Lark-based
parser into a human-readable JSON intermediate representation (.jir), which is
executed by a sandboxed, READ-ONLY runtime (JVMO). Every collection produces a
hashed .jrf evidence record; every action is appended to a .jal action log.

    .jky  ->  Lexer -> Parser -> AST -> Semantic Validation
          ->  Authorization Validation -> JSON IR (.jir) -> Controlled Runtime

--------------------------------------------------------------------------------
  QUICK START
--------------------------------------------------------------------------------
1. Double-click JOCKY.exe (no Python, no pip, no source code required).
2. The bundled demo script (examples/demo.jky) loads automatically.
3. Press  Validate  — checks JOCKY syntax, @authorization and semantics.
4. Press  Compile   — generates the .jir intermediate representation.
5. Press  Run       — executes the authorized, read-only investigation.
6. Inspect the tabs:  Results / Evidence / Action Log / IR / Case.
7. Press  Export JSON  or  Export HTML  to write the investigation report.

All artifacts are written to the evidence directory shown at the top
(default: %USERPROFILE%\JOCKYEvidence).

Command line equivalents (with Python installed):
    python -m jocky run demo.jky
    python -m jocky compile demo.jky -o demo.jir
    python -m jocky validate demo.jky
    python -m jocky doctor
    JOCKY.exe --selftest          (headless verification of this executable)

--------------------------------------------------------------------------------
  THE JOCKY LANGUAGE (MVP subset implemented)
--------------------------------------------------------------------------------
Directives        @authorization { ... }   (mandatory, manual §1.5)
                  @requires privilege.user|privilege.admin
                  @platform windows

Declarations      let x = expr        const MAX = 100
                  func name(a, b: int = 0) { return a + b }

Forensic verbs    collect module.entity(args...)     snapshot module.entity
                  where <condition> [and|or ...]     sort by field [asc|desc]
                  limit N                            export x to json|csv|html "f"
                  alert LOW|MEDIUM|HIGH|CRITICAL "message"    print expr

Control flow      if / elif / else     foreach x in coll { }     while cond { }
                  break / continue / return

Pipeline operator collections  |  where  |  sort by  |  limit   (manual §6.5)

Values            strings "…" '…' r"raw" f"interpolated {x:>8} with format specs"
                  ints (0xFF, 0b1010, 0o755)   floats   true/false/null
                  lists [1, 2, 3]   maps { "key": value }

Operators         + - * / // % **   == != < > <= >=
                  in / not in   matches (regex)   contains   startswith   endswith
                  and / or / not          pipeline |

Built-in funcs    len str int float bool range hash typeof env sleep now epoch
                  upper lower keys
Module funcs      mem.find_process(name)   disk.hash(path, algo)   disk.hash_dir(path)

--------------------------------------------------------------------------------
  FORENSIC MODULES (all strictly read-only)
--------------------------------------------------------------------------------
sys.info          hostname, OS, build, arch, CPU, memory, boot time, elevation

mem.processes     pid, ppid, name, path, cmdline, memory_mb, cpu_pct,
                  is_signed (Authenticode + catalog), create_time, user,
                  modules, connections, parent_name

net.connections   local/remote addr+port, protocol, state, pid, process_name
net.interfaces    name, up, speed, mtu, mac, ipv4, ipv6
net.arp_table     interface, ip, mac, type
net.routing_table destination, netmask, gateway, interface, metric
net.dns_cache     name, record type, ttl, data, section

reg.autoruns      Run/RunOnce (HKLM+HKU, 64/32-bit views) with signature status
reg.services      service metadata, image path, start mode
reg.mru           Explorer OpenSave MRU
reg.userassist    GUI execution history, ROT13-decoded, run counts, last run

log.windows_events(channel, event_id, max, within_hours)
                  any channel: Security*, System, Application, PowerShell…
                  (* Security requires Administrator)

disk.files(path, depth, extension, hash, md5, hidden, modified_within_hours)
                  metadata, timestamps, hidden attribute, owner, SHA-256/MD5
                  (opt-in hashing, 256 MB per-file cap)

Example script — see examples/demo.jky:

    @authorization {
        case_id: "DEMO-001"
        investigator: "Demo Analyst"
        authorized_by: "Self-Test"
        scope: "sys, mem, net, reg, log, disk"
        valid_until: "2026-12-31T23:59:59Z"
    }
    @requires privilege.user
    @platform windows

    let procs = collect mem.processes
        where process.memory_mb > 50
        sort by process.memory_mb desc
        limit 10
    export procs to json "top_processes.json"

--------------------------------------------------------------------------------
  AUTHORIZATION & CAPABILITY MODEL
--------------------------------------------------------------------------------
Every script MUST carry an @authorization block. The runtime REFUSES to run
(mandatory, no override) when:
    E001  authorization missing or incomplete (case_id, investigator,
          authorized_by, scope, valid_until)
    E002  authorization expired (valid_until passed)
    E003  valid_until is not ISO-8601
    E004  a collect targets a module outside the declared scope
    E010  @requires privilege.admin but process is not elevated — no silent
          escalation, ever
    E020  @platform mismatch

Capability flow for every operation:

    Requested Operation -> Declared Scope -> Authorization
        -> Capability Policy -> Execution

Capabilities: PROCESS_READ, NETWORK_READ, REGISTRY_READ, EVENTLOG_READ,
FILE_READ, HASH_FILE, EVIDENCE_EXPORT, SYSTEM_READ — read-only only.

DEMO/SELF-TEST MODE: the shipped examples use authorized_by: "Self-Test" so
the prototype can be demonstrated safely on your own machine.

--------------------------------------------------------------------------------
  EVIDENCE, INTEGRITY & AUDIT
--------------------------------------------------------------------------------
.jrf  Evidence record per collection/export: case id, investigator, hostname,
      Windows version, UTC timestamp, operation, collected artifact, data
      SHA-256, file SHA-256, Merkle parent hash (chain of custody), source
      metadata, result file, integrity status.
.jal  Action log (JSON lines): timestamp, case id, investigator, command,
      capability, result, success, duration, artifact, artifact SHA-256.
      Every statement, collection, export and alert is logged.
IR    The Evidence tab re-hashes every artifact at any time:

      Evidence Integrity
      ----------------------------------------
      Artifacts: 13
      Verified:  13
      Modified:  0
      Status:    VERIFIED

      Tampering with any .jrf flips its status to MODIFIED/FAILED.

--------------------------------------------------------------------------------
  ERROR CODES (manual Appendix C + prototype extensions)
--------------------------------------------------------------------------------
E001 AUTH_MISSING        E050 NAME_ERROR          E101 PARSE_ERROR
E002 AUTH_EXPIRED        E060 COLLECT_FAILED      E102 INVALID_FIELD
E003 AUTH_INVALID_SIG    E070 EXPORT_FAILED       E103 INVALID_FILTER
E004 AUTH_SCOPE_DENIED   E080 IOC_PARSE_ERROR     E104 MALFORMED_IR
E010 PRIV_DENIED         E090 NETWORK_ERROR       E105 EVIDENCE_WRITE_FAILED
E020 PLATFORM_MISMATCH   E100 RUNTIME_ERROR       E106 UNSUPPORTED_FEATURE
E030 MODULE_NOT_FOUND                             E107 CAPABILITY_DENIED
E040 TYPE_ERROR

Errors identify the source line and explain the problem.

--------------------------------------------------------------------------------
  CASE MANAGEMENT
--------------------------------------------------------------------------------
Cases are stored locally in SQLite (cases.db inside the evidence directory):
case id, investigator, authorization record, execution history, evidence
index, alerts, reports and integrity information. The Case tab shows the
summary; no external server is required.

--------------------------------------------------------------------------------
  SECURITY DESIGN (read this before demonstrating)
--------------------------------------------------------------------------------
JOCKY is DEFENSIVE and TRANSPARENT:
  - user-space, read-only collection only (no registry writes, no file
    modification, no process injection, no kernel interaction, no drivers)
  - no AV/EDR bypass, no credential access, no persistence, no covert
    networking, no evasion techniques of any kind
  - every read is logged with capability + hash for chain-of-custody
  - attacker techniques appear only as DETECTION TARGETS (unsigned autoruns,
    LOL-bins, 4625 brute force, service installations, dropped executables)

Running JOCKY on systems you are not authorized to investigate is illegal.

--------------------------------------------------------------------------------
  PROJECT LAYOUT (source tree)
--------------------------------------------------------------------------------
jocky/
  grammar/jocky.lark        Lark LALR(1) grammar (manual Appendix D)
  ast/nodes.py              AST node definitions
  compiler/parser.py        lexer + postlexer + AST transformer
  compiler/irgen.py         AST -> JSON IR (.jir)
  compiler/api.py           compile facade + semantic validation
  authorization/model.py    @authorization parsing + validation
  runtime/capabilities.py   capability policy (least privilege)
  runtime/interpreter.py    JVMO — executes the IR
  runtime/errors.py         error codes
  modules/                  sys / mem / net / reg / log / disk collectors
  evidence/store.py         .jrf evidence + .jal action log + integrity
  case_manager/store.py     SQLite case storage
  reports/generate.py       JSON + HTML investigation reports
  ui/                       PySide6 Forensic Workbench
tests/test_jocky.py         41 automated tests (unittest)

Run tests:   python -m unittest tests.test_jocky -v
Rebuild exe: pyinstaller --noconfirm --clean build/JOCKY.spec

--------------------------------------------------------------------------------
  TROUBLESHOOTING
--------------------------------------------------------------------------------
- "Security channel" collection requires Administrator (E060 otherwise) —
  relaunch JOCKY elevated, or use the System channel (see demo.jky).
- SmartScreen may warn on first run of an unsigned exe: More info -> Run anyway.
- Evidence defaults to %USERPROFILE%\JOCKYEvidence; change it in the UI.
- JOCKY.exe --selftest writes %TEMP%\JOCKY_selftest.log (exit 0 = healthy).

© 2026 JOCKY Project · prototype for SIH 2026 demonstration · authorized use only
