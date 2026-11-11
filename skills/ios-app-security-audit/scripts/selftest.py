#!/usr/bin/env python3
"""
Functional self-test for the iOS-Pentesting-Skill scripts.

Static analysis cannot catch the failure mode that matters most here: a
script that exits 0 while it did not do its job. A report that says "risk
LOW" next to a critical finding, or a cleanup that leaves the binary in the
legacy state and still reports success, both look perfect to a linter and to
a reviewer reading the code.

Every check below therefore asserts on the *behaviour* of a script: the exit
code and the content of its output, driven with real inputs.

The suite is self-contained: no network, no device, no simulator, and no
artefacts outside the repository. Checks that need a tool which is not
present (lief, the macOS toolchain) are reported as SKIPPED, not as failed.

Usage
-----
    python3 scripts/selftest.py            # human readable
    python3 scripts/selftest.py --json     # machine readable
    python3 scripts/selftest.py --strict   # skip nothing: SKIP is a failure

Exit codes
----------
    0  every check passed (skipped checks are allowed unless --strict)
    1  at least one check failed
    2  bad usage
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
PYTHON = sys.executable

LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False


@dataclass
class Suite:
    checks: list[Check] = field(default_factory=list)

    def passed(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name, ok, detail))

    def skipped(self, name: str, why: str) -> None:
        self.checks.append(Check(name, True, why, skipped=True))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def run(args: list[str], env: dict[str, str] | None = None, timeout: int = 180):
    """Run a command and return (returncode, stdout, stderr)."""
    environment = dict(os.environ)
    if env:
        environment.update(env)
    try:
        proc = subprocess.run(
            [PYTHON] + args,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def have_lief() -> bool:
    try:
        import lief  # noqa: F401
    except ImportError:
        return False
    return True


# --------------------------------------------------------------------------- #
# 1. The report must not downgrade a critical finding
# --------------------------------------------------------------------------- #

def test_generate_report(suite: Suite, tmp: Path) -> None:
    findings = SCRIPTS_DIR / "test-findings.json"
    if not findings.exists():
        suite.skipped("generate-report: fixture", "scripts/test-findings.json is missing")
        return

    out = tmp / "report.md"
    code, stdout, stderr = run([
        "scripts/generate-report.py",
        "--input", str(findings),
        "--output", str(out),
        "--app-name", "SelfTest",
        "--bundle-id", "com.selftest.app",
    ])
    suite.passed("generate-report: exits 0", code == 0, f"code={code} {stderr[:200]}")
    if not out.exists():
        suite.passed("generate-report: writes the report", False, "no output file")
        return

    text = out.read_text(encoding="utf-8")
    suite.passed("generate-report: includes the findings", "Critical" in text)
    # The regression this guards: the scanner emits CRITICAL while the report
    # looked up Critical, so the summary came out empty and the overall risk
    # rating came out LOW with a critical RCE on the table.
    suite.passed(
        "generate-report: never rates LOW with a critical finding",
        "Risk Rating: LOW" not in text,
        "the report says LOW despite a Critical finding",
    )
    suite.passed(
        "generate-report: summary table is not empty",
        "|" in text and "Critical" in text,
    )


# --------------------------------------------------------------------------- #
# 2. A source that fails must never be reported as "clean"
# --------------------------------------------------------------------------- #

def test_dependency_scanner(suite: Suite, tmp: Path) -> None:
    sbom = tmp / "sbom.json"
    sbom.write_text(json.dumps({
        "dependencies": [
            {"name": "AFNetworking", "version": "4.0.1", "manager": "cocoapods", "type": "library"}
        ]
    }), encoding="utf-8")
    report = tmp / "deps.json"

    # Point every source at a closed port: that is what a network failure
    # looks like from the scanner's point of view.
    wrapper = tmp / "netscan.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(SCRIPTS_DIR)!r})\n"
        "import dependency_scanner as ds\n"
        "_orig = ds.DependencyScanner.__init__\n"
        "def _patched(self, *a, **k):\n"
        "    _orig(self, *a, **k)\n"
        "    self.nvd_api = 'http://127.0.0.1:9/nvd'\n"
        "    self.github_advisory_api = 'http://127.0.0.1:9/gh'\n"
        "    self.osv_api = 'http://127.0.0.1:9/osv'\n"
        "ds.DependencyScanner.__init__ = _patched\n"
        f"sys.argv = ['dependency_scanner.py', '--sbom', {str(sbom)!r}, '--output', {str(report)!r}]\n"
        "sys.exit(ds.main())\n",
        encoding="utf-8",
    )
    code, stdout, stderr = run([str(wrapper)], timeout=120)
    suite.passed(
        "dependency-scanner: a failed source exits 2",
        code == 2,
        f"code={code} (2 = incomplete scan) {stdout[-200:]}",
    )
    if not report.exists():
        suite.passed("dependency-scanner: writes the report", False, "no output file")
        return

    data = json.loads(report.read_text(encoding="utf-8"))
    suite.passed("dependency-scanner: marks the scan incomplete", not data.get("scanReliable", True))
    suite.passed("dependency-scanner: records the source errors", bool(data.get("sourceErrors")))
    suite.passed(
        "dependency-scanner: does not claim a clean result",
        "no critical security issues" not in report.read_text(encoding="utf-8").lower(),
    )
    suite.passed(
        "dependency-scanner: never rates the risk LOW",
        str(data.get("overallRisk", "")).upper() != "LOW",
        f"overallRisk={data.get('overallRisk')}",
    )


# --------------------------------------------------------------------------- #
# 3. Cleanup must report failures through its exit code
# --------------------------------------------------------------------------- #

def _build_synthetic_macho(path: Path) -> None:
    """Write a minimal Mach-O carrying both legacy and modern load commands."""
    version_min = struct.pack("<IIIIII", LC_VERSION_MIN_IPHONEOS, 24,
                               0x00010000, 0x00010000, 0x000C0000, 0)
    build_version = struct.pack("<IIIIII", LC_BUILD_VERSION, 24,
                                 2, 0x000C0000, 0x00010000, 0)
    commands = version_min + build_version
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(commands), 0, 0)
    path.write_bytes(header + commands)


def test_simforge_cleanup(suite: Suite, tmp: Path) -> None:
    if not have_lief():
        suite.skipped("simforge-cleanup: rewrite path", "the 'lief' package is not installed")
        return

    import lief

    # --- happy path: the legacy command is removed and the original is kept ---
    target = tmp / "both"
    _build_synthetic_macho(target)
    original = target.read_bytes()

    code, stdout, stderr = run(["scripts/simforge_cleanup.py", str(target)], timeout=120)
    suite.passed("simforge-cleanup: exits 0 on success", code == 0, f"code={code} {stderr[:200]}")
    backup = tmp / "both.pre-lief.bak"
    suite.passed("simforge-cleanup: backs the binary up before rewriting", backup.exists())
    if backup.exists():
        suite.passed("simforge-cleanup: the backup is a faithful copy",
                     backup.read_bytes() == original)
        kept = lief.parse(str(backup))
        kinds = [str(c.command).split(".")[-1] for c in kept.commands] if kept else []
        suite.passed("simforge-cleanup: the backup keeps the legacy command",
                     "VERSION_MIN_IPHONEOS" in kinds, str(kinds))
    suite.passed("simforge-cleanup: leaves no temporary file",
                 not (tmp / "both.lief.tmp").exists())
    rewritten = lief.parse(str(target))
    kinds = [str(c.command).split(".")[-1] for c in rewritten.commands] if rewritten else []
    suite.passed("simforge-cleanup: removes the legacy command",
                 "VERSION_MIN_IPHONEOS" not in kinds, str(kinds))
    suite.passed("simforge-cleanup: keeps the modern command",
                 "BUILD_VERSION" in kinds, str(kinds))

    # --- failure path: a binary that cannot be written must fail the run ---
    # The regression this guards: cleanup_binary() returned False on failure
    # but main() counted it as "Already OK" and exited 0, so the caller
    # believed the binary had been cleaned.
    failing = tmp / "failing"
    failing.write_bytes(original)
    probe = tmp / "failing_probe.py"
    probe.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(SCRIPTS_DIR)!r})\n"
        "import simforge_cleanup as sc\n"
        "class _Cmd:\n"
        "    def __init__(self, t): self.command = t\n"
        "class _Binary:\n"
        "    def __init__(self):\n"
        "        self.commands = [\n"
        "            _Cmd(sc.lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS),\n"
        "            _Cmd(sc.lief.MachO.LoadCommand.TYPE.BUILD_VERSION),\n"
        "        ]\n"
        "    def remove_command(self, i): pass\n"
        "    def write(self, path): raise OSError('write refused')\n"
        "sc.lief.parse = lambda p: _Binary()\n"
        f"sys.argv = ['simforge_cleanup.py', {str(failing)!r}]\n"
        "sys.exit(sc.main())\n",
        encoding="utf-8",
    )
    code, stdout, stderr = run([str(probe)], timeout=120)
    suite.passed(
        "simforge-cleanup: a failed rewrite exits non-zero",
        code != 0,
        f"code={code}: the failure is not propagated to the exit code",
    )
    suite.passed(
        "simforge-cleanup: does not count a failure as 'Already OK'",
        "Already OK: 1" not in stdout,
        stdout[-300:],
    )


# --------------------------------------------------------------------------- #
# 4. URL normalisation happens at the source
# --------------------------------------------------------------------------- #

def test_mobsf_config(suite: Suite, tmp: Path) -> None:
    home = tmp / "home"
    home.mkdir()
    # The real configuration lives in ~/.ios-pentest-skill: HOME is redirected
    # so the test never touches the developer's own settings.
    env = {"HOME": str(home)}

    code, stdout, stderr = run(
        ["scripts/mobsf_config.py", "set-url", "http://http://127.0.0.1:8000"],
        env=env, timeout=60,
    )
    suite.passed("mobsf-config: set-url exits 0", code == 0, f"code={code} {stderr[:200]}")
    stored = ""
    for path in home.rglob("*"):
        if path.is_file():
            stored += path.read_text(encoding="utf-8", errors="ignore")
    suite.passed("mobsf-config: no duplicated scheme", "http://http://" not in stored, stored[:200])
    suite.passed("mobsf-config: keeps a usable URL", "127.0.0.1:8000" in stored, stored[:200])

    run(["scripts/mobsf_config.py", "set-url", "https://127.0.0.1:8000"], env=env, timeout=60)
    stored = ""
    for path in home.rglob("*"):
        if path.is_file():
            stored += path.read_text(encoding="utf-8", errors="ignore")
    suite.passed(
        "mobsf-config: an existing https is not downgraded",
        "https://127.0.0.1:8000" in stored,
        stored[:200],
    )


# --------------------------------------------------------------------------- #
# 5. The documented module invocation must work
# --------------------------------------------------------------------------- #

MODULES = (
    "mobsf_upload", "mobsf_config", "mobsf_detect", "mobsf_client",
    "dependency_scanner", "sbom_generator", "generate_report",
    "preflight_check", "simforge_apply", "simforge_preflight",
)


def test_module_invocation(suite: Suite) -> None:
    for module in MODULES:
        code, stdout, stderr = run(["-m", f"scripts.{module}", "--help"], timeout=60)
        if "the 'requests' package is required" in stderr:
            # A missing dependency is an environment problem, not a code
            # problem: the script says so instead of raising a traceback.
            suite.skipped(
                f"module invocation: python3 -m scripts.{module} --help",
                "the 'requests' package is not installed",
            )
            continue
        suite.passed(
            f"module invocation: python3 -m scripts.{module} --help",
            "ModuleNotFoundError" not in stderr and "Traceback" not in stderr,
            stderr[-200:],
        )


# --------------------------------------------------------------------------- #
# 6. Tooling must not fail in silence
# --------------------------------------------------------------------------- #

def test_preflight(suite: Suite) -> None:
    code, stdout, stderr = run(["scripts/preflight_check.py", "--json"], timeout=120)
    try:
        data = json.loads(stdout)
    except Exception as exc:
        suite.passed("preflight: emits valid JSON", False, str(exc))
        return
    suite.passed("preflight: emits valid JSON", True)
    suite.passed("preflight: reports a summary", "summary" in data)

    summary = data.get("summary", {})
    # The machine determines which tools are present, so the invariant is not
    # "nothing is missing" but "the report adds up and the exit code agrees
    # with it". A preflight that finds a missing critical tool must fail.
    suite.passed(
        "preflight: the tool accounting adds up",
        summary.get("total") == summary.get("found", 0) + summary.get("missing", 0),
        str(summary),
    )
    missing_critical = summary.get("missing_critical") or []
    expected = 0 if not missing_critical else 1
    suite.passed(
        "preflight: the exit code agrees with the report",
        code == expected,
        f"code={code}, missing_critical={missing_critical}",
    )
    # A critical tool that belongs to another platform (plutil and otool are
    # macOS-only) does not apply here: the JSON report and the exit code have
    # to reach the same verdict, or the report contradicts itself.
    suite.passed(
        "preflight: the report and the verdict cannot disagree",
        (code == 0) == (not missing_critical),
        f"code={code}, missing_critical={missing_critical}",
    )


def test_preflight_on_linux(suite: Suite) -> None:
    """The preflight must reach the same verdict on Linux as on macOS.

    `plutil` and `otool` are critical AND macOS-only. On Linux they do not
    apply, so they must not be reported as missing critical tools: the JSON
    report and the exit code have to agree, otherwise the report contradicts
    itself and a Linux host looks broken when it is not.
    """
    probe = Path(tempfile.mkdtemp(prefix="selftest-linux-"))
    try:
        script = probe / "linux_probe.py"
        script.write_text(
            "import io, json, contextlib, sys\n"
            f"sys.path.insert(0, {str(SCRIPTS_DIR)!r})\n"
            "import preflight_check as pf\n"
            "pf.SystemInfo._detect_os = lambda self: 'linux'\n"
            "pf.SystemInfo._detect_distro = lambda self: 'debian'\n"
            "buf = io.StringIO()\n"
            "sys.argv = ['preflight_check.py', '--json']\n"
            "with contextlib.redirect_stdout(buf):\n"
            "    code = pf.main()\n"
            "data = json.loads(buf.getvalue())\n"
            "print(json.dumps({'code': code, 'summary': data['summary']}))\n",
            encoding="utf-8",
        )
        code, stdout, stderr = run([str(script)], timeout=120)
        if code != 0:
            suite.passed("preflight on Linux: the checker runs", False, stderr[-300:])
            return
        payload = json.loads(stdout.strip().splitlines()[-1])
        summary = payload["summary"]
        suite.passed(
            "preflight on Linux: macOS-only critical tools are not reported missing",
            "plutil" not in (summary.get("missing_critical") or [])
            and "otool" not in (summary.get("missing_critical") or []),
            str(summary.get("missing_critical")),
        )
        suite.passed(
            "preflight on Linux: the report and the verdict agree",
            (payload["code"] == 0) == (not summary.get("missing_critical")),
            f"code={payload['code']}, missing_critical={summary.get('missing_critical')}",
        )
        suite.passed(
            "preflight on Linux: the accounting adds up",
            summary.get("total") == summary.get("found", 0) + summary.get("missing", 0),
            str(summary),
        )
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def test_frida_scripts_load(suite: Suite) -> None:
    """Every bundled Frida script must load under a simulated Frida API.

    `node --check` only parses the file. A script can parse perfectly and
    still abort on load: `process.on(...)` (a Node global that Frida does not
    have), `Java.perform = ...` (no Java VM on iOS), a call to an API that
    was removed. The script then never runs and the pentester believes the
    hook is active.
    """
    harness = SCRIPTS_DIR / "frida_harness.js"
    if not harness.exists():
        suite.skipped("frida scripts: load under a simulated API", "scripts/frida_harness.js is missing")
        return
    if shutil.which("node") is None:
        suite.skipped("frida scripts: load under a simulated API", "node is not installed")
        return

    try:
        proc = subprocess.run(
            ["node", str(harness), str(REPO_ROOT / "assets" / "frida-scripts")],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        )
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        code, output = -1, "timeout"

    suite.passed(
        "frida scripts: every script loads under a simulated Frida API",
        code == 0,
        output[-600:],
    )


def test_consistency_checker(suite: Suite) -> None:
    code, stdout, stderr = run(["scripts/check_docs_consistency.py", "--strict"], timeout=300)
    suite.passed("consistency checker: exits 0 in --strict", code == 0, stdout[-400:])


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def report(suite: Suite, as_json: bool) -> int:
    if as_json:
        print(json.dumps({
            "passed": sum(1 for c in suite.checks if c.ok and not c.skipped),
            "skipped": sum(1 for c in suite.checks if c.skipped),
            "failed": len(suite.failures),
            "checks": [
                {"name": c.name, "ok": c.ok, "skipped": c.skipped, "detail": c.detail}
                for c in suite.checks
            ],
        }, indent=2, ensure_ascii=False))
        return 1 if suite.failures else 0

    print("iOS-Pentesting-Skill - functional self-test")
    print("=" * 68)
    for check in suite.checks:
        if check.skipped:
            print(f"  SKIP  {check.name}  ({check.detail})")
        elif check.ok:
            print(f"  PASS  {check.name}")
        else:
            print(f"  FAIL  {check.name}")
            if check.detail:
                print(f"        {check.detail}")
    passed = sum(1 for c in suite.checks if c.ok and not c.skipped)
    skipped = sum(1 for c in suite.checks if c.skipped)
    print("=" * 68)
    print(f"{passed} passed, {len(suite.failures)} failed, {skipped} skipped")
    return 1 if suite.failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--strict", action="store_true", help="treat skipped checks as failures")
    args = parser.parse_args()

    suite = Suite()
    tmp = Path(tempfile.mkdtemp(prefix="selftest-"))
    try:
        test_generate_report(suite, tmp)
        test_dependency_scanner(suite, tmp)
        test_simforge_cleanup(suite, tmp)
        test_mobsf_config(suite, tmp)
        test_module_invocation(suite)
        test_preflight(suite)
        test_preflight_on_linux(suite)
        test_frida_scripts_load(suite)
        test_consistency_checker(suite)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if args.strict:
        for check in suite.checks:
            if check.skipped:
                check.ok = False
                check.detail = f"skipped: {check.detail}"

    return report(suite, args.json)


if __name__ == "__main__":
    sys.exit(main())
