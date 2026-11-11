#!/usr/bin/env python3
"""
simforge_triage.py — Parse .ips crash reports and apply a diagnostic decision tree.

Solves two problems:
  1. .ips crash reports are TRUNCATED by Consola.app and the file may be truncated
     at an unhelpful point. This script reads the second JSON line directly and
     prints all `termination.reasons` UNTRUNCATED.
  2. Without a decision tree, even a clear crash report can be misdiagnosed.
     This script classifies the crash by `termination.namespace`+`indicator`
     and recommends a specific next step.

Usage:
    python3 simforge_triage.py <path-to-ips>
    python3 simforge_triage.py <path-to-ips> --json
    python3 simforge_triage.py --latest     # most recent .ips in DiagnosticReports

Exit codes:
    0 — Triage complete (regardless of outcome; the report is the result)
    1 — File not found or unreadable

See:
    references/simforge-crash-triage.md (full methodology + decision tree)
    references/simforge-compatibility.md (workarounds for each class of issue)
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ANSI colors
def _color(code: str) -> str:
    if not sys.stdout.isatty():
        return ""
    return {
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }.get(code, "")


def RED(s: str) -> str:
    return f"{_color('red')}{s}{_color('reset')}"


def GREEN(s: str) -> str:
    return f"{_color('green')}{s}{_color('reset')}"


def YELLOW(s: str) -> str:
    return f"{_color('yellow')}{s}{_color('reset')}"


def BLUE(s: str) -> str:
    return f"{_color('blue')}{s}{_color('reset')}"


def BOLD(s: str) -> str:
    return f"{_color('bold')}{s}{_color('reset')}"


# Decision tree based on termination.namespace + indicator
# Maps to a (severity, diagnosis, recommended_action) tuple
DECISION_TREE = {
    ("DYLD", "Library missing"): {
        "severity": "investigate",
        "diagnosis": "A dylib or framework could not be loaded at runtime.",
        "action": (
            "1. Look at reasons[2] — it tells you WHICH library failed and WHERE dyld looked.\n"
            "2. If the path is correct but the lib is rejected, it's likely a signature or ABI issue.\n"
            "3. If you see 'incompatible platforms' (often a Swift ABI mismatch), see\n"
            "   references/simforge-compatibility.md §2.\n"
            "4. If you see 'code signature invalid', see\n"
            "   references/simforge-ios-testing.md §Troubleshooting → 'code signature invalid'."
        ),
    },
    ("DYLD", "Symbol missing"): {
        "severity": "investigate",
        "diagnosis": "A function/symbol expected by a library was not found.",
        "action": "Verify the dependent library was rebuilt with the same SDK and isn't stale.",
    },
    ("DYLD", "malformed LC_xxx"): {
        "severity": "investigate",
        "diagnosis": "Mach-O load command corruption — usually from over-eager patching.",
        "action": (
            "Re-extract the IPA from the original. Use ONE patching tool at a time\n"
            "(simforge OR vtool, not both on the same binary without re-signing between)."
        ),
    },
    ("POSIX", None): {
        "severity": "investigate",
        "diagnosis": "launchd could not spawn the process. Most common: E2BIG (153).",
        "action": (
            "E2BIG usually means Mach-O structural corruption. Re-extract IPA and\n"
            "re-apply patches with only ONE tool at a time, re-signing between steps."
        ),
    },
    ("SPRINGBOARD", "request denied"): {
        "severity": "investigate",
        "diagnosis": "SpringBoard rejected the launch — no crash report was generated.",
        "action": (
            "1. Run: xcrun simctl spawn booted log show --predicate 'process == \"SpringBoard\"' \\\n"
            "     --eventMessage CONTAINS '<bundleid>' --last 1m --style compact\n"
            "2. Look for: 'LSInstallType: StoreDownload' → FairPlay-encrypted, can't run in sim\n"
            "3. Look for: 'had no entitlements' → usually OK, just informational\n"
            "4. Look for: 'app not found' → try reinstalling"
        ),
    },
    ("EXIT", None): {
        "severity": "investigate",
        "diagnosis": "App called exit() with non-zero code.",
        "action": "Search the decompiled code for exit() calls or NSException raises; check NSLog output.",
    },
    ("LIBXPC", "service not available"): {
        "severity": "ignore",
        "diagnosis": "An XPC service the app called is not running in the simulator.",
        "action": "Usually not actionable; XPC services in sim are limited. Try a different sim or device.",
    },
}


def parse_ips(path: Path) -> dict:
    """Parse an .ips file and return the structured data."""
    with open(str(path)) as f:
        # First line is metadata
        f.readline()
        # Second line is the JSON payload
        return json.load(f)


def extract_first_framework_failure(reasons: list[str]) -> dict | None:
    """Find the first framework/dylib failure mentioned in reasons[2]."""
    if len(reasons) < 3:
        return None
    reason_text = reasons[2]
    # Pattern: ".../Frameworks/Suspect.framework/Suspect (macho file (...))"
    m = re.search(r"@rpath/([\w.]+)\.framework/(\w+)", reason_text)
    if m:
        return {"type": "framework", "name": m.group(1), "binary": m.group(2)}
    m = re.search(r"@rpath/(\w+\.dylib)", reason_text)
    if m:
        return {"type": "dylib", "name": m.group(1)}
    return None


def detect_incompatibility_kind(reasons: list[str]) -> str | None:
    """Detect 'incompatible platforms' (often Swift ABI mismatch) or 'code signature invalid'."""
    if not reasons:
        return None
    full_text = " ".join(reasons).lower()
    if "incompatible platforms" in full_text:
        return "swift_abi_or_platform"
    if "code signature invalid" in full_text:
        return "code_signature"
    if "no such file" in full_text and len(reasons) >= 3:
        # Check if the last attempted path exists
        return "library_missing_truly"
    return None


def print_human_readable(data: dict) -> None:
    """Print the crash report in a human-readable, untruncated way."""
    print(BLUE("=" * 70))
    print(BLUE("CRASH REPORT — UNTRUNCATED VIEW"))
    print(BLUE("=" * 70))

    proc = data.get("procName", "(unknown)")
    bundle_id = data.get("bundleID", "(unknown)")
    pid = data.get("pid", "(unknown)")
    signal = data.get("exception", {}).get("signal", "(unknown)")
    exc_type = data.get("exception", {}).get("type", "(unknown)")
    print(f"\n{BOLD('Process:')} {proc} (bundle: {bundle_id}, PID: {pid})")
    print(f"{BOLD('Exception:')} {exc_type} ({signal})")

    t = data.get("termination", {})
    namespace = t.get("namespace", "(unknown)")
    indicator = t.get("indicator", "(none)")
    code = t.get("code", "(none)")
    print(f"\n{BOLD('Termination:')}")
    print(f"  namespace: {YELLOW(namespace)}")
    print(f"  indicator: {YELLOW(indicator)}")
    print(f"  code:      {code}")

    print(f"\n{BOLD('Reasons (UNTRUNCATED):')}")
    reasons = t.get("reasons", [])
    for i, r in enumerate(reasons):
        print(f"\n  --- reason[{i}] ---")
        print(f"  {r}")

    # Decision tree recommendation
    print(f"\n{BLUE('=' * 70)}")
    print(BLUE("DIAGNOSTIC RECOMMENDATION"))
    print(BLUE("=" * 70))

    key = (namespace, indicator)
    if key in DECISION_TREE:
        rec = DECISION_TREE[key]
    elif (namespace, None) in DECISION_TREE:
        rec = DECISION_TREE[(namespace, None)]
    else:
        rec = {
            "severity": "investigate",
            "diagnosis": f"Unknown crash class: namespace={namespace}, indicator={indicator}",
            "action": "Search references/simforge-crash-triage.md for this pattern or escalate.",
        }

    severity_color = {"ignore": GREEN, "investigate": YELLOW, "critical": RED}.get(
        rec["severity"], YELLOW
    )
    print(f"\n  {severity_color('●')} {BOLD('Severity:')} {rec['severity'].upper()}")
    print(f"  {BOLD('Diagnosis:')} {rec['diagnosis']}")
    print(f"  {BOLD('Action:')}")
    for line in rec["action"].splitlines():
        print(f"    {line}")

    # Specific detectors
    failure = extract_first_framework_failure(reasons)
    if failure:
        print(f"\n  {BOLD('First failing binary:')} {failure}")

    incompatibility = detect_incompatibility_kind(reasons)
    if incompatibility == "swift_abi_or_platform":
        print(
            f"\n  {RED('⚠')} The 'incompatible platforms' error is OFTEN a Swift ABI mismatch."
        )
        print(
            "     See references/simforge-compatibility.md §2 (Swift ABI Version Mismatch)."
        )
    elif incompatibility == "code_signature":
        print(
            f"\n  {RED('⚠')} A code signature is invalid — likely leftover from patching."
        )
        print(
            "     Re-run the 4-sub-step re-signing in scripts/simforge_apply.py (Step 5)."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse .ips crash reports and apply a diagnostic decision tree."
    )
    parser.add_argument("ips_path", nargs="?", help="Path to .ips crash report")
    parser.add_argument("--latest", action="store_true", help="Use most recent .ips in DiagnosticReports")
    parser.add_argument("--path-only", action="store_true",
                        help="Print only the resolved path (for use from shell scripts)")
    parser.add_argument("--json", action="store_true", help="Output structured JSON instead of human-readable")
    args = parser.parse_args()

    if args.latest:
        reports_dir = Path.home() / "Library/Logs/DiagnosticReports"
        ips_files = sorted(reports_dir.glob("*.ips"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not ips_files:
            print(f"ERROR: No .ips files found in {reports_dir}", file=sys.stderr)
            return 1
        path = ips_files[0]
        if args.path_only:
            print(path)
            return 0
        print(f"Using most recent: {path}\n", file=sys.stderr)
    elif args.ips_path:
        path = Path(args.ips_path)
        if not path.exists():
            print(f"ERROR: {path} does not exist", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1

    try:
        data = parse_ips(path)
    except Exception as e:
        print(f"ERROR: Could not parse {path}: {e}", file=sys.stderr)
        return 1

    if args.json:
        # Output structured triage result
        t = data.get("termination", {})
        result = {
            "process": data.get("procName"),
            "bundle_id": data.get("bundleID"),
            "pid": data.get("pid"),
            "exception": data.get("exception"),
            "termination": t,
            "triage": DECISION_TREE.get(
                (t.get("namespace"), t.get("indicator")),
                DECISION_TREE.get((t.get("namespace"), None), {"severity": "investigate", "diagnosis": "Unknown", "action": "Escalate"}),
            ),
        }
        print(json.dumps(result, indent=2))
    else:
        print_human_readable(data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
