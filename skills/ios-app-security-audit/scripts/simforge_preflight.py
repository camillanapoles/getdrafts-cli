#!/usr/bin/env python3
"""
simforge_preflight.py — Pre-flight check for iOS app → iOS simulator emulation.

Validates 5 compatibility and integrity issues BEFORE any patching, so you
don't waste 30+ minutes on an app that cannot run in the simulator anyway.

Usage:
    python3 simforge_preflight.py <path-to-extracted-app>
    python3 simforge_preflight.py <path-to-extracted-app> --json

Exit codes:
    0 — All checks passed (or warnings only). Safe to apply patches.
    1 — Critical failure. Do NOT patch; address the issue first.
    2 — Warnings only. Patches may work but with reduced compatibility.

See:
    references/simforge-emulation-flow.md (Step: Pre-flight check)
    references/simforge-compatibility.md (what each check means)
"""

import argparse
import json
import plistlib
import re
import subprocess
import sys
from pathlib import Path

import _scripts_path  # noqa: F401  -- adds scripts/ to sys.path
from simforge_binaries import iter_bundle_binaries


# ANSI colors (no-op if not a tty)
def _color(code: str) -> str:
    if not sys.stdout.isatty():
        return ""
    return {
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
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


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def get_main_binary(app_path: Path) -> str | None:
    """Get CFBundleExecutable from the .app's Info.plist."""
    plist = app_path / "Info.plist"
    if not plist.exists():
        return None
    with open(str(plist), "rb") as f:
        info = plistlib.load(f)
    return info.get("CFBundleExecutable")


def get_bundle_id(app_path: Path) -> str | None:
    """Get CFBundleIdentifier from Info.plist."""
    plist = app_path / "Info.plist"
    if not plist.exists():
        return None
    with open(str(plist), "rb") as f:
        info = plistlib.load(f)
    return info.get("CFBundleIdentifier")


def check_arm64(binary: Path) -> dict:
    """Check 1: Is the binary arm64 (non-fat)?"""
    if not binary.exists():
        return {"id": "arm64", "status": "FAIL", "message": f"Binary not found: {binary}"}
    result = run(["file", str(binary)], check=False)
    output = result.stdout.lower()
    if "arm64" in output and "universal" not in output and "x86_64" not in output:
        return {"id": "arm64", "status": "OK", "message": "arm64 non-fat binary"}
    if "x86_64" in output and "arm64" not in output:
        return {
            "id": "arm64",
            "status": "FAIL",
            "message": "Binary is x86_64 (Intel) — simulator requires arm64. Run `lipo -thin arm64` first.",
        }
    if "universal" in output or "x86_64" in output and "arm64" in output:
        return {
            "id": "arm64",
            "status": "WARN",
            "message": "Fat binary (multi-arch). Run `lipo -thin arm64` before patching.",
        }
    return {"id": "arm64", "status": "FAIL", "message": f"Unknown architecture: {output.strip()}"}


def check_fairplay(binary: Path) -> dict:
    """Check 2: Is the binary FairPlay-encrypted (cryptid=1)?"""
    if not binary.exists():
        return {"id": "fairplay", "status": "FAIL", "message": f"Binary not found: {binary}"}
    result = run(["otool", "-l", str(binary)], check=False)
    if "cryptid" not in result.stdout:
        return {"id": "fairplay", "status": "OK", "message": "No encryption (no LC_ENCRYPTION_INFO)"}
    # Find the cryptid line
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("cryptid"):
            cryptid = line.split()[1]
            if cryptid == "1":
                return {
                    "id": "fairplay",
                    "status": "FAIL",
                    "message": (
                        "FairPlay-encrypted (cryptid=1). The simulator cannot run this. "
                        "Dump decrypted binary with frida-ios-dump on a jailbroken device first."
                    ),
                }
            return {"id": "fairplay", "status": "OK", "message": "Decrypted (cryptid=0)"}
    return {"id": "fairplay", "status": "OK", "message": "No cryptid found"}


def check_platforms(app_path: Path) -> dict:
    """Check 3: Does the Info.plist need CFBundleSupportedPlatforms patch?"""
    plist = app_path / "Info.plist"
    if not plist.exists():
        return {"id": "platforms", "status": "FAIL", "message": "Info.plist not found"}
    with open(str(plist), "rb") as f:
        info = plistlib.load(f)
    platforms = info.get("CFBundleSupportedPlatforms", [])
    if not platforms:
        return {
            "id": "platforms",
            "status": "WARN",
            "message": "CFBundleSupportedPlatforms missing — may need to be set to ['iPhoneSimulator']",
        }
    if "iPhoneSimulator" in platforms:
        return {"id": "platforms", "status": "OK", "message": "Already declares iPhoneSimulator"}
    if "iPhoneOS" in platforms:
        return {
            "id": "platforms",
            "status": "WARN",
            "message": "Declares iPhoneOS only — needs patch to ['iPhoneSimulator'] (handled in Step 4)",
        }
    return {"id": "platforms", "status": "WARN", "message": f"Declares {platforms}"}


def check_legacy_load_commands(app_path: Path, main_bin: str) -> dict:
    """Check 4: Are there legacy LC_VERSION_MIN_IPHONEOS binaries?"""
    legacy = []
    # Single source of truth for the binary inventory, shared with
    # simforge_apply.py. The pre-flight must inspect exactly the binaries the
    # patch flow is going to modify, otherwise it can report "all modern" for
    # a bundle whose .dylib or .appex is still legacy.
    for binary in iter_bundle_binaries(app_path):
        result = run(["otool", "-l", str(binary)], check=False)
        if "LC_VERSION_MIN_IPHONEOS" in result.stdout:
            legacy.append(str(binary.relative_to(app_path)))
    if not legacy:
        return {
            "id": "legacy_lc",
            "status": "OK",
            "message": "All binaries use modern LC_BUILD_VERSION",
        }
    return {
        "id": "legacy_lc",
        "status": "WARN",
        "message": f"{len(legacy)} legacy binary(ies) need vtool: {', '.join(legacy[:3])}{'...' if len(legacy) > 3 else ''}",
        "details": legacy,
    }


def check_swift_abi(binary: Path) -> dict:
    """Check 5: Is Swift ABI compatible with any available SimRuntime?

    Walks the bundle's binaries to find the required libswiftCore version.
    Checks three things in order:
      1. Does the host toolchain (Xcode's iphonesimulator lib) provide it? → OK
      2. Does any installed SimRuntime's lib provide it? → OK (with note)
      3. Neither? → FAIL with the specific runtime to install

    This is a generalized check — works for any iOS app, not test-case-specific.
    """
    if not binary.exists():
        return {"id": "swift_abi", "status": "FAIL", "message": f"Binary not found: {binary}"}

    # Walk all binaries in the bundle to find libswiftCore version requirements
    candidates = [binary]
    fw_dir = binary.parent / "Frameworks"
    if fw_dir.exists():
        for fw in fw_dir.glob("*.framework"):
            inner = fw / fw.stem
            if inner.exists() and inner != binary:
                candidates.append(inner)

    app_versions: set[str] = set()
    for b in candidates:
        result = run(["otool", "-L", str(b)], check=False)
        for line in result.stdout.splitlines():
            if "libswiftCore.dylib" in line and "current version" in line:
                m = re.search(r"current version\s+([0-9]+\.[0-9]+\.[0-9]+)", line)
                if m:
                    app_versions.add(m.group(1))

    if not app_versions:
        return {
            "id": "swift_abi",
            "status": "OK",
            "message": "Pure ObjC (no libswiftCore dependency)",
        }

    # Filter out 0.0.0 (shared cache stubs)
    real_app_versions = {v for v in app_versions if v != "0.0.0"}
    if not real_app_versions:
        return {
            "id": "swift_abi",
            "status": "WARN",
            "message": "libswiftCore versions in binary are all 0.0.0 (shared cache stubs). Cannot determine Swift ABI compatibility. Proceed with caution.",
        }

    app_swift_ver = sorted(real_app_versions, key=lambda v: tuple(int(p) for p in v.split(".")))[0]

    # Check 1: host toolchain
    host_lib = Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/iphonesimulator/libswiftCore.dylib"
    )
    host_swift_ver = _get_libswiftcore_version(host_lib)

    if app_swift_ver == host_swift_ver:
        return {
            "id": "swift_abi",
            "status": "OK",
            "message": f"Swift ABI matches host toolchain ({app_swift_ver})",
        }

    # Check 2: any installed SimRuntime
    installed_ios_majors = _get_installed_ios_majors()
    matching_runtime = _simruntime_providing_swift(app_swift_ver, installed_ios_majors)
    if matching_runtime:
        # We have a SimRuntime whose Swift ABI matches. Note that the user
        # must explicitly boot that runtime (the host toolchain still mismatches).
        return {
            "id": "swift_abi",
            "status": "OK",
            "message": (
                f"Swift ABI matches iOS {matching_runtime} SimRuntime (libswiftCore {app_swift_ver}). "
                f"Boot that runtime explicitly (the host toolchain has {host_swift_ver or 'unknown'} "
                f"and will fail otherwise)."
            ),
            "details": {"app": app_swift_ver, "host": host_swift_ver, "matching_runtime": matching_runtime},
        }

    # Check 3: FAIL — recommend the right runtime
    recommended_runtime = recommend_simruntime_for_swift(app_swift_ver)
    return {
        "id": "swift_abi",
        "status": "FAIL",
        "message": (
            f"Swift ABI mismatch (app={app_swift_ver}, host={host_swift_ver or 'unknown'}). "
            f"RECOMMENDED FIX: install {recommended_runtime} SimRuntime. "
            f"Currently installed: {', '.join(installed_ios_majors) or 'none detected'}. "
            f"See simforge-compatibility.md §6 (Choosing the right SimRuntime)."
        ),
        "details": {
            "app": app_swift_ver,
            "host": host_swift_ver,
            "recommended_runtime": recommended_runtime,
            "installed": installed_ios_majors,
        },
    }


def _get_libswiftcore_version(lib_path: Path) -> str | None:
    """Extract the libswiftCore.dylib 'current version' from a path. Returns None if not found."""
    if not lib_path.exists():
        return None
    result = run(["otool", "-L", str(lib_path)], check=False)
    for line in result.stdout.splitlines():
        if "libswiftCore.dylib" in line and "current version" in line:
            m = re.search(r"current version\s+([0-9]+\.[0-9]+\.[0-9]+)", line)
            if m:
                return m.group(1)
    return None


def _get_installed_ios_majors() -> list[str]:
    """Get the list of iOS major versions of installed SimRuntimes, e.g., ['17', '18', '26']."""
    result = subprocess.run(
        ["xcrun", "simctl", "list", "runtimes"], capture_output=True, text=True, check=False
    )
    majors: set[str] = set()
    for line in result.stdout.splitlines():
        m = re.match(r"iOS\s+(\d+)\.\d+", line)
        if m:
            majors.add(m.group(1))
    return sorted(majors, key=int)


def _simruntime_providing_swift(swift_ver: str, installed_ios_majors: list[str]) -> str | None:
    """Given an app's required Swift version and the list of installed iOS major
    versions (as strings), return the iOS major that has a matching Swift ABI, or None.

    Mapping (generalized):
      Swift 5.0-5.5 → iOS 13-15
      Swift 5.6-5.7 → iOS 16
      Swift 5.9     → iOS 17
      Swift 6.0-6.2 → iOS 18
      Swift 6.3+    → iOS 26
    """
    try:
        parts = swift_ver.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return None

    # Map Swift version → iOS major version
    target_ios_major = None
    if major == 5:
        if minor <= 5:
            target_ios_major = "15"  # iOS 13-15
        elif minor <= 7:
            target_ios_major = "16"
        else:  # 5.8, 5.9
            target_ios_major = "17"
    elif major == 6:
        if minor <= 2:
            target_ios_major = "18"
        else:
            target_ios_major = "26"

    if target_ios_major and target_ios_major in installed_ios_majors:
        return target_ios_major
    return None


def check_simruntime_coverage() -> dict:
    """Check 6: What iOS Simulator runtimes are installed?

    Informational. Tells you if you have a SimRuntime whose Swift ABI matches
    common app targets. Recommended install set:
    iOS 17.x (Swift 5.9), iOS 18.x (Swift 6.0), iOS 26.x (Swift 6.3).
    """
    installed_majors = _get_installed_ios_majors()
    if not installed_majors:
        return {
            "id": "simruntime_coverage",
            "status": "WARN",
            "message": "No iOS Simulator runtimes found. Install one via Xcode → Settings → Components.",
        }

    summary = ", ".join(f"iOS {m}.x" for m in installed_majors)
    has_17 = "17" in installed_majors
    has_18 = "18" in installed_majors
    if has_17 and has_18:
        status = "OK"
        msg = f"Good coverage: {summary}. iOS 17.x covers Swift 5.9 apps (most 2023-2024)."
    elif has_17:
        status = "WARN"
        msg = f"Only iOS 17.x + newer. Missing iOS 18.x means you can't run apps built with Swift 6.0 (Xcode 16+). Have: {summary}."
    else:
        status = "WARN"
        msg = f"No iOS 17.x runtime. iOS 17.x is the sweet spot for Swift 5.9 apps (Xcode 15). Have: {summary}. Consider downloading iOS 17.x via Xcode → Settings → Components."
    return {"id": "simruntime_coverage", "status": status, "message": msg, "details": installed_majors}


def recommend_simruntime_for_swift(swift_ver: str) -> str:
    """Recommend a SimRuntime version for a given Swift version."""
    try:
        parts = swift_ver.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return "the latest"

    if major == 5 and minor <= 5:
        return "iOS 15.x"
    if major == 5 and minor <= 7:
        return "iOS 16.x"
    if major == 5:
        return "iOS 17.x"  # 5.8+
    if major == 6 and minor <= 2:
        return "iOS 18.x"
    if major == 6:
        return "iOS 26.x"  # 6.3+
    return "the latest"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight check for iOS app → iOS simulator emulation."
    )
    parser.add_argument("app_path", help="Path to extracted .app bundle")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    app_path = Path(args.app_path).resolve()
    if not app_path.is_dir() or not app_path.name.endswith(".app"):
        print(RED(f"ERROR: {app_path} is not a .app bundle directory"), file=sys.stderr)
        return 1

    main_bin_name = get_main_binary(app_path)
    if not main_bin_name:
        print(RED(f"ERROR: Could not read CFBundleExecutable from {app_path}/Info.plist"), file=sys.stderr)
        return 1
    main_bin = app_path / main_bin_name
    bundle_id = get_bundle_id(app_path)

    if not args.json:
        print(BLUE(f"\n=== Pre-flight check for {app_path.name} ==="))
        print(f"Bundle ID: {bundle_id or '(unknown)'}")
        print(f"Main binary: {main_bin_name}\n")

    checks = [
        check_arm64(main_bin),
        check_fairplay(main_bin),
        check_platforms(app_path),
        check_legacy_load_commands(app_path, main_bin_name),
        check_swift_abi(main_bin),
        check_simruntime_coverage(),
    ]

    # The exit status must reflect the check results in BOTH output modes:
    # a caller that chains `simforge_preflight.py app.app --json` and decides
    # on the exit code must not proceed to patch a bundle that failed.
    fails = [c for c in checks if c["status"] == "FAIL"]
    warns = [c for c in checks if c["status"] == "WARN"]
    status = 1 if fails else (2 if warns else 0)

    if args.json:
        print(
            json.dumps(
                {
                    "bundle_id": bundle_id,
                    "checks": checks,
                    "summary": {
                        "failed": len(fails),
                        "warnings": len(warns),
                        "passed": len(checks) - len(fails) - len(warns),
                    },
                    "status": status,
                },
                indent=2,
            )
        )
        return status

    for check in checks:
        check_status = check["status"]
        if check_status == "OK":
            print(f"  {GREEN('[OK]')}      {check['id']:20s}  {check['message']}")
        elif check_status == "WARN":
            print(f"  {YELLOW('[WARN]')}    {check['id']:20s}  {check['message']}")
        else:  # FAIL
            print(f"  {RED('[FAIL]')}    {check['id']:20s}  {check['message']}")

    print()
    # Summary
    if fails:
        print(RED(f"  RESULT: {len(fails)} critical failure(s). Do NOT patch yet."))
        print(RED("          Address the FAIL above first."))
        return 1
    if warns:
        print(YELLOW(f"  RESULT: {len(warns)} warning(s). Patching will likely work but may need attention."))
        return 2
    print(GREEN("  RESULT: All checks passed. Safe to apply patches."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
