#!/usr/bin/env python3
"""
simforge_apply.py — Apply the canonical 5-step patch flow to an iOS .app.

After preflight passes, this script executes Steps 2-5 of the canonical flow:
  Step 2: simforge convert (LC_BUILD_VERSION → platform 7)
  Step 3: vtool align (LC_VERSION_MIN_IPHONEOS for legacy frameworks)
  Step 4: Patch CFBundleSupportedPlatforms in Info.plist (main + frameworks)
  Step 5: Manual 4-sub-step re-signing (--deep is NOT enough)

Always run simforge_preflight.py first. This script does NOT make a backup;
the caller must back up the .app before running this.

Usage:
    python3 simforge_apply.py <path-to-extracted-app>
    python3 simforge_apply.py <path-to-extracted-app> --no-vtool   # skip Step 3
    python3 simforge_apply.py <path-to-extracted-app> --no-sign    # skip Step 5

Exit codes:
    0 — All patches applied successfully.
    1 — Error during patching.

See:
    references/simforge-emulation-flow.md (the canonical 10-step flow)
"""

import argparse
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import _scripts_path  # noqa: F401  -- adds scripts/ to sys.path
from simforge_binaries import (
    get_main_binary_name as _get_main_binary_name,
    iter_bundle_binaries,
)

# Collects step failures so main() can exit with a truthful status code.
# A step that fails must never be reported as "all patches applied".
FAILURES: list[str] = []


def run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command. If check=True, exit on failure."""
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, check=check)
        return result
    except subprocess.CalledProcessError as e:
        print(f"ERROR running: {' '.join(cmd)}", file=sys.stderr)
        if e.stdout:
            print(f"stdout: {e.stdout}", file=sys.stderr)
        if e.stderr:
            print(f"stderr: {e.stderr}", file=sys.stderr)
        if check:
            sys.exit(1)
        return e
    except FileNotFoundError:
        # The tool is not installed (otool/vtool/codesign are macOS-only).
        # Report it clearly instead of dying with a traceback.
        print(
            f"ERROR: required tool not found: {cmd[0]}",
            file=sys.stderr,
        )
        if check:
            sys.exit(1)
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")


def find_simforge() -> str:
    """Locate simforge binary."""
    # Check common locations
    for p in ["simforge", "/usr/local/bin/simforge", str(Path.home() / ".local/bin/simforge")]:
        if shutil.which(p) or os.path.exists(p):
            return p
    print("ERROR: simforge not found in PATH or ~/.local/bin/", file=sys.stderr)
    sys.exit(1)


def step2_simforge_convert(app_path: Path, simforge: str) -> None:
    """Step 2: simforge convert — patches LC_BUILD_VERSION to platform 7."""
    print(f"\n[Step 2] simforge convert on {app_path}")
    result = run([simforge, "convert", str(app_path)], check=False)
    if result.returncode != 0:
        print(f"ERROR: simforge convert failed (exit {result.returncode})", file=sys.stderr)
        sys.exit(1)
    print("  [OK] simforge convert done")


def parse_sdk_version(otool_output: str) -> str | None:
    """Extract the SDK version from `otool -l` LC_BUILD_VERSION output.

    Modern toolchains print a dotted version ("sdk 26.7"); older ones print a
    packed 32-bit value ("sdk 0x00000011"). Both must be supported, otherwise
    the parser silently falls back to a wrong default version.
    """
    lines = otool_output.splitlines()
    for i, line in enumerate(lines):
        if "LC_BUILD_VERSION" not in line:
            continue
        for j in range(i, min(i + 10, len(lines))):
            stripped = lines[j].strip()
            if not stripped.startswith("sdk"):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            raw = parts[-1]
            # Dotted form, e.g. "26.7"
            if "." in raw:
                return raw
            # Packed 32-bit form, e.g. "0x00000011"
            try:
                value = int(raw, 16)
            except ValueError:
                continue
            major = (value >> 16) & 0xFFFF
            minor = (value >> 8) & 0xFF
            return f"{major}.{minor}"
    return None


def step3_vtool_align(app_path: Path) -> int:
    """Step 3: vtool -set-version-min for legacy binaries."""
    print("\n[Step 3] vtool align (legacy LC_VERSION_MIN_IPHONEOS)")
    main_bin_name = get_main_binary_name(app_path)
    if not main_bin_name:
        return 0

    main_bin = app_path / main_bin_name
    # Get the SDK version from main binary's LC_BUILD_VERSION
    result = run(["otool", "-l", str(main_bin)], check=False)
    sdk_version = parse_sdk_version(result.stdout)
    if not sdk_version:
        print("  [WARN] Could not detect SDK version from main binary; using 18.0 as default")
        sdk_version = "18.0"

    print(f"  Using SDK version: {sdk_version}")

    # Find binaries with LC_VERSION_MIN_IPHONEOS.
    # The inventory is shared with simforge_preflight.py so the pre-flight
    # inspects exactly the binaries this step is going to modify.
    legacy_binaries = []
    candidates = iter_bundle_binaries(app_path)

    for binary in candidates:
        result = run(["otool", "-l", str(binary)], check=False)
        if "LC_VERSION_MIN_IPHONEOS" in result.stdout:
            legacy_binaries.append(binary)

    if not legacy_binaries:
        print("  [OK] No legacy binaries (all use LC_BUILD_VERSION)")
        return 0

    print(f"  Found {len(legacy_binaries)} legacy binary(ies), patching...")
    for binary in legacy_binaries:
        # Note: vtool prints "code signature will be invalid" — that's expected
        result = run(
            ["vtool", "-arch", "arm64", "-set-version-min", "ios", sdk_version, sdk_version,
             "-output", str(binary), str(binary)],
            check=False,
        )
        if result.returncode != 0:
            print(f"  [FAIL] vtool failed on {binary.name}: {result.stderr}")
            FAILURES.append(f"vtool failed on {binary.name}")
        else:
            print(f"  [OK] Patched: {binary.relative_to(app_path)}")
    return len(legacy_binaries)


def step4_patch_platforms(app_path: Path) -> None:
    """Step 4: Patch CFBundleSupportedPlatforms in Info.plist files."""
    print("\n[Step 4] Patch CFBundleSupportedPlatforms in Info.plists")

    # Main bundle
    main_plist = app_path / "Info.plist"
    if main_plist.exists():
        _patch_plist_platforms(main_plist)
        print(f"  [OK] Patched: {main_plist.relative_to(app_path)}")

    # Frameworks
    fw_dir = app_path / "Frameworks"
    if fw_dir.exists():
        fw_count = 0
        for fw_plist in fw_dir.glob("*.framework/Info.plist"):
            try:
                _patch_plist_platforms(fw_plist)
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"  [FAIL] {fw_plist.relative_to(app_path)}: {exc}", file=sys.stderr)
                FAILURES.append(f"could not patch {fw_plist.relative_to(app_path)}")
                continue
            fw_count += 1
        print(f"  [OK] Patched {fw_count} framework Info.plist(s)")

    # PlugIns (appex)
    plugins_dir = app_path / "PlugIns"
    if plugins_dir.exists():
        apx_count = 0
        for apx_plist in plugins_dir.glob("*.appex/Info.plist"):
            try:
                _patch_plist_platforms(apx_plist)
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"  [FAIL] {apx_plist.relative_to(app_path)}: {exc}", file=sys.stderr)
                FAILURES.append(f"could not patch {apx_plist.relative_to(app_path)}")
                continue
            apx_count += 1
        print(f"  [OK] Patched {apx_count} appex Info.plist(s)")


def _patch_plist_platforms(plist_path: Path) -> None:
    """Replace CFBundleSupportedPlatforms with ['iPhoneSimulator'] in a plist.

    Raises on a malformed plist so the caller can record the failure; a
    partially patched bundle must never be reported as fully patched.
    """
    with open(str(plist_path), "rb") as f:
        info = plistlib.load(f)
    info["CFBundleSupportedPlatforms"] = ["iPhoneSimulator"]
    with open(str(plist_path), "wb") as f:
        plistlib.dump(info, f)


def step5_resign(app_path: Path) -> None:
    """Step 5: Manual 4-sub-step re-signing.

    This is critical: `codesign --deep` is NOT enough for modern apps.
    The original App Store signature is left orphaned in inner framework
    binaries unless we remove it explicitly and re-sign.
    """
    print("\n[Step 5] Manual 4-sub-step re-signing")

    main_bin_name = get_main_binary_name(app_path)
    if not main_bin_name:
        print("  [FAIL] Could not determine main binary name, cannot re-sign", file=sys.stderr)
        FAILURES.append("could not determine main binary name; bundle left unsigned")
        return

    # 5.1: Remove ALL existing signatures
    print("  [5.1] Removing all existing signatures...")
    main_bin = app_path / main_bin_name
    binaries_to_resign = []
    if main_bin.exists():
        run(["codesign", "--remove-signature", str(main_bin)], check=False)
        binaries_to_resign.append(main_bin)

    fw_dir = app_path / "Frameworks"
    if fw_dir.exists():
        for fw in fw_dir.glob("*.framework"):
            inner = fw / fw.stem
            if inner.exists():
                run(["codesign", "--remove-signature", str(inner)], check=False)
                binaries_to_resign.append(inner)
            run(["codesign", "--remove-signature", str(fw)], check=False)
        for dylib in fw_dir.glob("*.dylib"):
            run(["codesign", "--remove-signature", str(dylib)], check=False)
            binaries_to_resign.append(dylib)

    plugins_dir = app_path / "PlugIns"
    if plugins_dir.exists():
        for appex in plugins_dir.glob("*.appex"):
            inner = appex / appex.stem
            if inner.exists():
                run(["codesign", "--remove-signature", str(inner)], check=False)
                binaries_to_resign.append(inner)
            run(["codesign", "--remove-signature", str(appex)], check=False)
    run(["codesign", "--remove-signature", str(app_path)], check=False)

    # 5.2: Sign inner binaries
    print(f"  [5.2] Signing {len(binaries_to_resign)} inner binary(ies)...")
    for binary in binaries_to_resign:
        sign_result = run(["codesign", "-f", "-s", "-", str(binary)], check=False)
        if sign_result.returncode != 0:
            print(f"    [FAIL] could not sign {binary.name}: {sign_result.stderr}", file=sys.stderr)
            FAILURES.append(f"codesign failed on {binary.name}")

    # 5.3: Sign framework bundles and appex
    print("  [5.3] Signing framework bundles and appex...")
    if fw_dir.exists():
        for fw in fw_dir.glob("*.framework"):
            sign_result = run(["codesign", "-f", "-s", "-", str(fw)], check=False)
            if sign_result.returncode != 0:
                print(f"    [FAIL] could not sign {fw.name}: {sign_result.stderr}", file=sys.stderr)
                FAILURES.append(f"codesign failed on {fw.name}")
    if plugins_dir.exists():
        for appex in plugins_dir.glob("*.appex"):
            sign_result = run(["codesign", "-f", "-s", "-", str(appex)], check=False)
            if sign_result.returncode != 0:
                print(f"    [FAIL] could not sign {appex.name}: {sign_result.stderr}", file=sys.stderr)
                FAILURES.append(f"codesign failed on {appex.name}")

    # 5.4: Sign main app
    print("  [5.4] Signing main app bundle...")
    sign_result = run(["codesign", "-f", "-s", "-", str(app_path)], check=False)
    if sign_result.returncode != 0:
        print(f"    [FAIL] could not sign main bundle: {sign_result.stderr}", file=sys.stderr)
        FAILURES.append("codesign failed on the main app bundle")

    # Verify
    print("  [VERIFY] codesign -v --strict on main bundle:")
    result = run(["codesign", "-v", "--strict", str(app_path)], check=False)
    if result.returncode == 0:
        print("    [OK] Main bundle signature VALID")
    else:
        print(f"    [FAIL] Main bundle signature INVALID: {result.stderr}", file=sys.stderr)
        FAILURES.append(f"codesign verification failed: {result.stderr.strip()}")


def get_main_binary_name(app_path: Path) -> str | None:
    """Read CFBundleExecutable from the bundle's Info.plist."""
    return _get_main_binary_name(app_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply the canonical 5-step patch flow to an iOS .app bundle.",
    )
    parser.add_argument("app_path", help="Path to extracted .app bundle")
    parser.add_argument(
        "--no-vtool",
        action="store_true",
        help="Skip Step 3 (vtool align) — use only if you've already done it manually",
    )
    parser.add_argument(
        "--no-sign",
        action="store_true",
        help="Skip Step 5 (re-signing) — e.g., if you'll sign with custom entitlements later",
    )
    args = parser.parse_args()

    app_path = Path(args.app_path).resolve()
    if not app_path.is_dir() or not app_path.name.endswith(".app"):
        print(f"ERROR: {app_path} is not a .app bundle directory", file=sys.stderr)
        return 1

    if not (app_path / "Info.plist").exists():
        print(f"ERROR: {app_path}/Info.plist not found", file=sys.stderr)
        return 1

    print(f"=== Applying patches to {app_path.name} ===")
    print("WARNING: This is a DESTRUCTIVE operation. Make a backup first.")
    print("         (Press Ctrl+C within 3 seconds to abort)")
    try:
        import time
        time.sleep(3)
    except KeyboardInterrupt:
        print("\nAborted by user")
        return 1

    # Step 2
    simforge = find_simforge()
    step2_simforge_convert(app_path, simforge)

    # Step 3 (optional)
    if not args.no_vtool:
        step3_vtool_align(app_path)
    else:
        print("\n[Step 3] Skipped (--no-vtool)")

    # Step 4
    step4_patch_platforms(app_path)

    # Step 5
    if not args.no_sign:
        step5_resign(app_path)
    else:
        print("\n[Step 5] Skipped (--no-sign)")

    if FAILURES:
        print(
            f"\n=== {len(FAILURES)} step(s) FAILED — {app_path.name} is NOT ready to install ===",
            file=sys.stderr,
        )
        for failure in FAILURES:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\n=== All patches applied to {app_path.name} ===")
    print("Next: boot a simulator and install with simctl. See simforge_install_launch.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
