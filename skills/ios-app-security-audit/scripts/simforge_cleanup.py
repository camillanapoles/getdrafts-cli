#!/usr/bin/env python3
"""
SimForge Legacy Load Command Cleanup

Removes LC_VERSION_MIN_IPHONEOS from binaries that have BOTH
LC_VERSION_MIN_IPHONEOS and LC_BUILD_VERSION (a condition that
causes dyld to reject the binary).

Use after `simforge convert` when apps crash with dyld assertion
or SIGSEGV on simulator launch.
"""

import sys
import os
import shutil
import argparse

try:
    import lief
except ImportError:  # pragma: no cover - environment dependent
    print(
        "❌ ERROR: the 'lief' package is required by this script.\n"
        "   Install it with:  pip3 install lief",
        file=sys.stderr,
    )
    sys.exit(1)


def cleanup_binary(binary_path, verbose=True):
    """
    Remove LC_VERSION_MIN_IPHONEOS if LC_BUILD_VERSION exists.

    The rewrite is done on a temporary file that is validated before it
    replaces the original, and the original is backed up first: LIEF
    re-serialisation can produce an unusable Mach-O, and there is no undo
    once the only copy has been overwritten.

    Returns:
        - "cleaned": cleanup was performed (binary modified)
        - "skipped": nothing to do (no legacy command present)
        - "failed": the binary could not be processed; the caller must know
    """
    try:
        binary = lief.parse(binary_path)
        if not binary:
            if verbose:
                print(f"❌ ERROR: Cannot parse {binary_path}")
            return "failed"
    except Exception as e:
        if verbose:
            print(f"❌ ERROR parsing {binary_path}: {e}")
        return "failed"

    # Check if binary has both commands
    has_version_min = any(
        cmd.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS
        for cmd in binary.commands
    )
    has_build_version = any(
        cmd.command == lief.MachO.LoadCommand.TYPE.BUILD_VERSION
        for cmd in binary.commands
    )

    if not has_version_min:
        if verbose:
            print(f"  ✅ {os.path.basename(binary_path)}: No LC_VERSION_MIN_IPHONEOS")
        return "skipped"

    if not has_build_version:
        if verbose:
            print(f"  ⚠️  {os.path.basename(binary_path)}: Has LC_VERSION_MIN but no LC_BUILD_VERSION (skip)")
        return "skipped"

    # Has both - need cleanup
    version_min_indices = [
        idx for idx, cmd in enumerate(binary.commands)
        if cmd.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS
    ]

    if verbose:
        print(f"  📌 {os.path.basename(binary_path):30} - Removing {len(version_min_indices)} LC_VERSION_MIN_IPHONEOS")

    # Remove in reverse order to avoid index shifting
    for idx in reversed(version_min_indices):
        binary.remove_command(idx)

    # Write to a temporary file first, validate it, and only then replace the
    # original. A failed or unparseable write must never destroy the binary.
    backup_path = f"{binary_path}.pre-lief.bak"
    tmp_path = f"{binary_path}.lief.tmp"
    try:
        if not os.path.exists(backup_path):
            shutil.copy2(binary_path, backup_path)
            if verbose:
                print(f"     💾 Backup: {os.path.basename(backup_path)}")

        binary.write(tmp_path)

        if not lief.MachO.parse(tmp_path):
            os.unlink(tmp_path)
            if verbose:
                print("     ❌ ERROR: LIEF produced an unparseable Mach-O; original left untouched")
            return "failed"

        os.replace(tmp_path, binary_path)
        if verbose:
            print("     ✅ Cleaned")
        return "cleaned"
    except Exception as e:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if verbose:
            print(f"     ❌ ERROR writing: {e}")
            if os.path.exists(backup_path):
                print(f"        original preserved at {backup_path}")
        return "failed"

def verify_binary(binary_path):
    """Verify binary has only LC_BUILD_VERSION."""
    try:
        binary = lief.parse(binary_path)
        if not binary:
            return False

        has_version_min = any(
            cmd.command == lief.MachO.LoadCommand.TYPE.VERSION_MIN_IPHONEOS
            for cmd in binary.commands
        )
        has_build_version = any(
            cmd.command == lief.MachO.LoadCommand.TYPE.BUILD_VERSION
            for cmd in binary.commands
        )

        # Good state: has BUILD_VERSION, NO VERSION_MIN
        return has_build_version and not has_version_min
    except Exception:
        # A binary LIEF cannot parse is not in the "good" state.
        return False

def process_app_bundle(app_path, verify_only=False, verbose=True):
    """
    Process all binaries in an app bundle.

    Args:
        app_path: Path to .app bundle
        verify_only: Only verify, don't modify
        verbose: Print status

    Returns:
        Tuple: (total_processed, cleaned_count, failed_count)
    """
    binaries = []

    # Main binary
    main_binary = os.path.join(app_path, os.path.basename(os.path.basename(app_path).replace('.app', '')))
    # Some apps have different binary names - try common patterns
    if not os.path.exists(main_binary):
        # Try to find any executable in the app root
        for f in os.listdir(app_path):
            full_path = os.path.join(app_path, f)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                main_binary = full_path
                break

    if os.path.exists(main_binary):
        binaries.append(main_binary)

    # Frameworks
    frameworks_dir = os.path.join(app_path, "Frameworks")
    if os.path.exists(frameworks_dir):
        for fw in os.listdir(frameworks_dir):
            if fw.endswith(".framework"):
                name = fw.replace(".framework", "")
                binary = os.path.join(frameworks_dir, fw, name)
                if os.path.exists(binary):
                    binaries.append(binary)

    # Extensions
    plugins_dir = os.path.join(app_path, "PlugIns")
    if os.path.exists(plugins_dir):
        for ext in os.listdir(plugins_dir):
            if ext.endswith(".appex"):
                name = ext.replace(".appex", "")
                binary = os.path.join(plugins_dir, ext, name)
                if os.path.exists(binary):
                    binaries.append(binary)

    if verbose:
        print(f"Found {len(binaries)} binaries in {os.path.basename(app_path)}")

    cleaned = 0
    verified_ok = 0
    failed = 0

    for binary in binaries:
        if verify_only:
            if verify_binary(binary):
                if verbose:
                    print(f"  ✅ {os.path.basename(binary):30} - OK")
                verified_ok += 1
            else:
                if verbose:
                    print(f"  ❌ {os.path.basename(binary):30} - Needs cleanup")
                failed += 1
        else:
            # A binary that could not be cleaned is NOT "already OK": it is
            # still in the legacy state and the caller has to know about it.
            status = cleanup_binary(binary, verbose)
            if status == "cleaned":
                cleaned += 1
            elif status == "failed":
                failed += 1

    return len(binaries), cleaned, failed

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clean up LC_VERSION_MIN_IPHONEOS after SimForge conversion"
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Path(s) to .app bundle(s) or individual binary/binaries"
    )
    parser.add_argument(
        "-v", "--verify",
        action="store_true",
        help="Only verify, don't modify"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (less output)"
    )
    args = parser.parse_args()

    verbose = not args.quiet

    if verbose:
        print("="*60)
        print("SimForge Legacy Load Command Cleanup")
        print("="*60)
        if args.verify:
            print("MODE: Verify only (no modifications)")
        print()

    total_processed = 0
    total_cleaned = 0
    total_failed = 0

    for path in args.paths:
        if not os.path.exists(path):
            print(f"❌ Path not found: {path}", file=sys.stderr)
            total_failed += 1
            continue

        # Check if it's an app bundle or single binary
        if path.endswith(".app") or path.endswith(".appex"):
            if verbose:
                print(f"\n📱 Processing bundle: {os.path.basename(path)}")
            processed, cleaned, failed = process_app_bundle(path, args.verify, verbose)
            total_processed += processed
            if args.verify:
                total_failed += failed
            else:
                total_cleaned += cleaned
        else:
            # Single binary
            if verbose:
                print(f"\n📄 Processing: {os.path.basename(path)}")
            if args.verify:
                if verify_binary(path):
                    if verbose:
                        print("  ✅ OK")
                else:
                    if verbose:
                        print("  ❌ Needs cleanup")
                    total_failed += 1
                total_processed += 1
            else:
                status = cleanup_binary(path, verbose)
                if status == "cleaned":
                    total_cleaned += 1
                elif status == "failed":
                    total_failed += 1
                total_processed += 1

    if verbose:
        print()
        print("="*60)
        if args.verify:
            print("Verification complete:")
            print(f"  Total: {total_processed}")
            print(f"  OK: {total_processed - total_failed}")
            print(f"  Needs cleanup: {total_failed}")
        else:
            print("Cleanup complete:")
            print(f"  Total: {total_processed}")
            print(f"  Cleaned: {total_cleaned}")
            print(f"  Already OK: {total_processed - total_cleaned - total_failed}")
            if total_failed:
                print(f"  Failed: {total_failed}")
        print("="*60)

        if total_cleaned > 0:
            print()
            print("⚠️  Don't forget to re-sign after cleanup:")
            print("   codesign -f -s - --all-architectures <path_to_app>")

    # A failed cleanup must not be reported as success: the caller needs to
    # know the binaries are still in the legacy state.
    if total_failed:
        print(
            f"\n❌ {total_failed} file(s) could not be processed",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
