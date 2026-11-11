#!/usr/bin/env python3
"""
Neutralise termination-related error strings in a Mach-O binary.

This zeroes out human-readable strings tied to integrity/termination paths
(e.g. "Security violation", "Simulator detected"). It does NOT rewrite the
actual exit/abort call sites — that requires instruction-level patching and
is better done dynamically (see assets/frida-scripts/prevent-app-termination-ios.js
and rasp-bypass-ios-*.js). All edits are length-preserving.
"""
import _scripts_path  # noqa: F401  (adds scripts/ to sys.path)
import binpatch_util as bp

ERROR_STRINGS = [
    b"Application terminated",
    b"Terminated due to",
    b"Exiting due to",
    b"Security violation",
    b"Integrity check failed",
    b"Simulator detected",
    b"Device integrity check",
]


def patch_binary(input_file: str) -> int:
    data = bp.load(input_file)
    print("[+] Neutralising termination-related error strings...")
    patches = 0
    for s in ERROR_STRINGS:
        # Replace with NUL bytes of the same length (length-preserving).
        count = bp.replace_all_same_length(data, s, b"\x00" * len(s))
        if count:
            print(f"[+] Patched error string: {s.decode('latin-1')} ({count})")
            patches += count
    bp.save(input_file, data)
    print(f"[+] Total patches: {patches}")
    return patches


if __name__ == "__main__":
    args = bp.base_argparser(
        description="Neutralise termination-related error strings in a Mach-O binary.",
        backup_suffix=".backup_termination",
    ).parse_args()

    if not args.no_backup:
        bp.backup(args.binary, args.backup_suffix)

    count = patch_binary(args.binary)
    print(f"[+] Total patches applied: {count}")

    if args.codesign:
        bp.codesign(args.codesign)
