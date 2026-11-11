#!/usr/bin/env python3
"""
Patch the ``isSimulator`` detection string in a Mach-O binary.

Mutates ``isSimulator`` to a same-length token so the runtime lookup fails,
without changing the binary's total length (which would corrupt it).
"""
import _scripts_path  # noqa: F401  (adds scripts/ to sys.path)
import binpatch_util as bp


def patch_is_simulator(input_file: str) -> int:
    data = bp.load(input_file)
    print("[+] Searching for 'isSimulator'...")
    # 'isSimulator' (11 bytes) -> length-preserving replacement (padded to 11).
    count = bp.replace_all_same_length(data, b"isSimulator", b"isEmulator")
    if count == 0:
        print("[!] 'isSimulator' not found")
        return 0
    bp.save(input_file, data)
    print(f"[+] Patched isSimulator ({count} occurrence(s))")
    return count


if __name__ == "__main__":
    args = bp.base_argparser(
        description="Patch the 'isSimulator' detection string in a Mach-O binary.",
        backup_suffix=".backup_is_simulator",
    ).parse_args()

    if not args.no_backup:
        bp.backup(args.binary, args.backup_suffix)

    count = patch_is_simulator(args.binary)
    print(f"[+] Total patches: {count}")

    if args.codesign:
        bp.codesign(args.codesign)
