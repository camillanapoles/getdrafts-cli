#!/usr/bin/env python3
"""
Patch common jailbreak-detection strings in a Mach-O binary.

Every replacement is fitted to the exact length of the bytes it overwrites,
so the binary's total size never changes (a size change would corrupt the
Mach-O load-command offsets).
"""
import _scripts_path  # noqa: F401  (adds scripts/ to sys.path)
import binpatch_util as bp

# (search, replacement) pairs. Replacements are auto-fitted to the search
# length by binpatch_util, so they need not match the original length exactly.
PATCHES = [
    (b"/private/jailbreak_test.txt", b"/private/legit_test.txt"),
    (b"/private/var/mobile/jailbreak_test.txt", b"/private/var/mobile/legit.txt"),
    (b"isCompromised", b"isVerified"),
]


def patch_jailbreak_strings(input_file: str) -> int:
    data = bp.load(input_file)
    patches = 0
    for search, replacement in PATCHES:
        count = bp.replace_all_same_length(data, search, replacement)
        if count:
            print(f"[+] Patched {search.decode('latin-1')} ({count} occurrence(s))")
            patches += count
    bp.save(input_file, data)
    print(f"[+] Total patches: {patches}")
    return patches


if __name__ == "__main__":
    args = bp.base_argparser(
        description="Patch jailbreak-detection strings in a Mach-O binary.",
        backup_suffix=".backup_jailbreak",
    ).parse_args()

    if not args.no_backup:
        bp.backup(args.binary, args.backup_suffix)

    patch_jailbreak_strings(args.binary)

    if args.codesign:
        bp.codesign(args.codesign)
