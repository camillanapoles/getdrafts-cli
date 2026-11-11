#!/usr/bin/env python3
"""
Disable NuDetect SDK references in a Mach-O binary.

Patches the ``NuDetectSDK`` string and the ``_OBJC_CLASS_$_NuDetectListener``
symbol with same-length tokens so the runtime lookups fail. All patches are
length-preserving (the binary's total size is never changed).
"""
import _scripts_path  # noqa: F401  (adds scripts/ to sys.path)
import binpatch_util as bp


def patch_binary(input_file: str, output_file: str) -> int:
    data = bp.load(input_file)
    print("[+] Patching NuDetectSDK references...")
    patches = 0

    # Strategy 1: neutralise the "NuDetectSDK" string.
    n = bp.replace_all_same_length(data, b"NuDetectSDK", b"NoDetect")
    print(f"[+] Patched {n} NuDetectSDK string reference(s)")
    patches += n

    # Strategy 2: neutralise the Obj-C class symbol. The prefix is kept so the
    # symbol stays well-formed; the suffix is auto-padded to preserve length.
    n = bp.replace_all_same_length(
        data, b"_OBJC_CLASS_$_NuDetectListener", b"_OBJC_CLASS_$_"
    )
    print(f"[+] Patched {n} NuDetectListener reference(s)")
    patches += n

    bp.save(output_file, data)
    print(f"[+] Total patches: {patches}")
    return patches


if __name__ == "__main__":
    args = bp.base_argparser(
        description="Disable NuDetect SDK references in a Mach-O binary.",
        backup_suffix=".backup_nudetect",
    ).parse_args()

    if not args.no_backup:
        bp.backup(args.binary, args.backup_suffix)

    count = patch_binary(args.binary, args.binary)
    print(f"[+] Total patches applied: {count}")

    if args.codesign:
        bp.codesign(args.codesign)
