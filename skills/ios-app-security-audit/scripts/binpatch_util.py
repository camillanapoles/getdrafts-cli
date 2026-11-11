#!/usr/bin/env python3
"""
Shared helpers for in-place Mach-O string patching.

Mutating a Mach-O binary by changing its *total length* invalidates every
file offset recorded in the load commands, leaving a binary that will not
load. Every patch performed through this module is therefore guaranteed to
be length-preserving: the replacement is padded (or truncated) to exactly
match the bytes it overwrites, so subsequent offsets never shift.
"""

import argparse
import os
import shutil
import sys


def fit(replacement: bytes, length: int, pad: bytes = b"X") -> bytes:
    """Return ``replacement`` resized to exactly ``length`` bytes.

    Shorter replacements are padded with ``pad`` (default ``b'X'``); longer
    ones are truncated. This keeps every patch length-preserving by
    construction so a caller can never accidentally grow or shrink the binary.
    """
    if len(pad) != 1:
        raise ValueError("pad must be a single byte")
    if len(replacement) > length:
        return replacement[:length]
    return replacement + pad * (length - len(replacement))


def replace_all_same_length(data: bytearray, search: bytes, replacement: bytes) -> int:
    """Replace every occurrence of ``search`` in ``data`` in place.

    The replacement is fitted to ``len(search)`` so ``len(data)`` is unchanged.
    Returns the number of occurrences patched.
    """
    repl = fit(replacement, len(search))
    count = 0
    offset = 0
    while True:
        pos = data.find(search, offset)
        if pos == -1:
            break
        data[pos:pos + len(search)] = repl
        count += 1
        offset = pos + len(search)
    return count


def load(input_file: str) -> bytearray:
    """Read a binary into a mutable bytearray, exiting cleanly if missing."""
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        sys.exit(1)
    with open(input_file, "rb") as f:
        data = bytearray(f.read())
    print(f"[+] Binary size: {len(data)} bytes")
    return data


def save(output_file: str, data: bytearray) -> None:
    """Write the patched bytes back out."""
    with open(output_file, "wb") as f:
        f.write(data)
    print(f"[+] Saved patched binary to: {output_file}")


def backup(input_file: str, suffix: str = ".backup") -> None:
    """Create a one-time backup of ``input_file`` (never overwrites an existing one)."""
    backup_file = input_file + suffix
    if os.path.exists(backup_file):
        print(f"[=] Backup already exists, leaving untouched: {backup_file}")
        return
    shutil.copy(input_file, backup_file)
    print(f"[+] Created backup: {backup_file}")


def codesign(app_path: str) -> None:
    """Ad-hoc re-sign an .app bundle after patching."""
    print(f"[+] Re-signing app (ad-hoc): {app_path}")
    rc = os.system(f'codesign --force --sign - "{app_path}"')
    if rc != 0:
        print(f"[!] codesign exited with status {rc}")


def base_argparser(description: str, backup_suffix: str) -> argparse.ArgumentParser:
    """Standard CLI: positional binary path, optional backup control and re-sign."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("binary", help="Path to the Mach-O binary inside the .app bundle")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating a backup before patching",
    )
    parser.add_argument(
        "--backup-suffix",
        default=backup_suffix,
        help=f"Suffix for the backup file (default: {backup_suffix})",
    )
    parser.add_argument(
        "--codesign",
        metavar="APP_PATH",
        help="Re-sign the given .app bundle (ad-hoc) after patching",
    )
    return parser
