#!/usr/bin/env python3
"""
Shared inventory of the Mach-O binaries inside an extracted .app bundle.

The pre-flight check and the patch flow must agree on WHICH binaries they
inspect. When those lists diverge, the pre-flight reports "all modern" for a
bundle whose .dylib or .appex is still legacy, the patch flow then leaves that
binary untouched, and the app fails to launch on the simulator with an error
that points at the app instead of at the tooling.

This module is the single source of truth for that inventory, so the two
steps can no longer drift apart.
"""

from __future__ import annotations

import plistlib
from pathlib import Path


def get_main_binary_name(app_path: Path) -> str | None:
    """Return CFBundleExecutable from the bundle's Info.plist, or None."""
    plist = Path(app_path) / "Info.plist"
    if not plist.exists():
        return None
    try:
        with open(str(plist), "rb") as f:
            info = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    return info.get("CFBundleExecutable")


def iter_bundle_binaries(app_path: Path) -> list[Path]:
    """Return every Mach-O binary the patch flow touches, in a stable order.

    Covers the main executable, the inner binary of every framework, every
    loose .dylib in Frameworks/, and the inner binary of every .appex
    extension.
    """
    app_path = Path(app_path)
    binaries: list[Path] = []

    main_bin_name = get_main_binary_name(app_path)
    if main_bin_name:
        main_bin = app_path / main_bin_name
        if main_bin.exists():
            binaries.append(main_bin)

    fw_dir = app_path / "Frameworks"
    if fw_dir.exists():
        for fw in sorted(fw_dir.glob("*.framework")):
            inner = fw / fw.stem
            if inner.exists():
                binaries.append(inner)
        for dylib in sorted(fw_dir.glob("*.dylib")):
            binaries.append(dylib)

    plugins_dir = app_path / "PlugIns"
    if plugins_dir.exists():
        for appex in sorted(plugins_dir.glob("*.appex")):
            inner = appex / appex.stem
            if inner.exists():
                binaries.append(inner)

    return binaries
