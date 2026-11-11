#!/usr/bin/env python3
"""
Internal helpers for the iOS-Pentesting-Skill scripts package.

Adds the directory containing this file to ``sys.path`` so sibling
modules (e.g. ``mobsf_client``, ``mobsf_config``) can be imported
regardless of how the script is invoked:

    python3 scripts/mobsf_upload.py
    python3 -m scripts.mobsf_upload
    /usr/bin/env python3 scripts/mobsf_upload.py

Module mode relies on ``scripts/__init__.py`` running the same bootstrap
before the script body, so both invocations resolve the sibling imports.
"""

import os
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
