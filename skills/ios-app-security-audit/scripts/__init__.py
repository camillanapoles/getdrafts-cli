#!/usr/bin/env python3
"""
Package init for the iOS-Pentesting-Skill scripts.

Making ``scripts/`` a package lets every script be invoked in both documented
ways::

    python3 scripts/mobsf_upload.py      # script mode
    python3 -m scripts.mobsf_upload      # module mode

In script mode Python puts ``scripts/`` on ``sys.path`` itself, so the
sibling imports resolve. In module mode only the current directory is on
``sys.path``, so the sibling imports failed with ``ModuleNotFoundError``
even though the mode is advertised in ``_scripts_path.py``.

Running the bootstrap here fixes module mode for every script at once,
instead of repeating a try/except in each file.
"""

import os
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
