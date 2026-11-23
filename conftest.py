"""pytest configuration shared by every test directory.

The Python reference interpreter lives in ``reference/yog_ref.py`` so that
its import name does not collide with the ``yog`` binding package in
``bindings/python``.  Put it on ``sys.path`` for the reference tests.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "reference"))
