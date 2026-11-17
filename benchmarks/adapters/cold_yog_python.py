#!/usr/bin/env python3
"""One-shot cold-start probe for the YOG Python binding.

Run in a fresh interpreter so the measured wall time includes Python startup,
shared-library load, policy compilation and one decision.  Used only by
``benchmarks/boundaries.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))

import yog  # noqa: E402

source = Path(sys.argv[1]).read_text(encoding="utf-8")
policy = yog.Yog(source)
print(policy.check(sys.argv[2], "can_access", sys.argv[3]))
