#!/usr/bin/env python3
"""One-shot cold-start probe for Casbin.

Run in a fresh interpreter so the measured wall time includes Python startup,
casbin import, model/policy load and one decision.  Used only by
``benchmarks/boundaries.py``.
"""
from __future__ import annotations

import sys

from casbin import Enforcer

enforcer = Enforcer(sys.argv[1], sys.argv[2])
allowed = enforcer.enforce(sys.argv[3], sys.argv[4], "can_access")
print("ALLOW" if allowed else "DENY")
