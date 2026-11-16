#!/usr/bin/env python3
"""Measure YOG through its Python ctypes binding.

This is the same-runtime counterpart to Casbin: both engines run in CPython,
in-process, through their native Python interface.  It is not a C-vs-Python
comparison and should not be read as one.

The adapter reports two phases separately:

* ``load``    -- ``Yog(source)``: lex, parse, analyse, build IR;
* ``request`` -- steady-state ``check`` calls after a warm-up.

Usage:
    python benchmarks/adapters/yog_python_adapter.py --size small \
        [--profile common] [--iterations 2000]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from corpus import corpus_file, load_requests, PROFILES
from stats import measure, require_decision

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"
BOUNDARY = "python-library"

sys.path.insert(0, str(ROOT / "bindings" / "python"))
import yog as yog_binding  # noqa: E402


def git_commit() -> str:
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--profile", choices=PROFILES, default="full")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--load-iterations", type=int, default=5)
    args = parser.parse_args()

    corpus = corpus_file(CORPUS, args.profile, args.size)
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    requests = load_requests(CORPUS, args.size, args.profile)
    source = corpus.read_text(encoding="utf-8")

    load_measurement, policy = measure(
        lambda: yog_binding.Yog(source), args.load_iterations, warmup=0, repetitions=2
    )
    result = {
        "engine": "yog-python",
        "size": args.size,
        "profile": args.profile,
        "boundary": BOUNDARY,
        "available": True,
        "library": yog_binding.library_path(),
        "tool_version": f"source {git_commit()[:7]} (ctypes binding)",
        "load": {
            "compile": load_measurement["median"],
            "iterations": load_measurement["iterations"],
            "repetitions": load_measurement["repetitions"],
        },
        "requests": [],
    }

    for request in requests:
        def invoke() -> str:
            return policy.check(request["actor"], request["action"], request["resource"])

        measurement, decision = measure(invoke, args.iterations, args.warmup,
                                        args.repetitions)
        require_decision(request["label"], request["expected"], decision)
        result["requests"].append({
            "label": request["label"],
            "expected": request["expected"],
            "decision": decision,
            **measurement["median"],
            "iterations": measurement["iterations"],
            "warmup": measurement["warmup"],
            "repetitions": measurement["repetitions"],
            "runs": measurement["runs"],
        })

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
