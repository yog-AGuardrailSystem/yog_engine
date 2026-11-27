#!/usr/bin/env python3
"""OpenFGA equivalence check + concurrent throughput & memory-ceiling benchmarks."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
ADAPTERS = HERE / "adapters"
CORPUS = HERE / "generated"
RESULTS = HERE / "results"

for p in (str(HERE), str(ADAPTERS), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import openfga_adapter  # noqa: E402
import oracle  # noqa: E402
from corpus import build_model, corpus_file, load_workload, parse_facts  # noqa: E402
from yog_platform.pdp import ReferencePDP  # noqa: E402


def run_openfga_equivalence(sizes=("small", "medium", "large")) -> dict:
    report = {"sizes": {}, "total_checked": 0, "total_mismatches": 0}
    for size in sizes:
        cpath = corpus_file(CORPUS, "common", size)
        if not cpath.exists():
            continue
        rows = load_workload(CORPUS, "common", size)
        model_obj = oracle.load_model(cpath)
        facts = parse_facts(cpath)
        model_dict = build_model(facts)
        out_dir = RESULTS / "translations" / "openfga" / f"common-{size}"
        openfga_adapter.write_translation(model_dict, out_dir)
        tuples = json.loads((out_dir / "tuples.json").read_text(encoding="utf-8"))["tuples"]
        evaluator = openfga_adapter.OpenFGALocalEvaluator(tuples)

        mismatches = 0
        for row in rows:
            exp = oracle.decide(model_obj, "common", row["actor"], row["resource"])
            got = evaluator.check(row["actor"], row["resource"])
            if got != exp:
                mismatches += 1
        report["sizes"][size] = {"checked": len(rows), "mismatches": mismatches}
        report["total_checked"] += len(rows)
        report["total_mismatches"] += mismatches
    return report


def run_concurrent_throughput(thread_counts=(1, 2, 4, 8), calls_per_thread=500) -> list[dict]:
    policy = (
        "version 2\n"
        "allow can_access(U, R):\n"
        "    role(U, \"admin\")\n"
        "fact role(\"u0\", \"admin\")\n"
    )
    pdp = ReferencePDP(policy)
    rows = []
    for n_threads in thread_counts:
        latencies_us: list[float] = []
        lock = threading.Lock()
        errors = [0]

        def worker():
            local_lat = []
            for _ in range(calls_per_thread):
                t0 = time.perf_counter_ns()
                res = pdp.check({"actor": "u0", "action": "can_access", "resource": "r0"})
                t1 = time.perf_counter_ns()
                if res.get("decision") != "ALLOW":
                    errors[0] += 1
                local_lat.append((t1 - t0) / 1000.0)
            with lock:
                latencies_us.extend(local_lat)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        wall0 = time.perf_counter_ns()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall_s = (time.perf_counter_ns() - wall0) / 1e9
        ordered = sorted(latencies_us)
        total_calls = n_threads * calls_per_thread
        rows.append({
            "threads": n_threads,
            "total_calls": total_calls,
            "errors": errors[0],
            "throughput_per_s": round(total_calls / wall_s, 1) if wall_s else 0.0,
            "p50_us": round(ordered[int(0.50 * len(ordered))], 2),
            "p95_us": round(ordered[int(0.95 * len(ordered))], 2),
            "p99_us": round(ordered[min(len(ordered) - 1, int(0.99 * len(ordered)))], 2),
        })
    return rows


def run_memory_ceiling_test() -> dict:
    """Measure peak Python heap under large fact tables and verify yogc fail-closed limits."""
    facts = "\n".join(f'fact member("u{i}", "t{i % 50}")' for i in range(2000))
    policy = (
        "version 2\n"
        f"{facts}\n"
        "allow can_access(U, R):\n"
        "    member(U, \"t0\")\n"
    )
    tracemalloc.start()
    pdp = ReferencePDP(policy)
    res = pdp.check({"actor": "u1950", "action": "can_access", "resource": "r0"})
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    yogc = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")
    yogc_ok = None
    if yogc.exists():
        with tempfile.NamedTemporaryFile("w", suffix=".yog", delete=False, encoding="utf-8") as tf:
            tf.write(policy)
            tf_path = tf.name
        try:
            proc = subprocess.run([str(yogc), "validate", tf_path], capture_output=True, text=True)
            yogc_ok = proc.returncode == 0
        finally:
            os.unlink(tf_path)

    return {
        "facts": 2000,
        "decision": res.get("decision"),
        "current_kb": round(current / 1024.0, 1),
        "peak_kb": round(peak / 1024.0, 1),
        "yogc_validated": yogc_ok,
    }


def main() -> int:
    openfga = run_openfga_equivalence()
    concurrent = run_concurrent_throughput()
    memory = run_memory_ceiling_test()

    report = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "openfga_equivalence": openfga,
        "concurrent_throughput": concurrent,
        "memory_ceiling": memory,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "stress.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# OpenFGA Equivalence & Stress Benchmarks",
        "",
        f"Generated {report['generated_at']}.",
        "",
        "## OpenFGA (`common` corpus, local tuple-graph evaluator)",
        "",
        f"Total checked: **{openfga['total_checked']}**, mismatches: **{openfga['total_mismatches']}**.",
        "",
        "| Size | Checked | Mismatches |",
        "| --- | ---: | ---: |",
    ]
    for size, row in openfga["sizes"].items():
        lines.append(f"| {size} | {row['checked']} | {row['mismatches']} |")

    lines += [
        "",
        "## Concurrent Throughput (`ReferencePDP`)",
        "",
        "| Threads | Calls | Throughput (ops/s) | p50 (µs) | p95 (µs) | p99 (µs) | Errors |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in concurrent:
        lines.append(
            f"| {row['threads']} | {row['total_calls']} | {row['throughput_per_s']} | "
            f"{row['p50_us']} | {row['p95_us']} | {row['p99_us']} | {row['errors']} |"
        )

    lines += [
        "",
        "## Memory Ceiling (2,000 facts)",
        "",
        f"- Decision: `{memory['decision']}`",
        f"- Peak traced Python heap: **{memory['peak_kb']} KiB**",
        f"- `yogc validate` passed: `{memory['yogc_validated']}`",
        "",
    ]
    (RESULTS / "stress.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"OpenFGA: {openfga['total_checked']} checked, {openfga['total_mismatches']} mismatches")
    print(f"wrote {RESULTS / 'stress.json'} and {RESULTS / 'stress.md'}")
    return 0 if openfga["total_mismatches"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
