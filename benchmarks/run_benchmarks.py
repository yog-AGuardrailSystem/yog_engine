#!/usr/bin/env python3
"""Run the YOG benchmark suite and write machine- and human-readable results.

Two measurements are deliberately separate:

* **runtime** -- `bench_yog` compiles once and times repeated `yog_check()`;
* **end-to-end** -- `yogc` is invoked as a process, so startup, policy load and
  output are included.

Percentiles are computed from per-call samples.  Nothing here is a comparison
with another engine; the Cedar/OPA/Casbin adapters are separate and are only
run when their tool is installed.

Usage:
    python benchmarks/run_benchmarks.py [--yogc PATH] [--bench PATH] [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
DEFAULT_OUT = HERE / "results"
EXE = ".exe" if os.name == "nt" else ""

ITERATIONS = {"small": 20000, "medium": 5000, "large": 500}
COMPILE_ITERATIONS = {"small": 500, "medium": 100, "large": 10}
END_TO_END_ITERATIONS = {"small": 200, "medium": 100, "large": 20}
BATCH_REQUESTS = {"small": 2000, "medium": 1000, "large": 200}


def percentile(sorted_samples: list[float], fraction: float) -> float:
    if not sorted_samples:
        return 0.0
    index = min(len(sorted_samples) - 1, int(fraction * len(sorted_samples)))
    return sorted_samples[index]


def summarize(samples_ns: list[float], elapsed_ns: float) -> dict:
    ordered = sorted(samples_ns)
    return {
        "count": len(samples_ns),
        "mean_us": statistics.fmean(samples_ns) / 1000.0 if samples_ns else 0.0,
        "p50_us": percentile(ordered, 0.50) / 1000.0,
        "p95_us": percentile(ordered, 0.95) / 1000.0,
        "p99_us": percentile(ordered, 0.99) / 1000.0,
        "max_us": ordered[-1] / 1000.0 if ordered else 0.0,
        "throughput_per_s": (len(samples_ns) / (elapsed_ns / 1e9)) if elapsed_ns else 0.0,
    }


def run_json(command: list[str]) -> list[dict]:
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if completed.returncode != 0:
        raise SystemExit(f"command failed ({completed.returncode}): {' '.join(command)}\n"
                         f"{completed.stderr}")
    results = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            results.append(json.loads(line))
    return results


def run_engine_bench(bench: Path, corpus: Path, request: dict, iterations: int) -> dict:
    command = [str(bench), "check", str(corpus), request["actor"], request["action"],
               request["resource"], "--iterations", str(iterations)]
    return {entry["mode"]: entry for entry in run_json(command)}


def run_compile_bench(bench: Path, corpus: Path, iterations: int) -> dict:
    command = [str(bench), "compile", str(corpus), "--iterations", str(iterations)]
    return {entry["mode"]: entry for entry in run_json(command)}


def run_end_to_end_check(yogc: Path, corpus: Path, request: dict, iterations: int) -> dict:
    samples: list[float] = []
    start = time.perf_counter_ns()
    for _ in range(iterations):
        before = time.perf_counter_ns()
        completed = subprocess.run(
            [str(yogc), "check", str(corpus), request["actor"], request["action"],
             request["resource"]],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        after = time.perf_counter_ns()
        if completed.returncode not in (0, 3):
            raise SystemExit(f"yogc check failed: {completed.stderr}")
        samples.append(after - before)
    elapsed = time.perf_counter_ns() - start
    summary = summarize(samples, elapsed)
    summary["decision"] = completed.stdout.split("|", 1)[0].strip()
    return summary


def run_end_to_end_batch(yogc: Path, corpus: Path, requests: list[dict],
                         count: int) -> dict:
    lines = []
    expected = []
    for index in range(count):
        request = requests[index % len(requests)]
        lines.append(f"{request['actor']} {request['action']} {request['resource']}")
        expected.append(request["expected"])
    start = time.perf_counter_ns()
    completed = subprocess.run(
        [str(yogc), "batch", str(corpus)],
        input="\n".join(lines) + "\n",
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    elapsed = time.perf_counter_ns() - start
    if completed.returncode != 0:
        raise SystemExit(f"yogc batch failed: {completed.stderr}")
    blocks = [b.strip() for b in completed.stdout.split("--") if b.strip()]
    if len(blocks) != count:
        raise SystemExit(f"batch returned {len(blocks)} results for {count} requests")
    mismatches = 0
    for block, want in zip(blocks, expected):
        got = block.split("|", 1)[0].strip()
        if got != want:
            mismatches += 1
    return {
        "requests": count,
        "elapsed_ms": elapsed / 1e6,
        "throughput_per_s": count / (elapsed / 1e9),
        "mean_us": (elapsed / count) / 1000.0,
        "mismatches": mismatches,
    }


def write_markdown(path: Path, results: dict) -> None:
    lines = [
        "# Local YOG benchmark results",
        "",
        f"Generated: {results['generated_at']}",
        f"Host: {results['host']['platform']} / Python {results['host']['python']}",
        "",
        "These are local measurements of this build. They are not a comparison",
        "with Cedar, OPA or Casbin; see `docs/BENCHMARKS.md` for the methodology",
        "and for why adapter results are reported separately.",
        "",
    ]
    for size, data in results["corpora"].items():
        stats = data["stats"]
        lines.extend([
            f"## {size}",
            "",
            f"{stats['predicates']} predicates, {stats['clauses']} clauses, "
            f"{stats['values']} constants.",
            "",
            "### Compile and load",
            "",
            "| metric | mean | p50 | p95 | p99 | throughput |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            f"| compile (engine) | {data['compile']['mean_us']/1000:.3f} ms | "
            f"{data['compile']['p50_us']/1000:.3f} ms | "
            f"{data['compile']['p95_us']/1000:.3f} ms | "
            f"{data['compile']['p99_us']/1000:.3f} ms | "
            f"{data['compile']['throughput_per_s']:.1f}/s |",
            "",
            "### Engine check (compile once, time `yog_check`)",
            "",
            "| request | decision | mean | p50 | p95 | p99 | throughput |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ])
        for label, result in data["runtime"].items():
            lines.append(
                f"| {label} | {result['decision']} | {result['mean_us']:.2f} µs | "
                f"{result['p50_us']:.2f} µs | {result['p95_us']:.2f} µs | "
                f"{result['p99_us']:.2f} µs | {result['throughput_per_s']:.0f}/s |"
            )
        lines.extend([
            "",
            "### End-to-end (`yogc` process)",
            "",
            "| mode | mean | p50 | p95 | p99 | throughput |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ])
        single = data["end_to_end"]["check"]
        batch = data["end_to_end"]["batch"]
        lines.append(
            f"| one `yogc check` | {single['mean_us']/1000:.3f} ms | "
            f"{single['p50_us']/1000:.3f} ms | {single['p95_us']/1000:.3f} ms | "
            f"{single['p99_us']/1000:.3f} ms | {single['throughput_per_s']:.1f}/s |"
        )
        lines.append(
            f"| `yogc batch` ({batch['requests']} requests) | "
            f"{batch['mean_us']:.1f} µs/request | — | — | — | "
            f"{batch['throughput_per_s']:.0f}/s |"
        )
        lines.extend([
            "",
            f"Batch decision mismatches: {batch['mismatches']}.",
            "",
            "### Memory (resident set, approximate)",
            "",
            "| phase | RSS |",
            "| --- | ---: |",
            f"| before compile | {data['memory']['rss_before_kb']} KiB |",
            f"| after checks | {data['memory']['rss_after_kb']} KiB |",
            "",
        ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path,
                        default=ROOT / "yog" / "build" / f"yogc{EXE}")
    parser.add_argument("--bench", type=Path,
                        default=ROOT / "yog" / "build" / f"bench_yog{EXE}")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--corpus", type=Path, default=HERE / "generated")
    args = parser.parse_args()

    if not args.yogc.exists() or not args.bench.exists():
        raise SystemExit(
            "yogc or bench_yog not found; build first:\n"
            "  cmake -S yog -B yog/build && cmake --build yog/build"
        )

    subprocess.run([sys.executable, str(HERE / "gen_corpus.py"), "--out", str(args.corpus)],
                   check=True)
    requests = json.loads((args.corpus / "requests.json").read_text(encoding="utf-8"))["by_size"]

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "corpora": {},
    }

    for size in ("small", "medium", "large"):
        corpus = args.corpus / f"{size}.yog"
        print(f"benchmarking {size} ...", flush=True)
        compile_entries = run_compile_bench(args.bench, corpus, COMPILE_ITERATIONS[size])
        stats = compile_entries["stats"]
        compile_result = compile_entries["compile"]

        runtime = {}
        memory = {"rss_before_kb": None, "rss_after_kb": None}
        for request in requests[size]:
            entries = run_engine_bench(args.bench, corpus, request, ITERATIONS[size])
            runtime[request["label"]] = entries["check"]
            memory["rss_before_kb"] = entries["check"]["rss_before_kb"]
            memory["rss_after_kb"] = entries["check"]["rss_after_kb"]

        end_to_end = {
            "check": run_end_to_end_check(args.yogc, corpus, requests[size][0],
                                          END_TO_END_ITERATIONS[size]),
            "batch": run_end_to_end_batch(args.yogc, corpus, requests[size],
                                          BATCH_REQUESTS[size]),
        }

        results["corpora"][size] = {
            "stats": stats,
            "compile": compile_result,
            "runtime": runtime,
            "end_to_end": end_to_end,
            "memory": memory,
        }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "local.json").write_text(json.dumps(results, indent=2) + "\n",
                                         encoding="utf-8")
    write_markdown(args.out / "local.md", results)
    print(f"\nwrote {args.out / 'local.json'} and {args.out / 'local.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
