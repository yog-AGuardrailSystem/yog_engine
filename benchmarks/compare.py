#!/usr/bin/env python3
"""Run the same corpus through YOG, OPA, Cedar and Casbin and compare results.

Two boundaries are reported separately and never mixed:

* **cli-process** -- every sample compiles/loads the policy and spawns a
  process: `yogc check`, `opa eval`, `cedar authorize`.
* **library** -- in-process decisions: YOG's C engine (from the existing
  `local.json` run) and Casbin's Python enforcer.  This is cross-language and
  is labelled as such.

Every engine must return the decision recorded in `requests.json`; a mismatch
aborts the run rather than producing a timing for the wrong answer.

Usage:
    python benchmarks/compare.py [--sizes small medium large]
                                 [--iterations N] [--repetitions R]
                                 [--yogc PATH] [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
CORPUS = HERE / "generated"
RESULTS = HERE / "results"
ADAPTERS = HERE / "adapters"

sys.path.insert(0, str(ADAPTERS))
from corpus import load_requests  # noqa: E402
from stats import measure, require_decision  # noqa: E402

EXE = ".exe" if os.name == "nt" else ""
DEFAULT_ITERATIONS = {"small": 30, "medium": 20, "large": 10}
LIBRARY_ITERATIONS = {"small": 200, "medium": 100, "large": 30}
YOG_LIBRARY_ITERATIONS = {"small": 5000, "medium": 2000, "large": 500}
YOG_COMPILE_ITERATIONS = {"small": 20, "medium": 10, "large": 5}


def find_yogc(explicit: Path | None) -> Path:
    candidates = ([explicit] if explicit else []) + [
        ROOT / "yog" / "build-release" / f"yogc{EXE}",
        ROOT / "yog" / "build" / f"yogc{EXE}",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return Path(candidate)
    raise SystemExit("yogc not found; build it or pass --yogc")


def git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
        return completed.stdout.strip() if completed.returncode == 0 else "unknown"
    except OSError:
        return "unknown"


def run_adapter(name: str, size: str, iterations: int, warmup: int,
                repetitions: int) -> dict:
    command = [
        sys.executable, str(ADAPTERS / f"{name}_adapter.py"),
        "--size", size,
        "--iterations", str(iterations),
        "--warmup", str(warmup),
        "--repetitions", str(repetitions),
    ]
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        raise SystemExit(
            f"{name} adapter failed (exit {completed.returncode}):\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    try:
        return json.loads(completed.stdout)
    except ValueError as error:
        raise SystemExit(f"{name} adapter returned invalid JSON: {error}\n{completed.stdout}")


def yog_cli_results(yogc: Path, size: str, requests: list[dict],
                    iterations: int, warmup: int, repetitions: int) -> dict:
    corpus = CORPUS / f"{size}.yog"
    result = {
        "engine": "yog",
        "size": size,
        "boundary": "cli-process",
        "available": True,
        "executable": str(yogc),
        "requests": [],
    }
    for request in requests:
        command = [str(yogc), "check", str(corpus), request["actor"],
                   "can_access", request["resource"]]

        def invoke() -> str:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       encoding="utf-8", errors="replace")
            decision = completed.stdout.split("|", 1)[0].strip()
            if decision not in ("ALLOW", "DENY"):
                raise SystemExit(
                    f"yogc produced no decision (exit {completed.returncode}): "
                    f"{completed.stdout}{completed.stderr}"
                )
            return decision

        measurement, decision = measure(invoke, iterations, warmup, repetitions)
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
    return result


def find_bench() -> Path:
    candidates = [
        ROOT / "yog" / "build-release" / f"bench_yog{EXE}",
        ROOT / "yog" / "build" / f"bench_yog{EXE}",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit("bench_yog not found; build it with cmake")


def bench_json(bench: Path, arguments: list[str]) -> dict:
    completed = subprocess.run([str(bench), *arguments], capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        raise SystemExit(f"bench_yog failed: {completed.stderr}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    try:
        return json.loads(lines[-1])
    except (IndexError, ValueError) as error:
        raise SystemExit(f"bench_yog returned invalid JSON: {error}\n{completed.stdout}")


def yog_library_results(bench: Path, size: str, requests: list[dict],
                        iterations: int, compile_iterations: int) -> dict:
    corpus = CORPUS / f"{size}.yog"
    compile_row = bench_json(bench, ["compile", str(corpus),
                                     "--iterations", str(compile_iterations)])
    rows = []
    for request in requests:
        row = bench_json(bench, [
            "check", str(corpus), request["actor"], "can_access",
            request["resource"], "--iterations", str(iterations),
        ])
        require_decision(request["label"], request["expected"], row.get("decision"))
        rows.append({
            "label": request["label"],
            "expected": request["expected"],
            "decision": row.get("decision"),
            "mean_us": row.get("mean_us"),
            "p50_us": row.get("p50_us"),
            "p95_us": row.get("p95_us"),
            "p99_us": row.get("p99_us"),
            "max_us": row.get("max_us"),
            "throughput_per_s": row.get("throughput_per_s"),
            "samples": row.get("iterations"),
        })
    build = "release" if "build-release" in str(bench) else "debug"
    return {
        "engine": "yog",
        "size": size,
        "boundary": "c-library",
        "available": True,
        "build": build,
        "executable": str(bench),
        "compile": compile_row,
        "requests": rows,
        "note": "in-process C engine, compiled once then timed with bench_yog",
    }


def repo_path(value: str | Path) -> str:
    path = Path(value).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        pass
    try:
        return "~/" + path.relative_to(Path.home().resolve()).as_posix()
    except ValueError:
        return path.name


def sanitize(entry: dict) -> dict:
    """Make result artifacts relocatable before they are committed."""
    cleaned = dict(entry)
    if cleaned.get("executable"):
        cleaned["executable"] = repo_path(cleaned["executable"])
    translation = cleaned.get("translation")
    if translation:
        cleaned["translation"] = {
            key: (repo_path(value) if key in {"data", "policy", "entities", "model"} else value)
            for key, value in translation.items()
        }
    return cleaned


def engine_map(entries: list[dict] | dict) -> dict:
    if isinstance(entries, dict):
        return {name: sanitize(entry) for name, entry in entries.items()
                if entry and entry.get("available")}
    return {entry["engine"]: sanitize(entry) for entry in entries if entry.get("available")}


def pct_cell(entry: dict) -> str:
    if not entry or entry.get("p50_us") is None:
        return "n/a"
    return (f"{entry['p50_us']:,.0f} / {entry['p95_us']:,.0f} / "
            f"{entry['p99_us']:,.0f}")


def requests_by_label(entry: dict | None) -> dict:
    if not entry:
        return {}
    return {row["label"]: row for row in entry.get("requests", [])}


def markdown(comparison: dict) -> str:
    lines = [
        "# Cross-engine benchmark comparison",
        "",
        f"Generated: {comparison['generated_at']}",
        f"Commit: `{comparison['versions']['git_commit']}`",
        "",
        "Read this table by boundary. **cli-process** numbers include process",
        "startup and policy load; **library** numbers are in-process decisions.",
        "They are not interchangeable, and no result here is a general claim",
        "that one engine is faster than another.",
        "",
    ]

    for boundary, data in comparison["boundaries"].items():
        lines.append(f"## Boundary: `{boundary}`")
        lines.append("")
        lines.append(data["description"])
        lines.append("")
        for size in comparison["sizes"]:
            engines = data["sizes"].get(size, {})
            if not engines:
                continue
            lines.append(f"### {size}")
            lines.append("")
            rows = requests_by_label(next(iter(engine_map(engines).values()), None))
            names = [name for name in ("yog", "opa", "cedar", "casbin") if name in engines]
            header = "| request | " + " | ".join(names) + " |"
            lines.append(header)
            lines.append("| --- | " + " | ".join("---:" for _ in names) + " |")
            for label in rows:
                cells = []
                for name in names:
                    cells.append(pct_cell(requests_by_label(engines[name]).get(label)))
                lines.append(f"| {label} | " + " | ".join(cells) + " |")
            lines.append("")
            lines.append("Cells are p50 / p95 / p99 in microseconds. "
                         "All reported decisions matched the corpus.")
            config = comparison["config"]
            if boundary == "cli-process":
                lines.append(
                    f"N = {config['cli_iterations'][size]} samples per request per "
                    f"run, {config['repetitions']} runs; the cell is the median "
                    f"of runs. p99 is nearest-rank, so it equals the maximum "
                    f"when N < 100.")
            else:
                lines.append(
                    f"YOG: {config['yog_library_iterations'][size]} samples. "
                    f"Casbin: {config['casbin_iterations'][size]} samples x 2 runs. "
                    f"YOG library build: {comparison['versions'].get('library_build')}.")
            lines.append("")

    lines.extend([
        "## Versions and environment",
        "",
        "| item | value |",
        "| --- | --- |",
        f"| Python | {comparison['versions']['python']} |",
        f"| Platform | {comparison['versions']['platform']} |",
        f"| yogc | `{comparison['versions']['yogc']}` |",
    ])
    for name, version in comparison["versions"]["engines"].items():
        lines.append(f"| {name} | {version or 'unavailable'} |")
    lines.append("")
    lines.extend([
        "## What is not measured",
        "",
        "- Request rates under concurrent load; every sample is sequential.",
        "- Peak RSS for the OPA and Cedar child processes.",
        "- Casbin's numeric clearance clause, which its standard model cannot",
        "  express; the adapter records `numeric_clause: false`.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", default=["small", "medium", "large"],
                        choices=["small", "medium", "large"])
    parser.add_argument("--iterations", type=int, default=None,
                        help="samples per run; defaults depend on size")
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--yogc", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()

    if not (CORPUS / "requests.json").exists():
        raise SystemExit(f"missing {CORPUS / 'requests.json'}; run benchmarks/gen_corpus.py first")

    yogc = find_yogc(args.yogc)
    bench = find_bench()
    comparison = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "versions": {
            "git_commit": git_commit(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "yogc": repo_path(yogc),
            "bench_yog": repo_path(bench),
            "engines": {},
        },
        "sizes": args.sizes,
        "config": {
            "cli_iterations": {},
            "repetitions": args.repetitions,
            "warmup": args.warmup,
            "casbin_iterations": LIBRARY_ITERATIONS,
            "yog_library_iterations": YOG_LIBRARY_ITERATIONS,
        },
        "boundaries": {
            "cli-process": {
                "description": "Each sample spawns a process: policy compile/load, "
                               "startup, decision and output are all included.",
                "sizes": {},
            },
            "library": {
                "description": "In-process decisions. YOG is C and Casbin is Python, "
                               "so this is a cross-language comparison and is not "
                               "directly comparable with the CLI boundary.",
                "sizes": {},
            },
        },
    }

    for size in args.sizes:
        requests = load_requests(CORPUS, size)
        iterations = args.iterations or DEFAULT_ITERATIONS[size]
        comparison["config"]["cli_iterations"][size] = iterations
        cli_engines = [
            yog_cli_results(yogc, size, requests, iterations,
                            args.warmup, args.repetitions),
        ]
        for adapter in ("opa", "cedar"):
            cli_engines.append(run_adapter(adapter, size, iterations,
                                           args.warmup, args.repetitions))
        comparison["boundaries"]["cli-process"]["sizes"][size] = engine_map(cli_engines)

        casbin = run_adapter("casbin", size, LIBRARY_ITERATIONS[size], 10, 2)
        library = yog_library_results(bench, size, requests,
                                      YOG_LIBRARY_ITERATIONS[size],
                                      YOG_COMPILE_ITERATIONS[size])
        comparison["boundaries"]["library"]["sizes"][size] = engine_map([library, casbin])
        comparison["versions"]["library_build"] = library["build"]

        for name, entry in engine_map(cli_engines).items():
            comparison["versions"]["engines"].setdefault(name, entry.get("tool_version"))
        comparison["versions"]["engines"]["yog"] = (
            f"source {comparison['versions']['git_commit'][:7]} ({library['build']})")
        if casbin.get("available"):
            comparison["versions"]["engines"].setdefault("casbin", casbin.get("tool_version"))

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "versions.json").write_text(
        json.dumps(comparison["versions"], indent=2) + "\n", encoding="utf-8")
    (args.out / "comparison.json").write_text(
        json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    (args.out / "comparison.md").write_text(markdown(comparison), encoding="utf-8")
    print(f"wrote {args.out / 'comparison.json'}")
    print(f"wrote {args.out / 'comparison.md'}")
    print(f"wrote {args.out / 'versions.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
