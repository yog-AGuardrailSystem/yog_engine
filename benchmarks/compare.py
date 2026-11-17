#!/usr/bin/env python3
"""Fair, same-runtime in-process comparison of YOG with three other engines.

The de-biasing rule is simple: compare engines that run in the **same language
runtime**, in process, through their normal interface, on a feature-matched
corpus.  Every pairing below therefore has the same runtime cost structure:

* ``python-in-process`` -- YOG through its ctypes binding vs Casbin's Python
  enforcer.  Both run in CPython.
* ``rust-in-process``   -- YOG through its safe Rust wrapper vs the Cedar Rust
  SDK.  Both run in the same Rust binary shape.
* ``go-in-process``     -- YOG through its Go binding (syscall/cgo over the C
  ABI) vs the OPA Go SDK.  The YOG side pays an FFI boundary; that cost is part
  of the comparison and is called out explicitly.
* ``c-reference``       -- YOG's native C harness.  This is the engine's best
  case, not a same-runtime pairing, and is reported only as context.

The corpus is the feature-matched ``common`` profile: admin role, team
membership, resource ownership and a public flag.  The numeric clearance clause
of the ``full`` profile is excluded because Casbin's standard model cannot
express it; the measured cost of that gap is reported separately in
``equivalence.md``.

Every engine must return the expected decision for every request, or the run
aborts.  Each cell is the median of ``--runs`` independent runs; the bracket is
a 95% percentile bootstrap interval over the run medians.

Usage:
    python benchmarks/compare.py [--profile common|full]
                                 [--sizes small medium large]
                                 [--runs 10] [--iterations 500] [--warmup 50]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
ADAPTERS = HERE / "adapters"
CORPUS = HERE / "generated"
RESULTS = HERE / "results"
TRANSLATIONS = RESULTS / "translations"
BIN = RESULTS / "bin"
TMP = RESULTS / "tmp"
EXE = ".exe" if os.name == "nt" else ""

sys.path.insert(0, str(ADAPTERS))
sys.path.insert(0, str(ROOT / "bindings" / "python"))

import casbin_adapter  # noqa: E402
import cedar_adapter  # noqa: E402
import opa_adapter  # noqa: E402
from corpus import (build_model, corpus_file, load_requests, parse_facts)  # noqa: E402
from pin import pin_cpu  # noqa: E402
from stats import require_decision, sample_runs, summarize_runs  # noqa: E402

import yog as yog_binding  # noqa: E402

PROFILES = ("common",)
BOUNDARIES = {
    "python-in-process": {
        "description": "YOG-Python (ctypes) and Casbin both run in CPython. "
                       "Native runtime: same.",
        "engines": ["yog-python", "casbin"],
    },
    "rust-in-process": {
        "description": "YOG-Rust (safe wrapper) and the Cedar Rust SDK both run "
                       "in a Rust process. Native runtime: same.",
        "engines": ["yog-rust", "cedar-rust"],
    },
    "go-in-process": {
        "description": "YOG-Go calls the C ABI via syscall/cgo; OPA is the Go "
                       "SDK. Both run in a Go process, but only the YOG side "
                       "pays an FFI boundary. Read the two as bounds, not as a "
                       "pure engine comparison.",
        "engines": ["yog-go", "opa-go"],
    },
    "c-reference": {
        "description": "YOG's native C harness. This is the engine's best case "
                       "and is cross-language against every other row; it is "
                       "context, not fairness evidence.",
        "engines": ["yog-c"],
    },
}


def folder(profile: str, size: str) -> str:
    return size if profile == "full" else f"common-{size}"


def repo_path(value: str | Path) -> str:
    path = Path(value).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def git_commit() -> str:
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def yog_env() -> dict:
    env = os.environ.copy()
    libdir = str(ROOT / "yog" / "build-release")
    for key in ("PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[key] = libdir + os.pathsep + env.get(key, "")
    return env


def tool_version(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
        text = (completed.stdout or completed.stderr).strip().splitlines()
        return text[0].strip() if text else "unknown"
    except OSError:
        return "unknown"


def opa_version() -> str:
    for candidate in (shutil.which("opa"), ROOT / ".tools" / "opa.exe"):
        if candidate and Path(candidate).exists():
            completed = subprocess.run([str(candidate), "version"], capture_output=True,
                                       text=True, encoding="utf-8", errors="replace")
            for line in (completed.stdout or completed.stderr).splitlines():
                if line.strip():
                    return line.strip()
    mod = ADAPTERS / "opa_go" / "go.mod"
    if mod.exists():
        for line in mod.read_text(encoding="utf-8").splitlines():
            if "open-policy-agent/opa v" in line:
                return line.split()[-1] + " (Go SDK)"
    return "unknown"


def harness_paths() -> dict[str, Path]:
    return {
        "yog-rust": ROOT / "bindings" / "rust" / "target" / "release" / f"yog_bench{EXE}",
        "cedar-rust": ADAPTERS / "cedar_rust" / "target" / "release" / f"cedar-bench{EXE}",
        "yog-go": BIN / f"yog-go-bench{EXE}",
        "opa-go": BIN / f"opa-bench{EXE}",
        "yog-c": ROOT / "yog" / "build-release" / f"bench_yog{EXE}",
    }


def ensure_harnesses(paths: dict[str, Path]) -> None:
    missing = [name for name, path in paths.items() if not path.exists()]
    if "yog-rust" in missing or "cedar-rust" in missing:
        raise SystemExit(
            "missing Rust harnesses; build bindings/rust and "
            "benchmarks/adapters/cedar_rust with cargo build --release"
        )
    if "yog-go" in missing:
        raise SystemExit("missing yog-go-bench; run go build in benchmarks/adapters/yog_go")
    if "opa-go" in missing:
        raise SystemExit("missing opa-bench; run go build in benchmarks/adapters/opa_go")
    if "yog-c" in missing:
        raise SystemExit("missing bench_yog; build the C project first")


def ensure_translations(profile: str, size: str) -> dict[str, Path]:
    corpus = corpus_file(CORPUS, profile, size)
    model = build_model(parse_facts(corpus))
    targets = {
        "opa": TRANSLATIONS / "opa" / folder(profile, size),
        "cedar": TRANSLATIONS / "cedar" / folder(profile, size),
        "casbin": TRANSLATIONS / "casbin" / folder(profile, size),
    }
    for target in targets.values():
        target.mkdir(parents=True, exist_ok=True)
    opa_adapter.write_translation(model, targets["opa"], profile)
    cedar_adapter.write_translation(model, targets["cedar"], profile)
    casbin_adapter.write_translation(model, targets["casbin"])
    return targets


def request_tsv(rows: list[dict], target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(
        "\t".join([row["label"], row["actor"], row["action"], row["resource"], ""])
        for row in rows
    ) + "\n", encoding="utf-8")
    return target


def harness_table(command: list[str], rows: list[dict], runs: int,
                  iterations: int, warmup: int,
                  env: dict | None = None) -> dict[str, dict]:
    collected: dict[str, list[list[int]]] = {row["label"]: [] for row in rows}
    decisions: dict[str, str] = {}
    for _ in range(runs):
        completed = subprocess.run(
            command + ["--iterations", str(iterations), "--warmup", str(warmup)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env,
        )
        if completed.returncode != 0:
            raise SystemExit(f"harness failed: {completed.stderr}")
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            collected[payload["label"]].append(payload["samples_ns"])
            decisions[payload["label"]] = payload["decision"]
    for row in rows:
        require_decision(row["label"], row["expected"], decisions[row["label"]])
    return {label: summarize_runs(samples) for label, samples in collected.items()}


def bench_c_table(bench: Path, corpus: Path, rows: list[dict], runs: int,
                  iterations: int) -> dict[str, dict]:
    table: dict[str, list[list[int]]] = {row["label"]: [] for row in rows}
    for row in rows:
        for _ in range(runs):
            completed = subprocess.run([
                str(bench), "check", str(corpus), row["actor"], row["action"],
                row["resource"], "--iterations", str(iterations),
            ], capture_output=True, text=True, encoding="utf-8", errors="replace")
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
            require_decision(row["label"], row["expected"], payload.get("decision"))
            table[row["label"]].append([int(payload["p50_us"] * 1000)])
    return {label: summarize_runs(samples) for label, samples in table.items()}


def python_table(engine: str, source: str, rows: list[dict], runs: int,
                 iterations: int, warmup: int, targets: dict[str, Path]) -> dict[str, dict]:
    if engine == "yog-python":
        policy = yog_binding.Yog(source)
        table = {}
        for row in rows:
            samples = sample_runs(
                lambda row=row: policy.check(row["actor"], row["action"], row["resource"]),
                iterations, warmup, runs)
            require_decision(row["label"], row["expected"], policy.check(
                row["actor"], row["action"], row["resource"]))
            table[row["label"]] = summarize_runs(samples)
        return table

    from casbin import Enforcer  # type: ignore

    enforcer = Enforcer(str(targets["casbin"] / "model.conf"),
                        str(targets["casbin"] / "policy.csv"))
    table = {}
    for row in rows:
        def invoke(row=row) -> str:
            return "ALLOW" if enforcer.enforce(
                row["actor"], row["resource"], row["action"]) else "DENY"

        samples = sample_runs(invoke, iterations, warmup, runs)
        require_decision(row["label"], row["expected"], invoke())
        table[row["label"]] = summarize_runs(samples)
    return table


def load_python(engine: str, source: str, targets: dict[str, Path],
                runs: int) -> dict:
    if engine == "yog-python":
        return summarize_runs(sample_runs(
            lambda: yog_binding.Yog(source), iterations=10, warmup=1, runs=runs))
    from casbin import Enforcer  # type: ignore
    return summarize_runs(sample_runs(
        lambda: Enforcer(str(targets["casbin"] / "model.conf"),
                         str(targets["casbin"] / "policy.csv")),
        iterations=10, warmup=1, runs=runs))


def harness_load(command: list[str], field: str, runs: int,
                 env: dict | None = None, scale: int = 1) -> dict:
    samples = []
    for _ in range(runs):
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env)
        if completed.returncode != 0:
            raise SystemExit(f"load harness failed: {completed.stderr}")
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        samples.append([int(payload[field] * scale)])
    return summarize_runs(samples)


def cell(entry: dict | None) -> str:
    if not entry:
        return "n/a"
    return (f"{entry['p50_us']:,.1f} "
            f"[{entry['ci_low_us']:,.1f}, {entry['ci_high_us']:,.1f}]")


def markdown(report: dict) -> str:
    lines = [
        "# Fair cross-engine comparison",
        "",
        f"Generated: {report['generated_at']}",
        f"Commit: `{report['versions']['git_commit']}`",
        "",
        "Each boundary compares engines that run in the **same language runtime**,",
        "in process. Cells are p50 microseconds with a 95% percentile bootstrap",
        "interval over independent run medians. Every engine returned the expected",
        "decision for every request; a mismatch would have aborted the run.",
        "",
        f"Corpus profile: `{report['profile']}`. Config: {report['config']['runs']} "
        f"runs x {report['config']['iterations']} calls after "
        f"{report['config']['warmup']} warm-up calls per request.",
        f"CPU: {report['config']['cpu']}.",
        "",
    ]

    for boundary, data in report["boundaries"].items():
        lines.append(f"## Boundary: `{boundary}`")
        lines.append("")
        lines.append(data["description"])
        lines.append("")
        for size, engines in data["sizes"].items():
            if not engines:
                continue
            lines.append(f"### {size}")
            lines.append("")
            rows = report["requests"][size]
            names = list(engines)
            lines.append("| request | " + " | ".join(names) + " |")
            lines.append("| --- | " + " | ".join("---:" for _ in names) + " |")
            for label in rows:
                cells = [cell(engines[name]["requests"].get(label)) for name in names]
                lines.append(f"| {label} | " + " | ".join(cells) + " |")
            lines.append("")
            lines.append("Load time (compile / parse / prepare), p50 µs [95% CI]:")
            lines.append("")
            lines.append("| engine | load |")
            lines.append("| --- | ---: |")
            for name in names:
                lines.append(f"| {name} | {cell(engines[name]['load'])} |")
            lines.append("")

    lines.extend([
        "## How to read this",
        "",
        "- Same-runtime pairs are the evidence. The `c-reference` boundary is the",
        "  C engine's best case and is not a fairness claim.",
        "- The `go-in-process` pair is asymmetric: YOG crosses an FFI boundary and",
        "  OPA does not. Treat the two numbers as bounds on the engine difference.",
        "- The corpus is the feature-matched `common` profile. Casbin cannot express",
        "  the numeric clearance clause; `equivalence.md` records the measured cost",
        "  of that gap on the `full` profile.",
        "- Agreeing on this corpus is evidence, not proof of language equivalence.",
        "",
        "## Versions and environment",
        "",
        "| item | value |",
        "| --- | --- |",
        f"| Python | {report['versions']['python']} |",
        f"| Platform | {report['versions']['platform']} |",
        f"| Machine | {report['versions']['machine']} |",
    ])
    for name, version in report["versions"]["engines"].items():
        lines.append(f"| {name} | {version} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="common")
    parser.add_argument("--sizes", nargs="+", default=["small", "medium", "large"],
                        choices=["small", "medium", "large"])
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--pin-cpu", type=int, default=None,
                        help="pin the measurement and its children to one CPU")
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()

    pin_note = pin_cpu(args.pin_cpu)

    for required in ("cargo", "go"):
        if shutil.which(required) is None:
            raise SystemExit(f"{required} is required for the comparison")
    try:
        import casbin  # noqa: F401
    except ImportError:  # pragma: no cover - dependency missing
        raise SystemExit("casbin is required: pip install casbin")

    paths = harness_paths()
    ensure_harnesses(paths)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "versions": {
            "git_commit": git_commit(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "engines": {
                "yog": f"source {git_commit()[:7]} (shared library + bindings)",
                "casbin": tool_version([sys.executable, "-c",
                                        "import importlib.metadata as m; print('casbin', m.version('casbin'))"]),
                "opa": opa_version(),
                "cedar": "cedar-policy 4.14.1 (Rust SDK)",
            },
        },
        "config": {
            "runs": args.runs,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "ci": "95% percentile bootstrap over run medians",
            "cpu": pin_note,
        },
        "requests": {},
        "boundaries": {name: {"description": data["description"], "sizes": {}}
                       for name, data in BOUNDARIES.items()},
    }

    for size in args.sizes:
        corpus = corpus_file(CORPUS, args.profile, size)
        if not corpus.exists():
            raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
        rows = load_requests(CORPUS, size, args.profile)
        report["requests"][size] = [row["label"] for row in rows]
        targets = ensure_translations(args.profile, size)
        tsv = request_tsv(rows, TMP / f"compare-{args.profile}-{size}.tsv")
        source = corpus.read_text(encoding="utf-8")

        warm: dict[str, dict] = {}
        load: dict[str, dict] = {}

        warm["yog-python"] = python_table("yog-python", source, rows, args.runs,
                                          args.iterations, args.warmup, targets)
        load["yog-python"] = load_python("yog-python", source, targets, args.runs)
        warm["casbin"] = python_table("casbin", source, rows, args.runs,
                                      args.iterations, args.warmup, targets)
        load["casbin"] = load_python("casbin", source, targets, args.runs)

        warm["yog-rust"] = harness_table(
            [str(paths["yog-rust"]), "--policy", str(corpus), "--requests", str(tsv)],
            rows, args.runs, args.iterations, args.warmup, env=yog_env())
        load["yog-rust"] = harness_load(
            [str(paths["yog-rust"]), "--mode", "load", "--policy", str(corpus)],
            "compile_ns", args.runs, env=yog_env())

        warm["cedar-rust"] = harness_table(
            [str(paths["cedar-rust"]),
             "--policy", str(targets["cedar"] / "policy.cedar"),
             "--entities", str(targets["cedar"] / "entities.json"),
             "--requests", str(tsv)],
            rows, args.runs, args.iterations, args.warmup)
        load["cedar-rust"] = harness_load(
            [str(paths["cedar-rust"]), "--mode", "load",
             "--policy", str(targets["cedar"] / "policy.cedar"),
             "--entities", str(targets["cedar"] / "entities.json")],
            "load_ns", args.runs)

        warm["yog-go"] = harness_table(
            [str(paths["yog-go"]), "--policy", str(corpus), "--requests", str(tsv)],
            rows, args.runs, args.iterations, args.warmup, env=yog_env())
        load["yog-go"] = harness_load(
            [str(paths["yog-go"]), "--mode", "load", "--policy", str(corpus)],
            "compile_ns", args.runs, env=yog_env())

        warm["opa-go"] = harness_table(
            [str(paths["opa-go"]),
             "--data", str(targets["opa"] / "data.json"),
             "--policy", str(targets["opa"] / "policy.rego"),
             "--requests", str(tsv)],
            rows, args.runs, args.iterations, args.warmup)
        load["opa-go"] = harness_load(
            [str(paths["opa-go"]), "--mode", "load",
             "--data", str(targets["opa"] / "data.json"),
             "--policy", str(targets["opa"] / "policy.rego")],
            "prepare_ns", args.runs)

        warm["yog-c"] = bench_c_table(paths["yog-c"], corpus, rows, args.runs,
                                      args.iterations)
        load["yog-c"] = harness_load(
            [str(paths["yog-c"]), "compile", str(corpus), "--iterations", "20"],
            "p50_us", args.runs, scale=1000)

        for boundary, data in BOUNDARIES.items():
            entry = {}
            for name in data["engines"]:
                entry[name] = {
                    "requests": warm[name],
                    "load": load[name],
                }
            report["boundaries"][boundary]["sizes"][size] = entry
        print(f"measured {args.profile}/{size}")

    for boundary in report["boundaries"].values():
        for engines in boundary["sizes"].values():
            for entry in engines.values():
                for summary in [entry["load"], *entry["requests"].values()]:
                    summary.pop("run_p50_us", None)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "versions.json").write_text(
        json.dumps(report["versions"], indent=2) + "\n", encoding="utf-8")
    (args.out / "comparison.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.out / "comparison.md").write_text(markdown(report), encoding="utf-8")
    print(f"wrote {args.out / 'comparison.json'}")
    print(f"wrote {args.out / 'comparison.md'}")
    print(f"wrote {args.out / 'versions.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
