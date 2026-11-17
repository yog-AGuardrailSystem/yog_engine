#!/usr/bin/env python3
"""Measure the three phases that a single number hides: cold, load and warm.

The earlier comparison reported one number per engine, which conflated process
startup, policy compilation, data loading and the decision itself.  This driver
reports them separately, at the same boundary for each engine:

* ``cold``  -- a fresh process loads the engine, compiles the policy and answers
  one request.  External wall time, so language runtime startup is included.
* ``load``  -- compile/parse/prepare only, inside a warm process.
* ``warm``  -- steady-state decision cost after a warm-up, inside one process.

It also measures a persistent OPA server (the deployment shape OPA is designed
for) over HTTP keep-alive, and compares it with the in-process Go SDK.

Every engine is measured on the feature-matched ``common`` profile by default.
Results are written to ``benchmarks/results/boundaries.json`` and ``.md``.

Usage:
    python benchmarks/boundaries.py [--profiles common] [--sizes small medium large]
                                    [--runs 10] [--iterations 500]
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
ADAPTERS = HERE / "adapters"
CORPUS = HERE / "generated"
RESULTS = HERE / "results"
TRANSLATIONS = RESULTS / "translations"
TMP = RESULTS / "tmp"
EXE = ".exe" if os.name == "nt" else ""

sys.path.insert(0, str(ADAPTERS))
sys.path.insert(0, str(ROOT / "bindings" / "python"))

import casbin_adapter  # noqa: E402
import cedar_adapter  # noqa: E402
import opa_adapter  # noqa: E402
from corpus import (build_model, corpus_file, load_requests, parse_facts)  # noqa: E402
from pin import pin_cpu  # noqa: E402
from stats import sample_runs, summarize_runs, summarize_with_ci  # noqa: E402

import yog as yog_binding  # noqa: E402


def folder(profile: str, size: str) -> str:
    return size if profile == "full" else f"common-{size}"


def find_opa() -> str | None:
    found = shutil.which("opa")
    return found if found else (str(ROOT / ".tools" / "opa.exe")
                                if (ROOT / ".tools" / "opa.exe").exists() else None)


def find_cedar() -> str | None:
    found = shutil.which("cedar")
    if found:
        return found
    local = Path.home() / ".cargo" / "bin" / ("cedar.exe" if os.name == "nt" else "cedar")
    return str(local) if local.exists() else None


def yogc() -> Path:
    return ROOT / "yog" / "build-release" / f"yogc{EXE}"


def bench_yog() -> Path:
    return ROOT / "yog" / "build-release" / f"bench_yog{EXE}"


def yog_rust() -> Path:
    return ROOT / "bindings" / "rust" / "target" / "release" / f"yog_bench{EXE}"


def opa_go() -> Path:
    return RESULTS / "bin" / f"opa-bench{EXE}"


def yog_go() -> Path:
    return RESULTS / "bin" / f"yog-go-bench{EXE}"


def cedar_rust() -> Path:
    return ADAPTERS / "cedar_rust" / "target" / "release" / f"cedar-bench{EXE}"


def yog_env() -> dict:
    env = os.environ.copy()
    libdir = str(ROOT / "yog" / "build-release")
    for key in ("PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[key] = libdir + os.pathsep + env.get(key, "")
    return env


def one_line_tsv(row: dict, target: Path) -> Path:
    target.write_text("\t".join([
        row["label"], row["actor"], row["action"], row["resource"], ""
    ]) + "\n", encoding="utf-8")
    return target


def decision_from_output(text: str) -> str:
    text = text.strip()
    if text.startswith("{"):
        payload = json.loads(text.splitlines()[0])
        return str(payload.get("decision", "UNKNOWN")).upper()
    first = text.splitlines()[0].strip() if text else ""
    if "|" in first:
        first = first.split("|", 1)[0].strip()
    first = first.upper()
    return first if first in ("ALLOW", "DENY") else "UNKNOWN"


def run_command(command: list[str], env: dict | None = None) -> tuple[str, int]:
    started = time.perf_counter_ns()
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", env=env)
    elapsed = time.perf_counter_ns() - started
    return decision_from_output(completed.stdout), elapsed


def cold_runs(builder, rows: list[dict], runs: int, env: dict | None = None) -> dict:
    table = {}
    for row in rows:
        samples = []
        for _ in range(runs):
            decision, elapsed = run_command(builder(row), env=env)
            if decision != row["expected"]:
                raise SystemExit(
                    f"cold decision mismatch for {row['label']}: "
                    f"expected {row['expected']}, got {decision}"
                )
            samples.append(elapsed)
        table[row["label"]] = summarize_runs([[value] for value in samples])
    return table


def harness_warm(command: list[str], rows: list[dict], runs: int,
                 iterations: int, warmup: int, env: dict | None = None) -> dict:
    per_label: dict[str, list[list[int]]] = {row["label"]: [] for row in rows}
    for _ in range(runs):
        completed = subprocess.run(
            command + ["--iterations", str(iterations), "--warmup", str(warmup)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        )
        if completed.returncode != 0:
            raise SystemExit(f"harness failed: {completed.stderr}")
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            per_label[payload["label"]].append(payload["samples_ns"])
    return {label: summarize_runs(samples) for label, samples in per_label.items()}


def harness_load(command: list[str], field: str, runs: int,
                 env: dict | None = None) -> dict:
    samples = []
    for _ in range(runs):
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env)
        if completed.returncode != 0:
            raise SystemExit(f"load harness failed: {completed.stderr}")
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        samples.append(payload[field])
    return summarize_runs([[value] for value in samples])


def bench_load(runs: int, corpus: Path, iterations: int) -> dict:
    samples = []
    for _ in range(runs):
        completed = subprocess.run(
            [str(bench_yog()), "compile", str(corpus), "--iterations", str(iterations)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        samples.append(int(payload["p50_us"] * 1000))
    return summarize_runs([[value] for value in samples])


def bench_warm(runs: int, corpus: Path, rows: list[dict], iterations: int) -> dict:
    table = {}
    for row in rows:
        per_run = []
        for _ in range(runs):
            completed = subprocess.run([
                str(bench_yog()), "check", str(corpus), row["actor"],
                row["action"], row["resource"], "--iterations", str(iterations),
            ], capture_output=True, text=True, encoding="utf-8", errors="replace")
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
            per_run.append(int(payload["p50_us"] * 1000))
        table[row["label"]] = summarize_runs([[value] for value in per_run])
    return table


def ensure_translations(profile: str, size: str) -> dict:
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


def opa_server_measure(opa: str, targets: dict, rows: list[dict],
                       runs: int, iterations: int, warmup: int) -> dict:
    port = 18181
    process = subprocess.Popen(
        [opa, "run", "--server", "--addr", f"127.0.0.1:{port}", "--log-level", "error"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        start = time.perf_counter_ns()
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request("GET", "/health")
                response = connection.getresponse()
                response.read()
                if response.status == 200:
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise SystemExit("OPA server did not become healthy")
        start_ns = time.perf_counter_ns() - start

        policy_text = (targets["opa"] / "policy.rego").read_text(encoding="utf-8")
        configure = time.perf_counter_ns()
        connection.request("PUT", "/v1/policies/yogbench", body=policy_text,
                           headers={"Content-Type": "text/plain"})
        response = connection.getresponse()
        response.read()
        if response.status not in (200, 204):
            raise SystemExit(f"OPA policy PUT failed: {response.status}")

        data = (targets["opa"] / "data.json").read_text(encoding="utf-8")
        connection.request("PUT", "/v1/data", body=data,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        if response.status not in (200, 204):
            raise SystemExit(f"OPA data PUT failed: {response.status}")
        configure_ns = time.perf_counter_ns() - configure

        table = {}
        for row in rows:
            body = json.dumps({"input": {"actor": row["actor"],
                                        "resource": row["resource"]}})
            for _ in range(warmup):
                connection.request("POST", "/v1/data/yogbench/decision", body=body,
                                   headers={"Content-Type": "application/json"})
                connection.getresponse().read()
            samples = []
            for _ in range(iterations):
                started = time.perf_counter_ns()
                connection.request("POST", "/v1/data/yogbench/decision", body=body,
                                   headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                payload = json.loads(response.read() or b"{}")
                samples.append(time.perf_counter_ns() - started)
                decision = str(payload.get("result", "UNKNOWN")).upper()
                if decision != row["expected"]:
                    raise SystemExit(
                        f"OPA server decision mismatch for {row['label']}: "
                        f"expected {row['expected']}, got {decision}"
                    )
            table[row["label"]] = summarize_with_ci(samples)
        connection.close()
        return {
            "start": summarize_runs([[start_ns]]),
            "configure": summarize_runs([[configure_ns]]),
            "requests": table,
            "ci_scope": "within-run (single server process)",
        }
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", default=["common"],
                        choices=["common", "full"])
    parser.add_argument("--sizes", nargs="+", default=["small", "medium", "large"],
                        choices=["small", "medium", "large"])
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--cold-runs", type=int, default=10)
    parser.add_argument("--pin-cpu", type=int, default=None,
                        help="pin the measurement and its children to one CPU")
    args = parser.parse_args()

    pin_note = pin_cpu(args.pin_cpu)

    for required, path in (("cargo", None), ("go", None)):
        if shutil.which(required) is None:
            raise SystemExit(f"{required} is required")
    for path, label in ((yogc(), "yogc"), (bench_yog(), "bench_yog"), (yog_rust(), "Rust YOG harness"),
                        (yog_go(), "Go YOG harness"),
                        (opa_go(), "Go OPA harness"), (cedar_rust(), "Rust Cedar harness")):
        if not path.exists():
            raise SystemExit(f"missing {label}: {path}")

    opa = find_opa()
    cedar = find_cedar()
    TMP.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "runs": args.runs,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "cold_runs": args.cold_runs,
            "ci": "95% percentile bootstrap over run medians",
            "platform": sys.platform,
            "cpu": pin_note,
        },
        "profiles": {},
    }

    for profile in args.profiles:
        report["profiles"][profile] = {}
        for size in args.sizes:
            print(f"measuring {profile}/{size}")
            corpus = corpus_file(CORPUS, profile, size)
            rows = load_requests(CORPUS, size, profile)
            targets = ensure_translations(profile, size)
            bench_tsv = TMP / f"bench-{profile}-{size}.tsv"
            bench_tsv.write_text("\n".join(
                "\t".join([row["label"], row["actor"], row["action"],
                           row["resource"], ""]) for row in rows
            ) + "\n", encoding="utf-8")

            entry: dict = {"cold": {}, "load": {}, "warm": {}}

            # ---- cold: fresh process per request ----
            entry["cold"]["yog-c-cli"] = cold_runs(
                lambda row: [str(yogc()), "check", str(corpus), row["actor"],
                             row["action"], row["resource"]], rows, args.cold_runs)
            entry["cold"]["yog-python"] = cold_runs(
                lambda row: [sys.executable, str(ADAPTERS / "cold_yog_python.py"),
                             str(corpus), row["actor"], row["resource"]],
                rows, args.cold_runs, env=yog_env())
            entry["cold"]["yog-rust"] = cold_runs(
                lambda row: [str(yog_rust()), "--policy", str(corpus),
                             "--requests", str(one_line_tsv(row, TMP / "one.tsv")),
                             "--iterations", "1", "--warmup", "0"],
                rows, args.cold_runs, env=yog_env())
            entry["cold"]["yog-go"] = cold_runs(
                lambda row: [str(yog_go()), "--policy", str(corpus),
                             "--requests", str(one_line_tsv(row, TMP / "one.tsv")),
                             "--iterations", "1", "--warmup", "0"],
                rows, args.cold_runs, env=yog_env())
            entry["cold"]["casbin"] = cold_runs(
                lambda row: [sys.executable, str(ADAPTERS / "cold_casbin.py"),
                             str(targets["casbin"] / "model.conf"),
                             str(targets["casbin"] / "policy.csv"),
                             row["actor"], row["resource"]], rows, args.cold_runs)

            if opa:
                input_path = TMP / "opa-input.json"

                def opa_cold(row):
                    input_path.write_text(json.dumps({
                        "actor": row["actor"], "resource": row["resource"]}) + "\n")
                    return [opa, "eval", "-d", str(targets["opa"] / "data.json"),
                            "-d", str(targets["opa"] / "policy.rego"),
                            "-i", str(input_path), "-f", "raw",
                            "data.yogbench.decision"]

                entry["cold"]["opa-cli"] = cold_runs(opa_cold, rows, args.cold_runs)
                entry["cold"]["opa-go"] = cold_runs(
                    lambda row: [str(opa_go()), "--data", str(targets["opa"] / "data.json"),
                                 "--policy", str(targets["opa"] / "policy.rego"),
                                 "--requests", str(one_line_tsv(row, TMP / "one.tsv")),
                                 "--iterations", "1", "--warmup", "0"],
                    rows, args.cold_runs)

            if cedar:
                request_path = TMP / "cedar-request.json"

                def cedar_cold(row):
                    request_path.write_text(json.dumps({
                        "principal": f'User::"{row["actor"]}"',
                        "action": 'Action::"can_access"',
                        "resource": f'Resource::"{row["resource"]}"',
                        "context": {},
                    }) + "\n")
                    return [cedar, "authorize",
                            "--policies", str(targets["cedar"] / "policy.cedar"),
                            "--entities", str(targets["cedar"] / "entities.json"),
                            "--request-json", str(request_path)]

                entry["cold"]["cedar-cli"] = cold_runs(cedar_cold, rows, args.cold_runs)
                entry["cold"]["cedar-rust"] = cold_runs(
                    lambda row: [str(cedar_rust()),
                                 "--policy", str(targets["cedar"] / "policy.cedar"),
                                 "--entities", str(targets["cedar"] / "entities.json"),
                                 "--requests", str(one_line_tsv(row, TMP / "one.tsv")),
                                 "--iterations", "1", "--warmup", "0"],
                    rows, args.cold_runs)

            # ---- load: compile/prepare only ----
            entry["load"]["yog-c"] = bench_load(args.runs, corpus, 20)
            source = corpus.read_text(encoding="utf-8")
            entry["load"]["yog-python"] = summarize_runs(sample_runs(
                lambda: yog_binding.Yog(source), iterations=10, warmup=1, runs=args.runs))
            entry["load"]["yog-rust"] = harness_load(
                [str(yog_rust()), "--mode", "load", "--policy", str(corpus)],
                "compile_ns", args.runs, env=yog_env())
            entry["load"]["yog-go"] = harness_load(
                [str(yog_go()), "--mode", "load", "--policy", str(corpus)],
                "compile_ns", args.runs, env=yog_env())

            from casbin import Enforcer  # type: ignore
            model_path = str(targets["casbin"] / "model.conf")
            policy_path = str(targets["casbin"] / "policy.csv")
            entry["load"]["casbin"] = summarize_runs(sample_runs(
                lambda: Enforcer(model_path, policy_path), iterations=10, warmup=1,
                runs=args.runs))
            entry["load"]["opa-go"] = harness_load(
                [str(opa_go()), "--mode", "load", "--data", str(targets["opa"] / "data.json"),
                 "--policy", str(targets["opa"] / "policy.rego")],
                "prepare_ns", args.runs)
            entry["load"]["cedar-rust"] = harness_load(
                [str(cedar_rust()), "--mode", "load",
                 "--policy", str(targets["cedar"] / "policy.cedar"),
                 "--entities", str(targets["cedar"] / "entities.json")],
                "load_ns", args.runs)

            # ---- warm: steady-state decisions ----
            entry["warm"]["yog-c"] = bench_warm(args.runs, corpus, rows, 2000)
            policy = yog_binding.Yog(source)
            entry["warm"]["yog-python"] = {
                row["label"]: summarize_runs(sample_runs(
                    lambda row=row: policy.check(row["actor"], row["action"], row["resource"]),
                    args.iterations, args.warmup, args.runs))
                for row in rows
            }
            enforcer = Enforcer(model_path, policy_path)
            entry["warm"]["casbin"] = {
                row["label"]: summarize_runs(sample_runs(
                    lambda row=row: "ALLOW" if enforcer.enforce(
                        row["actor"], row["resource"], row["action"]) else "DENY",
                    args.iterations, args.warmup, args.runs))
                for row in rows
            }
            entry["warm"]["yog-rust"] = harness_warm(
                [str(yog_rust()), "--policy", str(corpus), "--requests", str(bench_tsv)],
                rows, args.runs, args.iterations, args.warmup, env=yog_env())
            entry["warm"]["yog-go"] = harness_warm(
                [str(yog_go()), "--policy", str(corpus), "--requests", str(bench_tsv)],
                rows, args.runs, args.iterations, args.warmup, env=yog_env())
            entry["warm"]["opa-go"] = harness_warm(
                [str(opa_go()), "--data", str(targets["opa"] / "data.json"),
                 "--policy", str(targets["opa"] / "policy.rego"),
                 "--requests", str(bench_tsv)],
                rows, args.runs, args.iterations, args.warmup)
            entry["warm"]["cedar-rust"] = harness_warm(
                [str(cedar_rust()), "--policy", str(targets["cedar"] / "policy.cedar"),
                 "--entities", str(targets["cedar"] / "entities.json"),
                 "--requests", str(bench_tsv)],
                rows, args.runs, args.iterations, args.warmup)

            # ---- persistent OPA service ----
            if opa:
                entry["service"] = {"opa-http": opa_server_measure(
                    opa, targets, rows, args.runs, args.iterations, args.warmup)}

            report["profiles"][profile][size] = entry

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "boundaries.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Cold, load and warm boundaries",
        "",
        f"Generated: {report['generated_at']}",
        "",
        f"Each number is the median of {args.runs} independent runs; brackets are a",
        "95% percentile bootstrap interval over the run medians. Warm measurements",
        f"use {args.iterations} calls per run after {args.warmup} warm-up calls.",
        "Cold measurements spawn a fresh process per request.",
        f"CPU: {pin_note}.",
        "",
    ]
    for profile, sizes in report["profiles"].items():
        lines.append(f"## Profile: `{profile}`")
        lines.append("")
        for size, entry in sizes.items():
            lines.append(f"### {size}")
            lines.append("")
            labels = [row["label"] for row in load_requests(CORPUS, size, profile)]
            for phase in ("cold", "warm"):
                lines.append(f"**{phase}** — p50 µs [95% CI]")
                lines.append("")
                engines = list(entry[phase])
                lines.append("| engine | " + " | ".join(labels) + " |")
                lines.append("| --- | " + " | ".join("---:" for _ in labels) + " |")
                for engine in engines:
                    cells = []
                    for label in labels:
                        item = entry[phase][engine].get(label)
                        cells.append(
                            f"{item['p50_us']:.1f} [{item['ci_low_us']:.1f}, "
                            f"{item['ci_high_us']:.1f}]" if item else "n/a")
                    lines.append(f"| {engine} | " + " | ".join(cells) + " |")
                lines.append("")
            lines.append("**load** — p50 µs [95% CI]")
            lines.append("")
            lines.append("| engine | compile / prepare |")
            lines.append("| --- | ---: |")
            for engine, item in entry["load"].items():
                lines.append(
                    f"| {engine} | {item['p50_us']:.1f} "
                    f"[{item['ci_low_us']:.1f}, {item['ci_high_us']:.1f}] |")
            lines.append("")
            service = entry.get("service", {}).get("opa-http")
            if service:
                cells = " | ".join(
                    f"{service['requests'][label]['p50_us']:.1f} "
                    f"[{service['requests'][label]['ci_low_us']:.1f}, "
                    f"{service['requests'][label]['ci_high_us']:.1f}]"
                    for label in labels)
                lines.append("**persistent OPA server** — p50 µs [95% CI]")
                lines.append("")
                lines.append("| engine | " + " | ".join(labels) + " |")
                lines.append("| --- | " + " | ".join("---:" for _ in labels) + " |")
                lines.append(f"| opa-http | {cells} |")
                lines.append("")
                lines.append(
                    f"Server start to healthy: {service['start']['p50_us'] / 1000:.0f} ms; "
                    f"policy+data configure: {service['configure']['p50_us'] / 1000:.1f} ms.")
                lines.append("")
    (RESULTS / "boundaries.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {RESULTS / 'boundaries.json'}")
    print(f"wrote {RESULTS / 'boundaries.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
