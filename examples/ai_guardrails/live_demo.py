#!/usr/bin/env python3
"""Presenter demo: an agent's tool calls hit a fail-closed policy decision.

This is a *demo*, not a test suite and not a benchmark. It runs a small set of
scenarios through the compiled C engine and prints the decision, the reason and
the exact command, so an audience can see the enforcement point rather than a
summary of it.

Every scenario states the decision the guardrail must produce. Unknown actions
and malformed context must be DENY: an evaluation error is not an allow.

Usage
-----
    python examples/ai_guardrails/live_demo.py
    python examples/ai_guardrails/live_demo.py --step      # pause between acts
    python examples/ai_guardrails/live_demo.py --bench     # append the scoreboard
    python examples/ai_guardrails/live_demo.py --no-color  # plain terminal

Exit code is 0 when every scenario produced its expected decision.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_YOGC = ROOT / "yog" / "build-release" / ("yogc.exe" if os.name == "nt" else "yogc")

# (actor, action, resource, context, expected)
ACTS: list[tuple[str, str, list[tuple[str, str, str, str | None, str]]]] = [
    (
        "1. A shell command from an agent",
        "shell_commands.yog",
        [
            ("agent_sandbox", "can_run_command", "cmd_ls", None, "ALLOW"),
            ("agent_support", "can_run_command", "cmd_ls", None, "DENY"),
            ("agent_admin", "can_run_command", "cmd_rm_rf", None, "DENY"),
            ("agent_admin", "can_run_command", "cmd_curl_pipe_sh", None, "DENY"),
        ],
    ),
    (
        "2. A write to the production database",
        "database_access.yog",
        [
            ("svc_app", "can_write", "db_stage", None, "ALLOW"),
            ("svc_app", "can_write", "db_prod", None, "DENY"),
            ("svc_admin", "can_write", "db_prod", None, "ALLOW"),
            ("guest", "can_write", "db_stage", None, "DENY"),
        ],
    ),
    (
        "3. Money movement, amount supplied by the trusted caller",
        "financial_transactions.yog",
        [
            ("fin_agent", "can_transfer", "acct_ops",
             "fact amount(acct_ops, 4000)", "ALLOW"),
            ("fin_agent", "can_transfer", "acct_ops",
             "fact amount(acct_ops, 9000)", "DENY"),
            ("fin_agent", "can_transfer", "acct_ops", None, "DENY"),
            ("fin_agent", "can_transfer", "acct_scam",
             "fact amount(acct_scam, 1)", "DENY"),
        ],
    ),
    (
        "4. Fail closed: an unknown action and a malformed context",
        "shell_commands.yog",
        [
            ("agent_admin", "can_browse_web", "https://example.test", None, "DENY"),
            ("fin_agent", "can_transfer", "acct_ops",
             "rule amount(X):\n    p(X)", "DENY"),
        ],
    ),
]

BENCH_ROWS = [
    # boundary, corpus, request, yog label, yog us, competitor label, competitor us, note
    ("warm", "large", "admin allow", "YOG-Python", 8.7, "Casbin", 132.4, ""),
    ("warm", "large", "guest deny", "YOG-Python", 364.2, "Casbin", 1350.8, ""),
    ("warm", "large", "admin allow", "YOG-Rust", 1.8, "Cedar", 10.5, "YOG wins"),
    ("warm", "large", "guest deny", "YOG-Rust", 345.4, "Cedar", 8.8, "Cedar ~40x"),
    ("warm", "large", "team join", "YOG-Rust", 121.8, "Cedar", 10.4, "Cedar ~12x"),
    ("warm", "large", "admin allow", "YOG-Go", 2.0, "OPA Go", 1467.7, ""),
    ("warm", "large", "guest deny", "YOG-Go", 347.2, "OPA Go", 1464.1, ""),
]

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return self.paint(text, BOLD)

    def dim(self, text: str) -> str:
        return self.paint(text, DIM)


def find_yogc(requested: Path | None) -> Path | None:
    if requested is not None:
        return requested if requested.exists() else None
    for candidate in (
        DEFAULT_YOGC,
        ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc"),
    ):
        if candidate.exists():
            return candidate
    return None


def run_check(yogc: Path, policy: Path, actor: str, action: str,
              resource: str, context: str | None) -> tuple[str, str]:
    command = [str(yogc), "check", str(policy), actor, action, resource]
    if context:
        command += ["--context", context]
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    if completed.returncode in (0, 3):
        out = completed.stdout.strip()
        decision, _, reason = out.partition("|")
        return decision.strip(), reason.strip()
    # Any other exit is an engine error; the caller must fail closed.
    return "DENY", f"engine error treated as DENY: {completed.stderr.strip()}"


def banner(title: str, pal: Palette) -> None:
    print()
    print(pal.paint(title, CYAN + BOLD))
    print(pal.dim("-" * min(len(title) + 6, 78)))


def print_scoreboard(pal: Palette) -> None:
    print()
    print(pal.paint("Measured scoreboard (not a demo input; from committed results)", CYAN + BOLD))
    print(pal.dim("Windows 11, MSVC Release, pinned to CPU 0, 10 runs x 500 calls, "
                  "95% bootstrap CI; warm, same-runtime in-process."))
    print()
    header = f"  {'boundary':8s} {'corpus':6s} {'request':13s} {'YOG side':10s} {'us':>9s}   {'competitor':12s} {'us':>9s}  note"
    print(pal.bold(header))
    for boundary, corpus, request, yn, yv, cn, cv, note in BENCH_ROWS:
        line = (f"  {boundary:8s} {corpus:6s} {request:13s} {yn:10s} {yv:9.1f}   "
                f"{cn:12s} {cv:9.1f}  {note}")
        print(line)
    print()
    print(pal.dim("Reading: YOG wins the first-match path and loses large deny/join to "
                  "Cedar."))
    print(pal.dim("Cedar is ~40x faster on large deny, ~12x on large team join. "
                  "OPA prepares a large policy ~34x faster than YOG compiles it."))
    print(pal.dim("No general superiority claim is made. See docs/BENCHMARKS.md."))


def load_results_note() -> str | None:
    """Optionally confirm the scoreboard is consistent with comparison.json."""
    results = ROOT / "benchmarks" / "results" / "comparison.json"
    if not results.exists():
        return None
    try:
        data = json.loads(results.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    generated = data.get("generated_at", "unknown")
    commit = data.get("versions", {}).get("git_commit", "unknown")[:7]
    return f"comparison.json generated {generated} at commit {commit}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yogc", type=Path, default=None,
                        help="path to yogc (default: Release build, then Debug build)")
    parser.add_argument("--step", action="store_true",
                        help="wait for Enter between acts")
    parser.add_argument("--bench", action="store_true",
                        help="append the measured scoreboard")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = parser.parse_args()

    use_color = (not args.no_color) and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    pal = Palette(use_color)

    yogc = find_yogc(args.yogc)
    if yogc is None:
        print("yogc not found. Build the Release tree first:\n"
              "  cmake -S yog -B yog/build-release -DCMAKE_BUILD_TYPE=Release\n"
              "  cmake --build yog/build-release", file=sys.stderr)
        return 2

    print(pal.bold("YOG guardrail demo"))
    print(f"engine: {yogc.relative_to(ROOT) if yogc.is_relative_to(ROOT) else yogc}")
    print(pal.dim("contract: deny > allow > default deny; unknown action = DENY; "
                  "engine error = DENY"))

    failures = 0
    total = 0
    for title, policy_name, scenarios in ACTS:
        policy = HERE / policy_name
        banner(title, pal)
        print(pal.dim(f"policy: examples/ai_guardrails/{policy_name}"))
        for actor, action, resource, context, expected in scenarios:
            decision, reason = run_check(yogc, policy, actor, action, resource, context)
            total += 1
            ok = decision == expected
            failures += 0 if ok else 1
            command = f"yogc check {policy_name} {actor} {action} {resource}"
            if context:
                shown = context if "\n" not in context else "<malformed context>"
                command += f' --context "{shown}"'
            print()
            print(f"  {pal.dim('$')} {command}")
            colour = GREEN if decision == "ALLOW" else RED
            marker = "" if ok else pal.paint(f"   expected {expected}", YELLOW)
            print(f"    {pal.paint(decision, colour + BOLD)}  {reason}{marker}")
        if args.step and title != ACTS[-1][0]:
            try:
                input(pal.dim("\n  press Enter for the next act "))
            except EOFError:
                pass

    if args.bench:
        print_scoreboard(pal)
        note = load_results_note()
        if note:
            print(pal.dim(note))

    print()
    if failures:
        print(pal.paint(f"{failures} of {total} scenarios did not match the specified decision",
                        RED + BOLD))
        return 1
    print(pal.paint(f"all {total} scenarios enforced as specified", GREEN + BOLD))
    return 0


if __name__ == "__main__":
    sys.exit(main())
