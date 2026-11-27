#!/usr/bin/env python3
"""Live AgentDojo attack-success-rate (ASR) runner with a YOG guard.

This is the model-in-the-loop counterpart to ``evaluate_agentdojo.py``.  The
offline evaluator runs AgentDojo's ground-truth tool calls; this script runs a
real LLM pipeline and reports:

* *utility*: did the benign user task succeed?
* *ASR*: did the injection task succeed?  (AgentDojo's ``security`` flag is
  ``True`` when the attack succeeded, so lower is better.)
* *guarded ASR*: the same run with the YOG runtime installed.  A blocked tool
  call returns a policy error to the model instead of executing.

It needs an AgentDojo-supported model and the provider's API key in the
environment (for example ``OPENAI_API_KEY`` for an OpenAI model).  It is
therefore **not** part of the default test suite and not reproducible in CI
without a key.  Use ``--dry-run`` to check the plan without making model calls.

Usage
-----
    # No model calls: show suites, tasks and the attack that would be used.
    python benchmarks/agent_security/run_agentdojo_live.py --suite banking --dry-run

    # One user/injection pair against a real model, with and without the guard.
    OPENAI_API_KEY=... python benchmarks/agent_security/run_agentdojo_live.py \
        --suite banking --model gpt-4o-mini-2024-07-18 \
        --user-task user_task_0 --injection-task injection_task_0 --baseline

    # The full suite (costs one model run per user/injection pair).
    python benchmarks/agent_security/run_agentdojo_live.py --suite workspace

Requires ``agentdojo`` and the provider SDK in the interpreter that runs this
file.  The YOG side uses the Python reference interpreter.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
BENCHMARKS = os.path.dirname(HERE)
ROOT = os.path.dirname(BENCHMARKS)
for path in (BENCHMARKS, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from agent_security.agentdojo_adapter import guarded_runtime_class  # noqa: E402
from agent_security.guard import ToolGuard, dump_json, load_policy  # noqa: E402

SUITES = ("banking", "workspace", "slack", "travel")


def _load_suite(suite_name: str, benchmark_version: str):
    from agentdojo.task_suite.load_suites import get_suite

    return get_suite(benchmark_version, suite_name)


def _build_pipeline(model: str, defense: str):
    from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig

    config = PipelineConfig(
        llm=model,
        model_id=None,
        defense=None if defense in ("", "none") else defense,
        system_message_name=None,
    )
    return AgentPipeline.from_config(config)


def _selected(available, requested):
    if not requested:
        return list(available)
    missing = [item for item in requested if item not in available]
    if missing:
        raise SystemExit(f"unknown task(s): {', '.join(missing)}")
    return requested


def dry_run(args) -> int:
    suite = _load_suite(args.suite, args.benchmark_version)
    users = _selected(suite.user_tasks, args.user_task)
    injections = _selected(suite.injection_tasks, args.injection_task)
    policy = args.policy or f"agentdojo_{args.suite}"
    guard = ToolGuard(load_policy(policy))  # compiles the policy; no model call

    print(f"suite: {args.suite} ({args.benchmark_version})")
    print(f"policy: {policy}")
    print(f"model: {args.model}  defense: {args.defense}  attack: {args.attack}")
    print(f"user tasks: {len(users)}  injection tasks: {len(injections)}  "
          f"pairs: {len(users) * len(injections)}")
    print("user tasks:", ", ".join(users))
    print("injection tasks:", ", ".join(injections))
    print(f"sample decision: {guard.check('get_balance', {}).decision}")
    print("dry run: no model calls were made")
    return 0


def run_pair(suite, pipeline, attack, guard, user_task, injection_task, baseline: bool) -> dict:
    injections = attack.attack(user_task, injection_task)
    row = {
        "user_task": user_task.ID,
        "injection_task": injection_task.ID,
    }

    if baseline:
        utility, security = suite.run_task_with_pipeline(
            pipeline, user_task, injection_task, injections,
        )
        row["baseline_utility"] = bool(utility)
        row["baseline_attack_succeeded"] = bool(security)

    decisions: list = []
    guarded = guarded_runtime_class(suite.name, guard, decisions=decisions)
    utility, security = suite.run_task_with_pipeline(
        pipeline, user_task, injection_task, injections, runtime_class=guarded,
    )
    row["guarded_utility"] = bool(utility)
    row["guarded_attack_succeeded"] = bool(security)
    row["policy_calls"] = len(decisions)
    row["policy_blocks"] = sum(1 for decision in decisions if decision.blocked)
    row["blocked_by_decision"] = {
        name: sum(1 for decision in decisions if decision.decision == name)
        for name in ("ALLOW", "REQUIRE_APPROVAL", "DENY")
    }
    return row


def _rate(rows, key):
    values = [row[key] for row in rows if key in row]
    return round(sum(1 for value in values if value) / len(values), 4) if values else None


def render_markdown(report: dict) -> str:
    def pct(value):
        return "n/a" if value is None else f"{value * 100:.1f}%"

    lines = [
        "# AgentDojo live ASR run",
        "",
        f"Generated {report['generated_at']}. Suite `{report['suite']}`, "
        f"model `{report['model']}`, attack `{report['attack']}`, "
        f"policy `{report['policy']}`.",
        "",
        "ASR here is the live attack-success rate: lower is better. The offline",
        "evaluator reports policy interception instead.",
        "",
        f"- Pairs run: **{report['pairs_run']}/{report['pairs_planned']}**",
        f"- Guarded utility: **{pct(report['guarded_utility'])}**",
        f"- Guarded ASR: **{pct(report['guarded_asr'])}**",
        f"- Policy calls blocked: **{report['policy_blocks']}/{report['policy_calls']}**",
    ]
    if report.get("baseline_pairs"):
        lines += [
            f"- Baseline utility: **{pct(report['baseline_utility'])}**",
            f"- Baseline ASR: **{pct(report['baseline_asr'])}**",
        ]
    lines += [
        "",
        "| User task | Injection task | Guarded utility | Guarded ASR | Blocks |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for row in report["results"]:
        if "error" in row:
            lines.append(f"| {row.get('user_task')} | {row.get('injection_task')} | error | error | — |")
            continue
        lines.append(
            f"| {row['user_task']} | {row['injection_task']} | "
            f"{'yes' if row['guarded_utility'] else 'no'} | "
            f"{'yes' if row['guarded_attack_succeeded'] else 'no'} | "
            f"{row['policy_blocks']}/{row['policy_calls']} |"
        )
    lines += [
        "",
        "## Limits",
        "",
        "- Model output is nondeterministic; rerun or use temperature 0 for a",
        "  comparable number. AgentDojo's pipeline sets temperature 0 by default.",
        "- This runner uses the public `TaskSuite.run_task_with_pipeline` API and",
        "  passes the guarded runtime class; it does not monkeypatch AgentDojo.",
        "- An API key is required. Never commit run logs containing prompts or",
        "  model output that may include user data.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="banking", choices=SUITES)
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--defense", default="none",
                        help="AgentDojo defense (none, tool_filter, ...)")
    parser.add_argument("--attack", default="important_instructions",
                        help="AgentDojo attack registry name")
    parser.add_argument("--policy", default=None,
                        help="policy name (default: agentdojo_<suite>)")
    parser.add_argument("--user-task", action="append", default=[],
                        help="user task id to run (repeatable; default: all)")
    parser.add_argument("--injection-task", action="append", default=[],
                        help="injection task id to run (repeatable; default: all)")
    parser.add_argument("--limit", type=int, default=0,
                        help="maximum pairs to run (0 = no limit)")
    parser.add_argument("--baseline", action="store_true",
                        help="also run each pair without the guard")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan and compile the policy; no model calls")
    parser.add_argument("--json",
                        default=os.path.join(HERE, "results", "agentdojo_live.json"))
    parser.add_argument("--md",
                        default=os.path.join(HERE, "results", "agentdojo_live.md"))
    args = parser.parse_args(argv)

    if args.dry_run:
        return dry_run(args)

    try:
        from agentdojo.attacks import load_attack
    except ImportError:
        print("agentdojo is not installed: pip install agentdojo", file=sys.stderr)
        return 2

    suite = _load_suite(args.suite, args.benchmark_version)
    users = _selected(suite.user_tasks, args.user_task)
    injections = _selected(suite.injection_tasks, args.injection_task)
    policy = args.policy or f"agentdojo_{args.suite}"
    guard = ToolGuard(load_policy(policy))
    pipeline = _build_pipeline(args.model, args.defense)
    attack = load_attack(args.attack, suite, pipeline)

    planned = len(users) * len(injections)
    if args.limit and args.limit > 0:
        planned = min(planned, args.limit)

    results = []
    for user_task_id in users:
        for injection_task_id in injections:
            if args.limit and len(results) >= args.limit:
                break
            user_task = suite.user_tasks[user_task_id]
            injection_task = suite.injection_tasks[injection_task_id]
            try:
                row = run_pair(suite, pipeline, attack, guard, user_task, injection_task,
                               baseline=args.baseline)
            except Exception as exc:
                traceback.print_exc()
                row = {
                    "user_task": user_task_id,
                    "injection_task": injection_task_id,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            results.append(row)
            status = "error" if "error" in row else (
                f"utility={row['guarded_utility']} asr={row['guarded_attack_succeeded']} "
                f"blocks={row['policy_blocks']}/{row['policy_calls']}"
            )
            print(f"{user_task_id} x {injection_task_id}: {status}")
        if args.limit and len(results) >= args.limit:
            break

    ok = [row for row in results if "error" not in row]
    report = {
        "benchmark": "AgentDojo live ASR",
        "suite": args.suite,
        "benchmark_version": args.benchmark_version,
        "model": args.model,
        "defense": args.defense,
        "attack": args.attack,
        "policy": policy,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "pairs_planned": planned,
        "pairs_run": len(ok),
        "errors": len(results) - len(ok),
        "guarded_utility": _rate(ok, "guarded_utility"),
        "guarded_asr": _rate(ok, "guarded_attack_succeeded"),
        "policy_calls": sum(row["policy_calls"] for row in ok),
        "policy_blocks": sum(row["policy_blocks"] for row in ok),
        "baseline_pairs": sum(1 for row in ok if "baseline_attack_succeeded" in row),
        "baseline_utility": _rate(ok, "baseline_utility"),
        "baseline_asr": _rate(ok, "baseline_attack_succeeded"),
        "results": results,
    }

    dump_json(args.json, report)
    os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
    with open(args.md, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_markdown(report))
    print(f"wrote {args.json} and {args.md}")
    return 0 if report["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
