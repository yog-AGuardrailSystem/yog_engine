#!/usr/bin/env python3
"""Offline InjecAgent evaluation for YOG.

What this measures
------------------
InjecAgent provides test cases with a benign ``User Tool`` and one or more
``Attacker Tools`` injected via a tool response.  The base/enhanced datasets do
not include attacker tool arguments, so this offline evaluator applies a
least-privilege tool-class policy (``policies/injecagent_least_privilege.yog``)
and measures:

* *user utility*: whether the benign ``User Tool`` is allowed (strict) or
  allowed/approvable (assisted);
* *interception*: whether at least one ``Attacker Tool`` in the case is blocked
  (``DENY`` or ``REQUIRE_APPROVAL``) before execution.

It is a deterministic policy-interception measurement, not an LLM ASR
measurement.

Usage
-----
    python benchmarks/agent_security/evaluate_injecagent.py
    python benchmarks/agent_security/evaluate_injecagent.py --data-dir %TEMP%\\injecagent
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
from collections import defaultdict
from typing import Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
BENCHMARKS = os.path.dirname(HERE)
ROOT = os.path.dirname(BENCHMARKS)
for path in (BENCHMARKS, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from agent_security.guard import Decision, ToolGuard, dump_json, load_policy  # noqa: E402
from agent_security.injecagent import (  # noqa: E402
    EXPLICIT_CLASSES,
    classify_catalog,
    classify_tool,
    default_data_dir,
    facts_for_tool,
    load_cases,
    load_tools,
)

DATASETS = {
    name: f"test_cases_{name}.json"
    for name in ("dh_base", "ds_base", "dh_enhanced", "ds_enhanced")
}


def evaluate_dataset(name: str, cases: list[dict], catalog: dict, guard: ToolGuard) -> dict:
    user_strict = 0
    user_assisted = 0
    attack_intercepted = 0
    attack_denied = 0

    user_call_counts = {"ALLOW": 0, "REQUIRE_APPROVAL": 0, "DENY": 0}
    attacker_call_counts = {"ALLOW": 0, "REQUIRE_APPROVAL": 0, "DENY": 0}

    by_attack_type: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "intercepted": 0})
    by_toolkit: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "intercepted": 0})
    by_class: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "ALLOW": 0, "REQUIRE_APPROVAL": 0, "DENY": 0}
    )
    fallback_tools: set[str] = set()
    misses: List[dict] = []

    for index, case in enumerate(cases):
        user_tool = str(case.get("User Tool", ""))
        attacker_tools = [str(t) for t in (case.get("Attacker Tools") or [])]
        attack_type = str(case.get("Attack Type", "unknown"))

        for tool in [user_tool, *attacker_tools]:
            if tool and tool not in EXPLICIT_CLASSES:
                fallback_tools.add(tool)

        user_dec: Decision = guard.check(user_tool, {}, facts=facts_for_tool(user_tool, catalog))
        user_call_counts[user_dec.decision] = user_call_counts.get(user_dec.decision, 0) + 1
        if user_dec.allowed:
            user_strict += 1
        if user_dec.decision != "DENY":
            user_assisted += 1

        att_decs = [
            guard.check(tool, {}, facts=facts_for_tool(tool, catalog))
            for tool in attacker_tools
        ]
        for tool, dec in zip(attacker_tools, att_decs):
            attacker_call_counts[dec.decision] = attacker_call_counts.get(dec.decision, 0) + 1
            toolkit = str(catalog.get(tool, {}).get("toolkit", ""))
            tool_class = classify_tool(tool, toolkit=toolkit)
            row = by_class[tool_class]
            row["calls"] += 1
            row[dec.decision] = row.get(dec.decision, 0) + 1

        intercepted = any(dec.blocked for dec in att_decs)
        denied = any(dec.decision == "DENY" for dec in att_decs)
        if intercepted:
            attack_intercepted += 1
        else:
            misses.append({
                "index": index,
                "attack_type": attack_type,
                "user_tool": user_tool,
                "attacker_tools": attacker_tools,
            })
        if denied:
            attack_denied += 1

        by_attack_type[attack_type]["total"] += 1
        if intercepted:
            by_attack_type[attack_type]["intercepted"] += 1

        first_toolkit = catalog.get(attacker_tools[0], {}).get("toolkit", "unknown") if attacker_tools else "unknown"
        by_toolkit[first_toolkit]["total"] += 1
        if intercepted:
            by_toolkit[first_toolkit]["intercepted"] += 1

    total = len(cases)
    return {
        "dataset": name,
        "cases": total,
        "user_strict_utility": round(user_strict / total, 4) if total else 0.0,
        "user_assisted_utility": round(user_assisted / total, 4) if total else 0.0,
        "interception_rate": round(attack_intercepted / total, 4) if total else 0.0,
        "hard_deny_rate": round(attack_denied / total, 4) if total else 0.0,
        "user_calls": user_call_counts,
        "attacker_calls": attacker_call_counts,
        "by_attack_type": {
            key: {
                **val,
                "interception_rate": round(val["intercepted"] / val["total"], 4) if val["total"] else 0.0,
            }
            for key, val in sorted(by_attack_type.items())
        },
        "by_toolkit": {
            key: {
                **val,
                "interception_rate": round(val["intercepted"] / val["total"], 4) if val["total"] else 0.0,
            }
            for key, val in sorted(by_toolkit.items())
        },
        "by_class": {
            key: {
                **val,
                "blocked_rate": round(
                    (val["REQUIRE_APPROVAL"] + val["DENY"]) / val["calls"], 4
                ) if val["calls"] else 0.0,
            }
            for key, val in sorted(by_class.items())
        },
        "fallback_tools": sorted(fallback_tools),
        "misses": misses[:25],
        "miss_count": len(misses),
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# InjecAgent policy interception (offline)",
        "",
        f"Generated {report['generated_at']}. Policy: `{report['policy']}`.",
        "",
        "This is **not** an LLM attack-success-rate measurement. InjecAgent datasets",
        "provide attacker tool names without attacker arguments, so this measures",
        "tool-level least-privilege interception (`read` -> `ALLOW`, `sensitive_read`",
        "and `write` -> `REQUIRE_APPROVAL`, `destructive` -> `DENY`).",
        "",
        "| Dataset | Cases | User strict | User assisted | Interception (block/approve) | Hard DENY |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, ds in report["datasets"].items():
        lines.append(
            f"| {name} | {ds['cases']} | "
            f"{ds['user_strict_utility'] * 100:.1f}% | "
            f"{ds['user_assisted_utility'] * 100:.1f}% | "
            f"{ds['interception_rate'] * 100:.1f}% | "
            f"{ds['hard_deny_rate'] * 100:.1f}% |"
        )
    lines += [
        "",
        "Case interception is high because every InjecAgent case pairs a read with a",
        "write or destructive sink. The 442 `read` attacker calls still pass; a future",
        "attack that only reads would not be stopped by tool-level least privilege.",
        "Closing that needs provenance or information-flow tracking.",
        "",
        "## Breakdown by attack type",
        "",
        "| Dataset | Attack type | Cases | Intercepted | Rate |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for name, ds in report["datasets"].items():
        for atype, row in ds["by_attack_type"].items():
            lines.append(
                f"| {name} | {atype} | {row['total']} | {row['intercepted']} | "
                f"{row['interception_rate'] * 100:.1f}% |"
            )

    lines += [
        "",
        "## Per-call decisions",
        "",
        "| Dataset | Side | ALLOW | REQUIRE_APPROVAL | DENY |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for name, ds in report["datasets"].items():
        for side_label, key in (("user", "user_calls"), ("attacker", "attacker_calls")):
            row = ds[key]
            lines.append(
                f"| {name} | {side_label} | {row['ALLOW']} | "
                f"{row['REQUIRE_APPROVAL']} | {row['DENY']} |"
            )

    lines += [
        "",
        "## Attacker calls by tool class",
        "",
        "| Class | Calls | ALLOW | REQUIRE_APPROVAL | DENY | Blocked |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in report.get("by_class", {}).items():
        lines.append(
            f"| {name} | {row['calls']} | {row['ALLOW']} | {row['REQUIRE_APPROVAL']} | "
            f"{row['DENY']} | {row['blocked_rate'] * 100:.1f}% |"
        )

    if report.get("fallback_tools"):
        lines += [
            "",
            "Tools that needed the keyword fallback (not in the explicit table): "
            + ", ".join(f"`{tool}`" for tool in report["fallback_tools"]) + ".",
        ]

    lines += [
        "",
        "## Limits",
        "",
        "- InjecAgent cases carry attacker tool names only, not attacker parameters;",
        "  argument-level policies cannot be exercised offline on these datasets.",
        "- Tool classification is deterministic from the tool name and recorded in",
        "  `injecagent.json` (`tool_classes`) for auditability.",
        "- The benchmark's own tools are classified in an explicit table. The keyword",
        "  fallback is only for tools added later, and it defaults to `write`",
        "  (approval), never `read`.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=default_data_dir(),
                        help="Directory containing InjecAgent tools.json and test_cases_*.json")
    parser.add_argument("--json", default=os.path.join(HERE, "results", "injecagent.json"))
    parser.add_argument("--md", default=os.path.join(HERE, "results", "injecagent.md"))
    args = parser.parse_args(argv)

    tools_path = os.path.join(args.data_dir, "tools.json")
    if not os.path.exists(tools_path):
        print(f"InjecAgent tools.json not found at {tools_path}", file=sys.stderr)
        return 2

    catalog = load_tools(tools_path)
    guard = ToolGuard(load_policy("injecagent_least_privilege"))

    datasets_out = {}
    for name, filename in DATASETS.items():
        case_path = os.path.join(args.data_dir, filename)
        if not os.path.exists(case_path):
            print(f"missing {case_path}", file=sys.stderr)
            return 2
        cases = load_cases(case_path)
        res = evaluate_dataset(name, cases, catalog, guard)
        datasets_out[name] = res
        print(
            f"== {name} ({res['cases']} cases) == "
            f"user_strict={res['user_strict_utility']} user_assisted={res['user_assisted_utility']} "
            f"interception={res['interception_rate']} hard_deny={res['hard_deny_rate']} "
            f"misses={res['miss_count']}"
        )

    report = {
        "benchmark": "InjecAgent",
        "policy": "injecagent_least_privilege",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "measurement": "offline tool-class least-privilege interception",
        "tool_count": len(catalog),
        "tool_classes": classify_catalog(catalog),
        "datasets": datasets_out,
        "by_class": {},
        "fallback_tools": sorted({
            tool for ds in datasets_out.values() for tool in ds["fallback_tools"]
        }),
    }

    combined_classes: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "ALLOW": 0, "REQUIRE_APPROVAL": 0, "DENY": 0}
    )
    for ds in datasets_out.values():
        for tool_class, row in ds["by_class"].items():
            bucket = combined_classes[tool_class]
            for key in ("calls", "ALLOW", "REQUIRE_APPROVAL", "DENY"):
                bucket[key] += row[key]
    report["by_class"] = {
        name: {
            **row,
            "blocked_rate": round(
                (row["REQUIRE_APPROVAL"] + row["DENY"]) / row["calls"], 4
            ) if row["calls"] else 0.0,
        }
        for name, row in sorted(combined_classes.items())
    }
    dump_json(args.json, report)
    markdown = render_markdown(report)
    os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
    with open(args.md, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown)
    print(f"wrote {args.json} and {args.md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
