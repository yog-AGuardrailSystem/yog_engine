#!/usr/bin/env python3
"""Run the four AI-guardrail policies through the C engine.

This is an enforcement demo, not a benchmark: every scenario states the
decision a guardrail must produce, including the fail-closed cases.  A denied
request exits 3 from `yogc check`; an evaluation error must also be treated as
denied by the caller.

Usage:
    python examples/ai_guardrails/enforce_demo.py [--yogc PATH]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_YOGC = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")

SCENARIOS = [
    ("shell: unsandboxed read", "shell_commands.yog", "agent_support", "can_run_command",
     "cmd_ls", None, "DENY"),
    ("shell: sandboxed safe command", "shell_commands.yog", "agent_sandbox",
     "can_run_command", "cmd_ls", None, "ALLOW"),
    ("shell: destructive overrides allow", "shell_commands.yog", "agent_sandbox",
     "can_run_command", "cmd_rm_rf", None, "DENY"),
    ("shell: destructive overrides admin", "shell_commands.yog", "agent_admin",
     "can_run_command", "cmd_curl_pipe_sh", None, "DENY"),
    ("database: staging write", "database_access.yog", "svc_app", "can_write",
     "db_stage", None, "ALLOW"),
    ("database: production write denied", "database_access.yog", "svc_app",
     "can_write", "db_prod", None, "DENY"),
    ("database: admin production write", "database_access.yog", "svc_admin",
     "can_write", "db_prod", None, "ALLOW"),
    ("database: unknown agent", "database_access.yog", "guest", "can_write",
     "db_stage", None, "DENY"),
    ("api: public scope", "api_calls.yog", "agent_research", "can_call_api",
     "api_search", None, "ALLOW"),
    ("api: internal scope not granted", "api_calls.yog", "agent_research",
     "can_call_api", "api_billing", None, "DENY"),
    ("api: admin internal scope", "api_calls.yog", "agent_admin", "can_call_api",
     "api_billing", None, "ALLOW"),
    ("api: unknown agent", "api_calls.yog", "agent_unknown", "can_call_api",
     "api_status", None, "DENY"),
    ("finance: within limit", "financial_transactions.yog", "fin_agent",
     "can_transfer", "acct_ops", "fact amount(acct_ops, 4000)", "ALLOW"),
    ("finance: over limit", "financial_transactions.yog", "fin_agent",
     "can_transfer", "acct_ops", "fact amount(acct_ops, 9000)", "DENY"),
    ("finance: no amount proof", "financial_transactions.yog", "fin_agent",
     "can_transfer", "acct_ops", None, "DENY"),
    ("finance: blocked account", "financial_transactions.yog", "fin_agent",
     "can_transfer", "acct_scam", "fact amount(acct_scam, 1)", "DENY"),
    ("fail-closed: unknown action", "shell_commands.yog", "agent_admin",
     "can_browse_web", "https://example.test", None, "DENY"),
    ("fail-closed: malformed context", "financial_transactions.yog", "fin_agent",
     "can_transfer", "acct_ops", "rule amount(X):\n    p(X)", "DENY"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=DEFAULT_YOGC)
    args = parser.parse_args()

    if not args.yogc.exists():
        print(f"yogc not found: {args.yogc}\n"
              f"Build it first:  cmake -S yog -B yog/build && cmake --build yog/build",
              file=sys.stderr)
        return 2

    failures = 0
    for label, policy, actor, action, resource, context, expected in SCENARIOS:
        command = [str(args.yogc), "check", str(HERE / policy), actor, action, resource]
        if context:
            command += ["--context", context]
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if completed.returncode in (0, 3):
            actual = completed.stdout.split("|", 1)[0].strip()
            detail = completed.stdout.strip()
        else:
            # An evaluation error is not an allow: the caller must fail closed.
            actual = "DENY"
            detail = f"error treated as DENY: {completed.stderr.strip()}"
        ok = actual == expected
        failures += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {label:42s} {actual:5s} (expected {expected})")
        if not ok:
            print(f"     {detail}")

    if failures:
        print(f"\n{failures} guardrail scenario(s) failed")
        return 1
    print(f"\nall {len(SCENARIOS)} guardrail scenarios enforced as specified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
