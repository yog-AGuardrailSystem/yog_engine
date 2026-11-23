"""A Claude Code ``PreToolUse`` hook that enforces a YOG policy.

Claude Code runs the hook before each tool call, sending a JSON event on stdin::

    {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/work", ...}

and reads a decision from stdout.  Mapping (fail closed):

==================  ===========================================================
YOG decision        hook output
==================  ===========================================================
ALLOW               nothing (exit 0): Claude Code's own permission rules still apply, so a policy ALLOW never
                    grants more than the user's settings already do
DENY                ``permissionDecision: "deny"`` with the reason
REQUIRE_APPROVAL    ``permissionDecision: "ask"``: Claude Code prompts the user
any error           ``permissionDecision: "deny"``
==================  ===========================================================

Configure it in ``.claude/settings.json``::

    {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command",
        "command": "python -m yog_platform.claude_hook --policy path/to/guard.yog"}]}]}}

Obligations are handled by the gateway; a policy used here should use only ``audit`` (give ``--audit FILE``),
``rate_limit`` and ``max_output_bytes`` is not applicable to a pre-tool hook and is ignored when unconfigured.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .gateway import Gateway

# How each Claude Code tool's input is analysed.  Anything not listed is still sent to the policy
# (its input stays under input.*), so the policy can allow or deny it by name.
TOOLS = {
    "Bash": {"extract": [("command", "shell")]},
    "WebFetch": {"extract": [("url", "http")], "taints_context": True},
    "WebSearch": {"taints_context": True},
}


def _decision(reason: str, kind: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                   "permissionDecisionReason": reason}}


def handle_event(event: dict, gateway: Gateway) -> Optional[dict]:
    """Returns the hook output dict, or None to leave Claude Code's normal flow untouched."""
    if event.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    tool, arguments = event.get("tool_name"), event.get("tool_input")
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        return _decision("YOG: malformed tool event", "deny")
    agent = f"claude-code:{event.get('session_id', 'session')}"
    auth = gateway.authorize(agent, tool, arguments)
    if auth.status == "allowed":
        # run the post-call handlers that matter to the hook (taint tracking) as soon as we let it through
        for after in auth.after:
            try:
                after("")
            except Exception:
                pass
        return None
    if auth.status == "approval_required":
        return _decision("YOG policy: this call needs your approval (" + auth.reason + ")", "ask")
    return _decision(f"YOG policy: {auth.reason or 'denied'}", "deny")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True, help="a .yog policy file")
    parser.add_argument("--yogc", help="use the C engine (path to yogc) instead of the Python reference")
    parser.add_argument("--sidecar", help="ask a running sidecar (http://host:port) instead of evaluating locally")
    parser.add_argument("--audit", help="hash-chained audit log file (needed if the policy uses `obligation audit`)")
    parser.add_argument("--stage", default="dev")
    args = parser.parse_args(argv)

    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        if args.sidecar:
            from .pdp import HttpPDP
            pdp = HttpPDP(args.sidecar)
        else:
            policy_text = open(args.policy, encoding="utf-8").read()
            if args.yogc:
                from .engine import make_engine
                import tempfile
                pdp = make_engine(policy_text, tempfile.mkdtemp(prefix="yog-hook-"), yogc_path=args.yogc)
            else:
                from .pdp import ReferencePDP
                pdp = ReferencePDP(policy_text)
        audit = None
        if args.audit:
            from .audit import AuditLog
            audit = AuditLog(args.audit)
        env = {"stage": args.stage, "cwd": event.get("cwd") if isinstance(event.get("cwd"), str) else ""}
        output = handle_event(event, Gateway(pdp, tools=TOOLS, env=env, audit=audit, ask_user=True))
    except Exception as exc:                                  # a broken guard must block, not wave through
        output = _decision(f"YOG guard error: {type(exc).__name__}: {exc}", "deny")
    if output is not None:
        print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
