"""Interactive REPL and trace debugger for YOG policies.

Usage:
    python -m yog_platform repl [POLICY_FILE]
"""
from __future__ import annotations

import json
import shlex
import sys
from typing import Dict, List, Optional

from . import analysis
from .pdp import ReferencePDP


class ReplSession:
    """Stateful interactive YOG policy debugging session."""

    def __init__(self, source: str = "version 2\n"):
        self.source: str = source
        self.pdp: Optional[ReferencePDP] = None
        self.facts: List[dict] = []
        self.last_result: Optional[dict] = None
        self._compile(source)

    def _compile(self, source: str) -> str:
        try:
            self.pdp = ReferencePDP(source)
            self.source = source
            return "compiled ok"
        except Exception as exc:
            return f"compile error: {exc}"

    def eval_line(self, line: str) -> str:
        text = line.strip()
        if not text:
            return ""
        if text in (":quit", ":q", "exit", "quit"):
            raise EOFError()
        if text in (":help", ":h"):
            return (
                "Commands:\n"
                "  :load FILE                  load a .yog policy file\n"
                "  :fact PRED ARG1 [ARG2 ...]  add a session fact\n"
                "  :clear-facts                clear session facts\n"
                "  :facts                      list session facts\n"
                "  :analyze                    run static analysis (A001-A013)\n"
                "  :trace                      show last decision trace/reason\n"
                "  :check ACTOR ACT RES [JSON] evaluate a request (or plain: ACTOR ACT RES)\n"
                "  :quit                       exit"
            )
        if text.startswith(":load "):
            path = text[6:].strip()
            with open(path, encoding="utf-8") as handle:
                return self._compile(handle.read())
        if text == ":clear-facts":
            self.facts.clear()
            return "cleared facts"
        if text == ":facts":
            return json.dumps(self.facts, indent=2)
        if text.startswith(":fact "):
            parts = shlex.split(text[6:])
            if len(parts) < 2:
                return "usage: :fact PRED ARG1 [ARG2 ...]"
            args = []
            for p in parts[1:]:
                if p == "true":
                    args.append(True)
                elif p == "false":
                    args.append(False)
                else:
                    try:
                        args.append(int(p))
                    except ValueError:
                        args.append(p)
            self.facts.append({"predicate": parts[0], "args": args})
            return f"added fact {parts[0]}({', '.join(repr(a) for a in args)})"
        if text == ":analyze":
            findings = analysis.analyze(self.source)
            if not findings:
                return "0 finding(s)"
            return "\n".join(
                f"line {f['line']}: {f['severity']} {f['code']}: {f['message']}"
                for f in findings
            )
        if text == ":trace":
            if self.last_result is None:
                return "no evaluation yet"
            return json.dumps(self.last_result, indent=2)

        if text.startswith(":check "):
            text = text[7:].strip()

        parts = shlex.split(text)
        if len(parts) < 3:
            return "expected: ACTOR ACTION RESOURCE [ARGS_JSON] (or :help)"
        actor, action, resource = parts[0], parts[1], parts[2]
        args_obj: Dict = {}
        if len(parts) >= 4:
            args_obj = json.loads(" ".join(parts[3:]))
        if self.pdp is None:
            return "no compiled policy loaded"
        req = {
            "actor": actor,
            "action": action,
            "resource": resource,
            "args": {"input": args_obj},
            "facts": list(self.facts),
        }
        res = self.pdp.check(req)
        self.last_result = res
        decision = res.get("decision", "DENY")
        reason = res.get("reason", "")
        obs = res.get("obligations") or []
        out = f"{decision} | {reason}"
        if obs:
            out += f" | obligations={json.dumps(obs)}"
        return out


def run_repl(policy_path: Optional[str] = None) -> int:
    source = "version 2\n"
    if policy_path:
        with open(policy_path, encoding="utf-8") as handle:
            source = handle.read()
    session = ReplSession(source)
    print("YOG interactive REPL (:help for commands, :quit to exit)")
    while True:
        try:
            line = input("yog> ")
            out = session.eval_line(line)
            if out:
                print(out)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
