"""The gateway: the enforcement point between an agent and its tools.

YOG decides; the gateway enforces.  Everything the agent can influence is kept apart from everything the
gateway knows to be true:

* ``actor``, ``env``, ``state`` and ``now`` are set by the gateway, never copied from agent input;
* the agent's raw arguments live under the ``input.`` namespace, and extractor results under ``sql.``,
  ``shell.``, ``http.`` and ``k8s.``, so an agent cannot forge a fact such as ``shell.rm_rf = false`` by
  naming one of its arguments that way.

Fail closed throughout: an unreachable decision point, an error result, an unknown decision, an
obligation the gateway cannot perform, or a downstream failure all end in a refusal, never in running the
tool.  Tool output is returned marked ``untrusted``; it never grants permission.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from . import extractors
from .approvals import ApprovalError, ApprovalManager, request_hash

ACTION = "run_tool"


class Refusal(Exception):
    """An obligation (or other condition) that means the call must not run."""


@dataclass
class Authorization:
    status: str                        # "allowed" | "denied" | "approval_required"
    decision: str = "DENY"
    reason: str = ""
    request: dict = field(default_factory=dict)
    request_hash: str = ""
    obligations: list = field(default_factory=list)
    approval: Optional[dict] = None
    approver: Optional[str] = None
    after: list = field(default_factory=list)      # post-execution obligation handlers


class RateLimiter:
    """A sliding-window counter store.  Counters live here, outside YOG, owned by the gateway."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock, self._lock, self._hits = clock, threading.Lock(), {}

    def hit(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = self._clock()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


class Gateway:
    def __init__(self, pdp, *, tools: Optional[Mapping[str, Mapping]] = None, downstream: Optional[Callable] = None,
                 approvals: Optional[ApprovalManager] = None, env: Optional[Mapping[str, Any]] = None,
                 state_provider: Optional[Callable[[], Optional[dict]]] = None, audit=None,
                 limiter: Optional[RateLimiter] = None, clock: Callable[[], float] = time.time,
                 ask_user: bool = False):
        """``tools`` maps a tool name to ``{"extract": [(argument, extractor), ...]}``.

        ``ask_user``: when there is no approval service, report REQUIRE_APPROVAL as ``approval_required`` so the
        host (for example a Claude Code hook) can ask a human, instead of refusing the call outright."""
        self._pdp = pdp
        self._tools = dict(tools or {})
        self._downstream = downstream
        self._approvals = approvals
        self._env = dict(env or {})
        self._state = state_provider
        self._audit = audit
        self._limiter = limiter or RateLimiter(clock)
        self._clock = clock
        self._ask_user = ask_user
        self._tainted: set = set()                     # agents whose context has seen untrusted content
        self._handlers: dict[str, Callable] = {"audit": self._ob_audit, "rate_limit": self._ob_rate_limit,
                                               "max_output_bytes": self._ob_max_output}

    # ------------------------------------------------------------ building the request
    def build_request(self, agent: str, tool: str, arguments: dict) -> dict:
        args: dict = {"input": arguments}
        for argument, kind in (self._tools.get(tool) or {}).get("extract", []):
            args.update(extractors.extract(kind, arguments, argument))
        env = dict(self._env)
        env["context_tainted"] = agent in self._tainted        # set by the gateway, never by the agent
        request = {"actor": agent, "action": ACTION, "resource": tool, "args": args,
                   "env": env, "now": int(self._clock())}
        state = self._state() if self._state else None
        if state:
            request["state"] = state
        return request

    # ---------------------------------------------------------------- authorising
    def authorize(self, agent: str, tool: str, arguments: dict, approval_token: Optional[str] = None) -> Authorization:
        """Decides whether this call may run.  Performs the *before* obligations; the caller runs the tool and
        then each handler in ``after``."""
        if not isinstance(agent, str) or not isinstance(tool, str) or not isinstance(arguments, dict):
            return self._record(Authorization("denied", reason="malformed tool call"))
        try:
            request = self.build_request(agent, tool, arguments)
        except Exception as exc:                          # an extractor or state failure is a refusal
            return self._record(Authorization("denied", reason=f"could not prepare the request: {type(exc).__name__}"))
        digest = request_hash(request)
        auth = Authorization("denied", request=request, request_hash=digest)
        try:
            result = self._pdp.check(request)
        except Exception as exc:
            auth.reason = f"policy decision unavailable: {type(exc).__name__}"
            return self._record(auth)
        if not isinstance(result, dict):
            auth.reason = "bad policy response"
            return self._record(auth)
        decision = result.get("decision")
        auth.decision = decision if decision in ("ALLOW", "DENY", "REQUIRE_APPROVAL") else "DENY"
        auth.reason = str(result.get("reason", ""))
        if "error" in result or decision not in ("ALLOW", "DENY", "REQUIRE_APPROVAL"):
            auth.decision = "DENY"
            auth.reason = auth.reason or "policy returned an error"
            return self._record(auth)
        auth.obligations = result.get("obligations", []) if isinstance(result.get("obligations"), list) else []
        policy_hash = result.get("policy_hash", "")

        if decision == "DENY":
            return self._record(auth)
        if decision == "REQUIRE_APPROVAL":
            if not approval_token or self._approvals is None:
                if self._approvals is None:
                    if self._ask_user:
                        auth.status = "approval_required"        # the host asks a human; nothing is created here
                        return self._record(auth)
                    auth.reason = "approval is required but no approval service is configured"
                    return self._record(auth)
                approval = self._approvals.create(request, policy_hash)
                auth.status = "approval_required"
                auth.approval = {"approval_id": approval.approval_id, "request_hash": approval.request_hash,
                                 "expires_at": approval.expires_at}
                return self._record(auth)
            try:
                auth.approver = self._approvals.consume(approval_token, request, policy_hash)
            except ApprovalError as exc:
                auth.reason = f"approval refused: {exc}"
                return self._record(auth)

        try:
            for obligation in auth.obligations:
                handler = self._handlers.get(obligation.get("name"))
                if handler is None:
                    raise Refusal(f"cannot perform obligation {obligation.get('name')!r}")
                after = handler(obligation.get("args", []), agent, tool, digest)
                if after is not None:
                    auth.after.append(after)
        except Refusal as exc:
            auth.status, auth.reason, auth.after = "denied", str(exc), []
            return self._record(auth)
        if (self._tools.get(tool) or {}).get("taints_context"):
            # the output of this tool is untrusted content (a web page, a file from outside): once it
            # has been shown to the agent, its context is tainted until a human clears it
            auth.after.append(lambda output, agent=agent: self._taint(agent, output))
        auth.status = "allowed"
        return self._record(auth)

    def _taint(self, agent: str, output):
        self._tainted.add(agent)
        return output

    def clear_taint(self, agent: str) -> None:
        """A human decision: the agent's context is trusted again."""
        self._tainted.discard(agent)

    def is_tainted(self, agent: str) -> bool:
        return agent in self._tainted

    def approve(self, approval_id: str, approver: str) -> str:
        """The approval surface: returns a token for a pending approval request."""
        if self._approvals is None:
            raise ApprovalError("no approval service is configured")
        return self._approvals.issue_token(approval_id, approver)

    # ------------------------------------------------------------------- executing
    def call_tool(self, agent: str, tool: str, arguments: dict, approval_token: Optional[str] = None) -> dict:
        auth = self.authorize(agent, tool, arguments, approval_token)
        if auth.status != "allowed":
            return {"status": auth.status, "decision": auth.decision, "reason": auth.reason,
                    "approval": auth.approval, "request_hash": auth.request_hash}
        if self._downstream is None:
            return {"status": "error", "reason": "no downstream configured", "request_hash": auth.request_hash}
        try:
            output = self._downstream(tool, arguments)
        except Exception as exc:
            return {"status": "error", "reason": f"downstream failed: {type(exc).__name__}",
                    "request_hash": auth.request_hash}
        try:
            for after in auth.after:
                output = after(output)
        except Refusal as exc:
            return {"status": "denied", "decision": auth.decision, "reason": str(exc), "request_hash": auth.request_hash}
        return {"status": "ok", "decision": auth.decision, "result": output, "untrusted": True,
                "obligations": auth.obligations, "approver": auth.approver, "request_hash": auth.request_hash}

    # ----------------------------------------------------------------- obligations
    def _ob_audit(self, args, agent, tool, digest):
        if self._audit is None:
            raise Refusal("cannot perform obligation 'audit': no audit log is configured")
        try:
            self._audit.append({"kind": "obligation:audit", "agent": agent, "tool": tool, "request_hash": digest,
                                "args": [a for a in args if isinstance(a, (str, int, bool))]})
        except OSError as exc:
            raise Refusal("cannot perform obligation 'audit': the audit log is not writable") from exc
        return None

    def _ob_rate_limit(self, args, agent, tool, digest):
        if len(args) != 2 or not isinstance(args[1], int) or isinstance(args[1], bool):
            raise Refusal("cannot perform obligation 'rate_limit': expected (key, limit)")
        if not self._limiter.hit(f"{agent}|{args[0]}", args[1]):
            raise Refusal(f"rate limit exceeded ({args[1]} per minute)")
        return None

    def _ob_max_output(self, args, agent, tool, digest):
        if len(args) != 1 or not isinstance(args[0], int) or isinstance(args[0], bool) or args[0] < 0:
            raise Refusal("cannot perform obligation 'max_output_bytes': expected a size")
        limit = args[0]

        def after(output):
            text = output if isinstance(output, str) else json.dumps(output)
            if len(text.encode("utf-8")) > limit:
                return text.encode("utf-8")[:limit].decode("utf-8", "ignore") + " [truncated by policy]"
            return output
        return after

    # ------------------------------------------------------------------- recording
    def _record(self, auth: Authorization) -> Authorization:
        if self._audit is not None:
            try:
                self._audit.append({"kind": "gateway", "request_hash": auth.request_hash, "status": auth.status,
                                    "decision": auth.decision, "approver": auth.approver})
            except OSError:
                if auth.status == "allowed":      # an action we cannot record must not run
                    auth.status, auth.reason, auth.after = "denied", "the audit log is not writable", []
        return auth
