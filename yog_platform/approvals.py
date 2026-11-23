"""Approval workflow for REQUIRE_APPROVAL decisions (see docs/INTERFACES.md section 7).

An approval is bound to the *exact call*: the request hash covers the actor, action, resource and every
argument, so changing even one byte after approval invalidates it (TOCTOU defence).  It is also bound to
the policy hash in force, expires quickly and can be used once.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

# Fields that identify the call.  `now`, `state` and `request_id` change between attempts and are
# deliberately NOT part of the hash.
_CALL_FIELDS = ("actor", "action", "resource", "args", "env", "facts")


class ApprovalError(Exception):
    """An approval that must not be honoured."""


def request_hash(request: dict) -> str:
    call = {k: request[k] for k in _CALL_FIELDS if k in request}
    data = json.dumps(call, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass
class Approval:
    approval_id: str
    request_hash: str
    policy_hash: str
    expires_at: float
    used: bool = False


class ApprovalManager:
    def __init__(self, secret: bytes, *, ttl: float = 300.0, approvers: Optional[Iterable[str]] = None,
                 clock: Callable[[], float] = time.time):
        if len(secret) < 16:
            raise ValueError("the approval secret must be at least 16 bytes")
        self._secret = secret
        self._ttl = ttl
        self._approvers = None if approvers is None else frozenset(approvers)
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: dict[str, Approval] = {}

    def create(self, request: dict, policy_hash: str) -> Approval:
        approval = Approval(approval_id=secrets.token_hex(16), request_hash=request_hash(request),
                            policy_hash=policy_hash, expires_at=self._clock() + self._ttl)
        with self._lock:
            self._purge()
            self._pending[approval.approval_id] = approval
        return approval

    def _mac(self, approval: Approval, approver: str) -> str:
        message = "|".join((approval.approval_id, approval.request_hash, approval.policy_hash,
                            repr(approval.expires_at), approver)).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def issue_token(self, approval_id: str, approver: str) -> str:
        """Called by the approval surface after it has authenticated the approver."""
        if self._approvers is not None and approver not in self._approvers:
            raise ApprovalError(f"{approver!r} is not an authorised approver")
        with self._lock:
            approval = self._pending.get(approval_id)
        if approval is None:
            raise ApprovalError("unknown or expired approval request")
        payload = {"id": approval_id, "approver": approver, "mac": self._mac(approval, approver)}
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    def consume(self, token: str, request: dict, policy_hash: str) -> str:
        """Validates a token for the call about to run and uses it up.  Returns the approver."""
        try:
            padded = token + "=" * (-len(token) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
            approval_id, approver, mac = payload["id"], payload["approver"], payload["mac"]
            if not all(isinstance(x, str) for x in (approval_id, approver, mac)):
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise ApprovalError("malformed approval token") from exc
        with self._lock:
            approval = self._pending.get(approval_id)
            if approval is None:
                raise ApprovalError("unknown or expired approval")
            if approval.used:
                raise ApprovalError("approval was already used")
            if self._clock() > approval.expires_at:
                del self._pending[approval_id]
                raise ApprovalError("approval expired")
            if not hmac.compare_digest(mac, self._mac(approval, approver)):
                raise ApprovalError("approval token does not verify")
            if approval.request_hash != request_hash(request):
                raise ApprovalError("the call differs from the one that was approved")
            if approval.policy_hash != policy_hash:
                raise ApprovalError("the policy changed since this was approved")
            approval.used = True
            return approver

    def _purge(self) -> None:
        now = self._clock()
        for key in [k for k, a in self._pending.items() if a.used or now > a.expires_at]:
            del self._pending[key]
