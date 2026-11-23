"""Policy decision point adapters: the one-method interface the gateway talks to.

``check(request: dict) -> dict`` returns a result dict (with ``decision``) or ``{"error": ...}``.  Any raised
exception means "no answer", which the gateway treats as DENY.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def check_batch(pdp, requests) -> list:
    """Decisions for several requests, in order.  Uses ``pdp.check_batch`` when the decision point has one,
    otherwise asks one request at a time.  An exception for one request becomes a DENY-shaped error result for
    that request only."""
    if hasattr(pdp, "check_batch"):
        return pdp.check_batch(list(requests))
    out = []
    for request in requests:
        try:
            out.append(pdp.check(request))
        except Exception as exc:
            out.append({"decision": "DENY", "reason": f"decision unavailable: {type(exc).__name__}", "obligations": [],
                        "error": {"message": str(exc)}})
    return out


class PDPError(Exception):
    """The decision point could not be reached or answered badly."""


class InProcessPDP:
    """Calls a :class:`~yog_platform.sidecar.Sidecar` directly (no network)."""

    def __init__(self, sidecar):
        self._sidecar = sidecar

    def check(self, request: dict) -> dict:
        _, body = self._sidecar.handle_check(json.dumps(request).encode("utf-8"))
        return body


class HttpPDP:
    """Calls a sidecar over HTTP.  Timeouts and connection errors raise :class:`PDPError`."""

    def __init__(self, base_url: str, *, timeout: float = 2.0):
        self._url = base_url.rstrip("/") + "/v1/check"
        self._timeout = timeout

    def check(self, request: dict) -> dict:
        data = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(self._url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                return json.loads(response.read(1 << 20))
        except urllib.error.HTTPError as exc:                       # the sidecar answers errors with a DENY body
            try:
                return json.loads(exc.read(1 << 20))
            except ValueError as inner:
                raise PDPError(f"sidecar returned HTTP {exc.code}") from inner
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise PDPError(f"sidecar unreachable: {type(exc).__name__}") from exc


class ReferencePDP:
    """Evaluates with the Python reference interpreter.  Slower than the C engine and not the production
    path; it exists so the platform can be exercised end to end where the C binary is unavailable, and as an
    independent cross-check.  It also works as an engine for :class:`~yog_platform.policy.PolicyManager`."""

    def __init__(self, policy_text: str):
        reference = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")
        if reference not in sys.path:
            sys.path.insert(0, reference)
        import yog_ref
        self._ref = yog_ref
        try:
            self._engine = yog_ref.Engine(yog_ref.Parser(yog_ref.tokenize(policy_text)).parse())
        except yog_ref.YogError as exc:
            from .engine import EngineError
            raise EngineError(f"the policy does not compile: {exc}") from exc

    def check(self, request: dict) -> dict:
        return self._ref.check_json(self._engine, request)

    def close(self) -> None:
        pass
