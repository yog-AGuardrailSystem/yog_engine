"""The sidecar: an HTTP service that hosts the engine and answers check requests.

Safety rules, in order of importance:

1. **Fail closed.** Any error, timeout, missing policy or internal exception produces a response whose
   ``decision`` is ``DENY`` and which carries an ``error``.  A client that only reads ``decision`` can never be
   tricked into allowing by a failure.
2. **Every decision is audited** (hashes only).  If the audit record cannot be written, the request is denied.
3. A decision is cached only when it is safe to reuse (see ``cache.py``); a policy swap clears the cache.
4. Bodies are limited to 1 MiB.

Endpoints are listed in docs/INTERFACES.md section 6.
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .approvals import request_hash
from .audit import AuditLog
from .cache import DecisionCache
from .engine import EngineError
from .policy import PolicyError, PolicyManager

MAX_BODY = 1 << 20


def _deny(message: str, status: int = 500, **extra) -> tuple[int, dict]:
    body = {"decision": "DENY", "reason": message, "obligations": [], "error": {"message": message}}
    body.update(extra)
    return status, body


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.counts: dict[str, int] = {}

    def inc(self, name: str, by: int = 1) -> None:
        with self._lock:
            self.counts[name] = self.counts.get(name, 0) + by

    def render(self, extra: dict) -> str:
        with self._lock:
            counts = dict(self.counts)
        lines = []
        for name in sorted(counts):
            lines.append(f"yog_{name}_total {counts[name]}")
        for name in sorted(extra):
            lines.append(f"yog_{name} {extra[name]}")
        return "\n".join(lines) + "\n"


class Sidecar:
    def __init__(self, manager: PolicyManager, *, audit: Optional[AuditLog] = None,
                 cache: Optional[DecisionCache] = None, trusted_bundle_dir: Optional[str] = None, shadow: bool = False):
        self.manager = manager
        self.shadow = shadow          # decide and audit as usual, but answer ALLOW (see handle_check)
        self.audit = audit
        self.cache = cache
        self.metrics = Metrics()
        self._bundle_dir = trusted_bundle_dir

    # -- core ---------------------------------------------------------------
    def handle_check(self, body: bytes) -> tuple[int, dict]:
        self.metrics.inc("requests")
        try:
            status, reply = self._check(body)
        except Exception as exc:                                  # never let a bug become an allow
            self.metrics.inc("internal_errors")
            status, reply = _deny(f"internal error: {type(exc).__name__}")
        if self.shadow:
            return self._as_shadow(status, reply)
        return status, reply

    def _as_shadow(self, status: int, reply: dict) -> tuple[int, dict]:
        """Shadow mode: report what the policy decided, but tell the caller to proceed.  The real answer stays in
        ``shadow_decision``; obligations are dropped because nothing is being enforced."""
        real = reply.get("decision", "DENY")
        self.metrics.inc("shadow_would_" + {"DENY": "deny", "REQUIRE_APPROVAL": "approve"}.get(real, "allow"))
        out = dict(reply)
        out.update(decision="ALLOW", shadow_decision=real, enforced=False, obligations=[],
                   reason="shadow mode: " + str(reply.get("reason", "")))
        return 200, out

    def _check(self, body: bytes) -> tuple[int, dict]:
        if len(body) > MAX_BODY:
            self.metrics.inc("rejected")
            return _deny("request is larger than 1 MiB", 413)
        try:
            request = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            self.metrics.inc("rejected")
            return _deny("request is not valid JSON", 400)
        if not isinstance(request, dict):
            self.metrics.inc("rejected")
            return _deny("request must be a JSON object", 400)

        loaded = self.manager.current
        if loaded is None:
            self.metrics.inc("no_policy")
            return _deny("no policy is loaded", 503)

        cached = self.cache.get(request, loaded.policy_hash) if self.cache else None
        if cached is not None:
            result, from_cache = cached, True
            self.metrics.inc("cache_hits")
        else:
            try:
                result = loaded.engine.check(request)
            except EngineError as exc:
                self.metrics.inc("engine_errors")
                return _deny(f"engine unavailable: {exc}", 503, policy_hash=loaded.policy_hash)
            from_cache = False
            if self.cache and "error" not in result:
                self.cache.put(request, loaded.policy_hash, result)

        if "error" in result:                                     # a malformed request: a DENY-shaped reply
            self.metrics.inc("request_errors")
            message = result["error"].get("message", "request error") if isinstance(result["error"], dict) else "request error"
            result = {"decision": "DENY", "reason": message, "obligations": [], "error": result["error"]}
            status = 400
        else:
            status = 200

        state = request.get("state")
        record = {
            "request_hash": request_hash(request),
            "policy_hash": loaded.policy_hash,
            "state_version": state.get("version") if isinstance(state, dict) else None,
            "decision": result.get("decision"),
            "obligations": result.get("obligations", []),
            "cached": from_cache,
            "error": "error" in result,
            "shadow": self.shadow,
        }
        if self.audit is not None:
            try:
                self.audit.append(record)
            except OSError:
                self.metrics.inc("audit_failures")
                return _deny("the audit log is not writable", 503, policy_hash=loaded.policy_hash)

        out = dict(result)
        out.update(policy_hash=loaded.policy_hash, request_hash=record["request_hash"], cached=from_cache)
        if isinstance(request.get("request_id"), str):
            out["request_id"] = request["request_id"]
        self.metrics.inc("decisions_" + str(out.get("decision", "unknown")).lower())
        return status, out

    def policy_info(self) -> tuple[int, dict]:
        loaded = self.manager.current
        if loaded is None:
            return 503, {"error": {"message": "no policy is loaded"}}
        return 200, {"policy_hash": loaded.policy_hash, "policy_version": loaded.policy_version,
                     "loaded_at": loaded.loaded_at}

    def reload(self, body: bytes) -> tuple[int, dict]:
        try:
            request = json.loads(body)
            doc = request["bundle"] if isinstance(request.get("bundle"), dict) else None
            if doc is None and isinstance(request.get("bundle"), str):
                doc = self._read_bundle(request["bundle"])
            if doc is None:
                return 400, {"error": {"message": "send {\"bundle\": <document or path>}"}}
            loaded = self.manager.load_bundle(doc)
        except PolicyError as exc:
            self.metrics.inc("reload_failures")
            return 422, {"error": {"message": str(exc)}, "kept": self._kept()}
        except (ValueError, KeyError, TypeError, OSError) as exc:
            self.metrics.inc("reload_failures")
            return 400, {"error": {"message": f"bad reload request: {exc}"}, "kept": self._kept()}
        if self.cache:
            self.cache.clear()
        self.metrics.inc("reloads")
        return 200, {"policy_hash": loaded.policy_hash, "policy_version": loaded.policy_version}

    def _kept(self):
        loaded = self.manager.current
        return None if loaded is None else {"policy_hash": loaded.policy_hash, "policy_version": loaded.policy_version}

    def _read_bundle(self, path: str) -> dict:
        import os
        if self._bundle_dir is None:
            raise ValueError("file reloads are disabled (no bundle directory configured)")
        full = os.path.realpath(os.path.join(self._bundle_dir, path))
        root = os.path.realpath(self._bundle_dir)
        if os.path.commonpath([full, root]) != root:
            raise ValueError("bundle path is outside the bundle directory")
        with open(full, encoding="utf-8") as handle:
            return json.load(handle)

    def metrics_text(self) -> str:
        loaded = self.manager.current
        extra = {"policy_loaded": 1 if loaded else 0, "policy_version": loaded.policy_version if loaded else 0}
        if self.audit is not None:
            extra["audit_records"] = self.audit.count
        if self.cache is not None:
            extra["cache_entries"] = len(self.cache._items)
        return self.metrics.render(extra)


def make_server(sidecar: Sidecar, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):                              # keep request values out of stderr
            pass

        def _send(self, status: int, payload, content_type: str = "application/json") -> None:
            data = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> Optional[bytes]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._send(*_deny("request is larger than 1 MiB or has a bad Content-Length", 413))
                self.close_connection = True
                return None
            return self.rfile.read(length)

        def do_POST(self):
            body = self._body()
            if body is None:
                return
            if self.path == "/v1/check":
                self._send(*sidecar.handle_check(body))
            elif self.path == "/v1/policy/reload":
                self._send(*sidecar.reload(body))
            else:
                self._send(404, {"error": {"message": "not found"}})

        def do_GET(self):
            if self.path == "/v1/policy":
                self._send(*sidecar.policy_info())
            elif self.path == "/healthz":
                ok = sidecar.manager.current is not None
                self._send(200 if ok else 503, {"ok": ok})
            elif self.path == "/metrics":
                self._send(200, sidecar.metrics_text(), "text/plain; version=0.0.4")
            else:
                self._send(404, {"error": {"message": "not found"}})

    return ThreadingHTTPServer((host, port), Handler)


def run_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
