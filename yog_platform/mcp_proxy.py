"""A stdio proxy for the Model Context Protocol that puts the gateway in front of an MCP server.

The agent speaks MCP to this process; the proxy spawns the real MCP server and relays every message, except
that each ``tools/call`` request is first authorised by the :class:`~yog_platform.gateway.Gateway`.  A refused
call is answered to the agent directly and never reaches the server.  MCP over stdio is newline-delimited
JSON-RPC.

The agent holds no credentials for the downstream server: only this proxy talks to it (see
docs/THREAT_MODEL.md, T1).  An approval token travels in ``params._meta.yog_approval_token`` and is removed
before the call is forwarded or hashed.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Callable, Optional

from .gateway import Gateway

_BLOCKED = -32001


def _text_result(request_id, text: str, *, error: bool, extra: Optional[dict] = None) -> dict:
    result = {"content": [{"type": "text", "text": text}], "isError": error}
    if extra:
        result["structuredContent"] = extra
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class McpProxy:
    def __init__(self, gateway: Gateway, server_command: list, agent_id: str, *,
                 read_agent: Callable[[], Optional[str]], write_agent: Callable[[str], None],
                 visible: Optional[Callable[[list], list]] = None):
        """``visible(names)`` returns the tool names to show the agent in ``tools/list`` (see
        :func:`yog_platform.partial_eval.visible_tools`).  It only trims the list; every call is still
        authorised.  If it raises, the full list is shown."""
        self._visible = visible
        self._list_ids: set = set()
        self._gateway = gateway
        self._command = server_command
        self._agent = agent_id
        self._read_agent = read_agent
        self._write_agent = write_agent
        self._write_lock = threading.Lock()
        self._pending: dict = {}                      # request id -> post-call obligation handlers
        self._pending_lock = threading.Lock()
        self._server: Optional[subprocess.Popen] = None

    # ---------------------------------------------------------------- output helpers
    def _to_agent(self, message) -> None:
        with self._write_lock:
            self._write_agent(json.dumps(message, ensure_ascii=False))

    def _to_server(self, line: str) -> None:
        assert self._server is not None and self._server.stdin is not None
        self._server.stdin.write(line + "\n")
        self._server.stdin.flush()

    # ---------------------------------------------------------------- agent -> server
    def _handle_agent_line(self, line: str) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self._to_agent({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return                                    # malformed input is never forwarded
        if isinstance(message, list):
            if any(isinstance(m, dict) and m.get("method") == "tools/call" for m in message):
                self._to_agent({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "batched tool calls are not supported"}})
            else:
                self._to_server(line)
            return
        if isinstance(message, dict) and message.get("method") == "tools/list" and self._visible is not None:
            with self._pending_lock:
                self._list_ids.add(json.dumps(message.get("id")))
        if not (isinstance(message, dict) and message.get("method") == "tools/call"):
            self._to_server(line)
            return

        request_id = message.get("id")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        name, arguments = params.get("name"), params.get("arguments", {})
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        token = meta.pop("yog_approval_token", None)
        auth = self._gateway.authorize(self._agent, name, arguments if isinstance(arguments, dict) else None, token)
        if auth.status == "approval_required":
            self._to_agent(_text_result(
                request_id, f"Approval required before this call can run (approval id {auth.approval['approval_id']}). "
                            f"Ask an approver, then retry with the token.", error=True,
                extra={"yog": {"status": "approval_required", **auth.approval}}))
            return
        if auth.status != "allowed":
            self._to_agent(_text_result(request_id, f"Blocked by policy: {auth.reason}", error=True,
                                        extra={"yog": {"status": "denied", "reason": auth.reason}}))
            return
        if params.get("_meta") is not None and not meta:
            params.pop("_meta")                       # do not forward an emptied _meta
        if auth.after:
            with self._pending_lock:
                self._pending[json.dumps(request_id)] = auth.after
        self._to_server(json.dumps(message, ensure_ascii=False))

    # ---------------------------------------------------------------- server -> agent
    def _handle_server_line(self, line: str) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self._write_agent_raw(line)
            return
        if isinstance(message, dict) and "result" in message and "id" in message:
            with self._pending_lock:
                handlers = self._pending.pop(json.dumps(message["id"]), None)
                was_list = json.dumps(message["id"]) in self._list_ids
                self._list_ids.discard(json.dumps(message["id"]))
            if was_list and isinstance(message["result"], dict) and isinstance(message["result"].get("tools"), list):
                try:
                    names = [t.get("name") for t in message["result"]["tools"] if isinstance(t, dict)]
                    keep = set(self._visible([n for n in names if isinstance(n, str)]))
                    message["result"]["tools"] = [t for t in message["result"]["tools"]
                                                   if not isinstance(t, dict) or t.get("name") in keep]
                except Exception:
                    pass                                  # the list is a convenience; never break it
            if handlers:
                try:
                    for content in message["result"].get("content", []) if isinstance(message["result"], dict) else []:
                        if isinstance(content, dict) and isinstance(content.get("text"), str):
                            text = content["text"]
                            for handler in handlers:
                                text = handler(text)
                            content["text"] = text
                except Exception as exc:              # an obligation that cannot be applied withholds the output
                    message = _text_result(message["id"], f"Output withheld by policy: {exc}", error=True)
        self._to_agent(message)

    def _write_agent_raw(self, line: str) -> None:
        with self._write_lock:
            self._write_agent(line)

    # -------------------------------------------------------------------------- run
    def run(self) -> int:
        self._server = subprocess.Popen(self._command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1)

        def pump_server():
            assert self._server and self._server.stdout
            for raw in self._server.stdout:
                if raw.strip():
                    self._handle_server_line(raw.rstrip("\r\n"))

        pump = threading.Thread(target=pump_server, daemon=True)
        pump.start()
        try:
            while True:
                line = self._read_agent()
                if line is None:
                    break
                if line.strip():
                    self._handle_agent_line(line.rstrip("\r\n"))
        finally:
            if self._server.stdin:
                try:
                    self._server.stdin.close()
                except OSError:
                    pass
            self._server.wait(timeout=10)
            pump.join(timeout=5)
        return self._server.returncode or 0
