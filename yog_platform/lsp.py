"""Minimal Language Server Protocol (LSP) server for YOG v2 policies.

Speaks Content-Length-framed JSON-RPC 2.0 over stdin/stdout:
* ``initialize`` / ``initialized`` / ``shutdown`` / ``exit``
* ``textDocument/didOpen`` / ``textDocument/didChange`` -> ``publishDiagnostics``
* ``textDocument/hover`` -> documentation for keywords and built-in predicates
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any, BinaryIO, Dict, List, Optional

from . import analysis
from .pdp import ReferencePDP

HOVER_DOCS: Dict[str, str] = {
    "version": "**version 2** — Declare the YOG policy language version.",
    "input": "**input pred(type, ...)** — Declare an external predicate supplied by the request.",
    "fact": "**fact pred(val, ...)** — Declare a ground policy fact.",
    "rule": "**rule head(Args): ...** — Define a non-recursive helper predicate.",
    "allow": "**allow action(Actor, Resource): ...** — Grant access when body goals succeed.",
    "deny": "**deny action(Actor, Resource): ...** — Deny access (highest precedence).",
    "require_approval": "**require_approval action(Actor, Resource): ...** — Pause for human approval.",
    "obligate": "**obligate name(Args)** — Attach an obligation enforced by the gateway.",
    "in": "**in(X, v1, v2, ...)** — True when `X` equals one of the listed constants.",
    "matches": "**matches(Text, Pattern)** — Linear-time regex search.",
    "glob": "**glob(Text, Pattern)** — Whole-string glob match (`*` and `?`).",
    "under": "**under(Path, Prefix)** — True when normalized `Path` is under `Prefix`.",
    "starts_with": "**starts_with(Text, Prefix)** — Byte prefix check.",
    "ends_with": "**ends_with(Text, Suffix)** — Byte suffix check.",
    "contains": "**contains(Text, Sub)** — Byte substring check.",
    "cidr": "**cidr(Ip, Network)** — True when IPv4/IPv6 `Ip` lies inside `Network`.",
}


def compute_diagnostics(source: str) -> List[Dict[str, Any]]:
    """Return LSP Diagnostic objects from compiler + static analyzer."""
    diags: List[Dict[str, Any]] = []
    try:
        ReferencePDP(source)
    except Exception as exc:
        msg = str(exc)
        line_no = 0
        m = re.search(r"line\s+(\d+)", msg, re.IGNORECASE)
        if m:
            line_no = max(0, int(m.group(1)) - 1)
        diags.append({
            "range": {
                "start": {"line": line_no, "character": 0},
                "end": {"line": line_no, "character": 80},
            },
            "severity": 1,
            "source": "yog",
            "message": msg,
        })
        return diags

    for finding in analysis.analyze(source):
        ln = max(0, int(finding.get("line", 1)) - 1)
        sev = 1 if finding.get("severity") == "error" else 2
        diags.append({
            "range": {
                "start": {"line": ln, "character": 0},
                "end": {"line": ln, "character": 80},
            },
            "severity": sev,
            "code": finding.get("code"),
            "source": "yog-analyze",
            "message": finding.get("message", ""),
        })
    return diags


def word_at_position(source: str, line: int, character: int) -> str:
    lines = source.splitlines()
    if not 0 <= line < len(lines):
        return ""
    text = lines[line]
    if not text:
        return ""
    pos = min(max(0, character), len(text) - 1)
    start = pos
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        start -= 1
    end = pos
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return text[start:end]


class YogLanguageServer:
    """In-memory LSP handler (testable without stdio framing)."""

    def __init__(self):
        self.documents: Dict[str, str] = {}
        self.shutdown_requested = False

    def handle_message(self, msg: Dict[str, Any]) -> List[Dict[str, Any]]:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        outgoing: List[Dict[str, Any]] = []

        if method == "initialize":
            outgoing.append({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "capabilities": {
                        "textDocumentSync": 1,
                        "hoverProvider": True,
                    },
                    "serverInfo": {"name": "yog-lsp", "version": "0.2.0"},
                },
            })
        elif method == "shutdown":
            self.shutdown_requested = True
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "textDocument/didOpen":
            doc = params.get("textDocument") or {}
            uri = doc.get("uri", "")
            text = doc.get("text", "")
            self.documents[uri] = text
            outgoing.append({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": compute_diagnostics(text)},
            })
        elif method == "textDocument/didChange":
            doc = params.get("textDocument") or {}
            uri = doc.get("uri", "")
            changes = params.get("contentChanges") or []
            if changes:
                text = changes[-1].get("text", "")
                self.documents[uri] = text
                outgoing.append({
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {"uri": uri, "diagnostics": compute_diagnostics(text)},
                })
        elif method == "textDocument/hover":
            uri = (params.get("textDocument") or {}).get("uri", "")
            pos = params.get("position") or {}
            text = self.documents.get(uri, "")
            word = word_at_position(text, int(pos.get("line", 0)), int(pos.get("character", 0)))
            doc_str = HOVER_DOCS.get(word)
            result = {"contents": {"kind": "markdown", "value": doc_str}} if doc_str else None
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": result})
        elif msg_id is not None:
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": None})
        return outgoing


def _read_message(stream: BinaryIO) -> Optional[Dict[str, Any]]:
    headers: Dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        decoded = line.decode("ascii", errors="replace").strip()
        if not decoded:
            break
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = stream.read(length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def _write_message(stream: BinaryIO, payload: Dict[str, Any]) -> None:
    raw = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
    stream.write(header + raw)
    stream.flush()


def serve_stdio(stdin: Optional[BinaryIO] = None, stdout: Optional[BinaryIO] = None) -> int:
    in_s = stdin or sys.stdin.buffer
    out_s = stdout or sys.stdout.buffer
    server = YogLanguageServer()
    while True:
        msg = _read_message(in_s)
        if msg is None:
            return 0
        if msg.get("method") == "exit":
            return 0 if server.shutdown_requested else 1
        for reply in server.handle_message(msg):
            _write_message(out_s, reply)
