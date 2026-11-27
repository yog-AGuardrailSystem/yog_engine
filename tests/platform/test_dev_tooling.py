"""Tests for developer tooling (REPL, LSP, VS Code syntax extension) and OpenFGA adapter."""
from __future__ import annotations

import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from benchmarks.adapters.openfga_adapter import OpenFGALocalEvaluator, write_translation  # noqa: E402
from yog_platform.lsp import YogLanguageServer, compute_diagnostics, serve_stdio  # noqa: E402
from yog_platform.repl import ReplSession  # noqa: E402


def test_repl_session_commands_and_evaluation():
    policy = (
        "version 2\n"
        "input role(text, text)\n"
        "allow read(U, R):\n"
        "    role(U, \"admin\")\n"
    )
    sess = ReplSession(policy)
    assert sess.eval_line(":fact role alice admin").startswith("added fact")
    assert "ALLOW" in sess.eval_line("alice read doc1")
    assert "DENY" in sess.eval_line("bob read doc1")
    trace_json = json.loads(sess.eval_line(":trace"))
    assert trace_json["decision"] == "DENY"
    assert sess.eval_line(":analyze") == "0 finding(s)"
    assert sess.eval_line(":clear-facts") == "cleared facts"
    assert "DENY" in sess.eval_line("alice read doc1")


def test_lsp_diagnostics_hover_and_stdio_framing():
    srv = YogLanguageServer()
    init_replies = srv.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_replies[0]["result"]["capabilities"]["hoverProvider"] is True

    valid = "version 2\nallow read(U, R):\n    in(U, \"alice\")\n"
    open_replies = srv.handle_message({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {"textDocument": {"uri": "file:///test.yog", "text": valid}},
    })
    assert open_replies[0]["method"] == "textDocument/publishDiagnostics"
    assert open_replies[0]["params"]["diagnostics"] == []

    hover = srv.handle_message({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {"textDocument": {"uri": "file:///test.yog"}, "position": {"line": 2, "character": 4}},
    })
    assert "in(X" in hover[0]["result"]["contents"]["value"]

    bad_diags = compute_diagnostics("version 2\nallow read(U, R):\n    undefined_pred(U)\n")
    assert len(bad_diags) >= 1
    assert bad_diags[0]["severity"] == 1

    # Stdio framing round-trip
    req = {"jsonrpc": "2.0", "id": 10, "method": "shutdown", "params": {}}
    body = json.dumps(req).encode("utf-8")
    in_buf = io.BytesIO(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    out_buf = io.BytesIO()
    assert serve_stdio(in_buf, out_buf) == 0
    assert b'"id": 10' in out_buf.getvalue()


def test_vscode_extension_manifests_are_valid_json():
    ext_dir = os.path.join(ROOT, ".vscode", "extensions", "yog-syntax")
    for rel in ("package.json", "language-configuration.json", os.path.join("syntaxes", "yog.tmLanguage.json")):
        with open(os.path.join(ext_dir, rel), encoding="utf-8") as handle:
            data = json.load(handle)
        assert isinstance(data, dict)


def test_openfga_adapter_translation_and_local_eval(tmp_path):
    model = {
        "role": {"alice": "admin", "bob": "manager", "carol": "guest"},
        "member": {"carol": {"eng"}},
        "team_resource": {"eng": {"repo1"}},
        "public": {"doc_pub"},
    }
    write_translation(model, tmp_path)
    assert (tmp_path / "model.fga").exists()
    tuples = json.loads((tmp_path / "tuples.json").read_text(encoding="utf-8"))["tuples"]
    ev = OpenFGALocalEvaluator(tuples)
    assert ev.check("alice", "anything") == "ALLOW"
    assert ev.check("carol", "repo1") == "ALLOW"
    assert ev.check("carol", "doc_pub") == "DENY"
    assert ev.check("bob", "doc_pub") == "ALLOW"
