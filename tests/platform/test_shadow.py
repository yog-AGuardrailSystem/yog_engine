"""Shadow (log-only) mode: decide and audit, never block."""
import json
import sys
from pathlib import Path

import pytest

from yog_platform import claude_hook
from yog_platform.audit import AuditLog
from yog_platform.gateway import Gateway
from yog_platform.pdp import ReferencePDP
from yog_platform.sidecar import Sidecar
from yog_platform.policy import PolicyManager

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "examples" / "claude_code" / "guard.yog").read_text(encoding="utf-8")
CWD = "/home/dev/project"
ENV = {"stage": "dev", "cwd": CWD}


@pytest.fixture(scope="module")
def pdp():
    return ReferencePDP(POLICY)


class Broken:
    def check(self, request):
        raise RuntimeError("engine is down")


def records(path):
    return [json.loads(line.split(" ", 1)[1]) if not line.startswith("{") else json.loads(line)
            for line in Path(path).read_text().splitlines() if line.strip()]


def test_shadow_lets_a_denied_call_through_and_audits_the_real_decision(pdp, tmp_path):
    log = tmp_path / "audit.log"
    gw = Gateway(pdp, tools=claude_hook.TOOLS, env=ENV, audit=AuditLog(str(log)), mode="shadow")
    auth = gw.authorize("a", "Bash", {"command": "rm -rf /"})
    assert auth.status == "allowed" and auth.shadow["status"] == "denied" and auth.shadow["decision"] == "DENY"
    text = log.read_text()
    assert "would_have_status" in text and "denied" in text and "shadow" in text


def test_the_same_call_is_blocked_in_enforce_mode(pdp):
    gw = Gateway(pdp, tools=claude_hook.TOOLS, env=ENV)
    assert gw.authorize("a", "Bash", {"command": "rm -rf /"}).status == "denied"


def test_shadow_never_blocks_even_when_the_engine_is_down():
    gw = Gateway(Broken(), mode="shadow")
    auth = gw.authorize("a", "Bash", {"command": "ls"})
    assert auth.status == "allowed" and auth.shadow["status"] == "denied"
    assert Gateway(Broken()).authorize("a", "Bash", {"command": "ls"}).status == "denied"


def test_shadow_does_not_create_approvals_or_run_obligations(pdp):
    from yog_platform.approvals import ApprovalManager
    created = []

    class Spy(ApprovalManager):
        def create(self, *a, **k):
            created.append(1)
            return super().create(*a, **k)
    gw = Gateway(pdp, tools=claude_hook.TOOLS, env=ENV, approvals=Spy(b"k" * 32), mode="shadow")
    assert gw.authorize("a", "Bash", {"command": "git push origin main"}).status == "allowed"
    assert created == []


def test_malformed_calls_are_still_refused_in_shadow(pdp):
    assert Gateway(pdp, mode="shadow").authorize("a", "Bash", "not a dict").status == "denied"


def test_invalid_mode_is_rejected(pdp):
    with pytest.raises(ValueError):
        Gateway(pdp, mode="observe")


def test_hook_shadow_prints_nothing_for_a_denied_call(monkeypatch, capsys, pdp):
    import io
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": CWD, "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    policy = ROOT / "examples" / "claude_code" / "guard.yog"
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    assert claude_hook.main(["--policy", str(policy), "--shadow"]) == 0
    assert capsys.readouterr().out == ""
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    claude_hook.main(["--policy", str(policy)])
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_sidecar_shadow_answers_allow_but_keeps_the_real_decision(tmp_path):
    from test_sidecar_policy_faults import REQ, make_sidecar, post
    car, _manager, log = make_sidecar(tmp_path, shadow=True)
    status, body = post(car, dict(REQ, resource="nope"))                   # the fake engine denies this
    assert status == 200 and body["decision"] == "ALLOW" and body["enforced"] is False
    assert body["shadow_decision"] == "DENY" and body["obligations"] == []
    status, body = post(car, b"not json")                                  # even a malformed request is only reported
    assert status == 200 and body["decision"] == "ALLOW" and body["shadow_decision"] == "DENY"
    assert car.metrics.counts["shadow_would_deny"] == 2
    assert "shadow" in (tmp_path / "audit.log").read_text()


def test_sidecar_enforce_is_unchanged(tmp_path):
    from test_sidecar_policy_faults import REQ, make_sidecar, post
    car, _manager, _log = make_sidecar(tmp_path)
    assert post(car, dict(REQ, resource="nope"))[1]["decision"] == "DENY"
    assert "enforced" not in post(car, REQ)[1]
