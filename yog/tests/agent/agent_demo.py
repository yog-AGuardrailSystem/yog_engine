"""End-to-end agent demo: a simulated agent asks YOG what it may do.

Run it:   python yog/tests/agent/agent_demo.py

The policy is ``all_examples.yog`` at the repository root and is evaluated by
the reference interpreter, so nothing needs to be built.  With a built
``yogc`` the same decisions come from the C engine (see
``examples/ai_guardrails/enforce_demo.py``).

Each simulated action names the policy predicate it is asking about
(``can_delete``, ``can_transfer``, ...).  YOG's ``check(actor, action,
resource)`` treats ``action`` as that predicate name -- it is not a free-form
verb like "delete".
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "reference"))

from yog_ref import Atom, Const, load_policy  # noqa: E402

POLICY_FILE = ROOT / "all_examples.yog"


def main():
    engine = load_policy(str(POLICY_FILE))

    actions = [
        {
            "label": "admin deletes a database",
            "actor": "a_admin",
            "action": "can_delete",
            "resource": "database_1",
        },
        {
            "label": "developer agent deletes a database",
            "actor": "a_agent",
            "action": "can_delete",
            "resource": "database_1",
        },
        {
            "label": "customer transfers 9,000 (within limit)",
            "actor": "i_customer",
            "action": "can_transfer",
            "resource": "i_acct_999",
            # Per-request facts: the amount is not known at policy-write time.
            "context": [Atom("amount", [Const("i_acct_999"), Const(9000)])],
        },
        {
            "label": "customer transfers 50,000 (over limit)",
            "actor": "i_customer",
            "action": "can_transfer",
            "resource": "i_acct_999",
            "context": [Atom("amount", [Const("i_acct_999"), Const(50000)])],
        },
        {
            "label": "sandboxed agent runs a safe command",
            "actor": "j_sandboxed_agent",
            "action": "can_run_command",
            "resource": "ls_command",
        },
        {
            "label": "unsandboxed agent runs rm -rf",
            "actor": "j_agent",
            "action": "can_run_command",
            "resource": "rm_rf",
        },
    ]

    for action in actions:
        print("\n" + "=" * 45)
        print("YOG AGENT DECISION")
        print("=" * 45)

        print(f"Scenario : {action['label']}")
        print(f"Actor    : {action['actor']}")
        print(f"Action   : {action['action']}")
        print(f"Resource : {action['resource']}")

        result = engine.check(
            actor=action["actor"],
            action=action["action"],
            resource=action["resource"],
            context=action.get("context"),
        )

        decision = result["decision"]
        reason = result.get("reason", "No reason provided")

        print(f"Decision : {decision}")

        if decision == "ALLOW":
            print(f"[would execute] {action['label']}")
        else:
            print(f"Reason   : {reason}")


if __name__ == "__main__":
    main()
