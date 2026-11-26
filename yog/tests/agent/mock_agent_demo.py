"""Simulated (mocked) agent: evaluate actions without executing them.

Run it:   python yog/tests/agent/mock_agent_demo.py

The policy is ``all_examples.yog`` at the repository root.  As in
``agent_demo.py``, the ``action`` passed to ``check`` is the policy predicate
name (``can_delete``, ``can_deploy``, ...), not a free-form verb.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "reference"))

from yog_ref import load_policy, YogError  # noqa: E402

POLICY_FILE = ROOT / "all_examples.yog"


def run_mocked_agent(engine, actions):
    """Evaluate simulated actions without executing them."""
    print("\n=== YOG Mocked Agent Demo ===")
    for item in actions:
        actor = item["actor"]
        action = item["action"]
        resource = item["resource"]
        result = engine.check(
            actor,
            action,
            resource,
            context=item.get("context", []),
        )
        print(f"\nAgent:    {actor}")
        print(f"Action:   {action}({resource})")
        print(f"Decision: {result['decision']}")
        print(f"Reason:   {result['reason']}")
        print("Execution: SIMULATED ONLY")


if __name__ == "__main__":
    try:
        engine = load_policy(str(POLICY_FILE))
    except YogError as error:
        raise SystemExit(f"Could not load policy: {error}")
    # These actions are simulated. No real files or databases are changed.
    sample_actions = [
        {
            "actor": "a_agent",
            "action": "can_delete",
            "resource": "database_1",
        },
        {
            "actor": "a_admin",
            "action": "can_delete",
            "resource": "database_1",
        },
        {
            "actor": "b_agent",
            "action": "can_deploy",
            "resource": "database_2",
        },
        {
            "actor": "i_customer",
            "action": "can_transfer",
            "resource": "i_acct_999",
            "context": [],
        },
    ]
    run_mocked_agent(engine, sample_actions)
