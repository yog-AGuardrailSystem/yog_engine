import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "reference"))

from yog_ref import Engine  # noqa: E402


def main():
    # TODO: Initialize Engine using your project's actual API.
    engine = None

    actions = [
        {
            "actor": "admin",
            "action": "read",
            "resource": "report"
        },
        {
            "actor": "guest",
            "action": "delete",
            "resource": "database"
        },
        {
            "actor": "agent",
            "action": "transfer",
            "resource": "money"
        },
        {
            "actor": "agent",
            "action": "run",
            "resource": "system_command"
        }
    ]

    for action in actions:
        print("\n" + "=" * 45)
        print("YOG AGENT DECISION")
        print("=" * 45)

        print(f"Actor    : {action['actor']}")
        print(f"Action   : {action['action']}")
        print(f"Resource : {action['resource']}")

        # Replace this line after confirming Engine initialization.
        result = engine.check(
            actor=action["actor"],
            action=action["action"],
            resource=action["resource"]
        )

        decision = result["decision"]
        reason = result.get("reason", "No reason provided")

        print(f"Decision : {decision}")

        if decision == "ALLOW":
            print(f"[would execute] {action}")
        else:
            print(f"Reason   : {reason}")


if __name__ == "__main__":
    main()