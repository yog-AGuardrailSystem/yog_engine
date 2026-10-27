from yog import Engine


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