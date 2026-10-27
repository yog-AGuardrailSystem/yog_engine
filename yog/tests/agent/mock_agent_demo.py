from yog import load_policy, YogError
POLICY_FILE = "all_examples.yog"
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
        engine = load_policy(POLICY_FILE)
    except YogError as error:
        raise SystemExit(f"Could not load policy: {error}")
    # These actions are simulated. No real files or databases are changed.
    sample_actions = [
        {
            "actor": "agent",
            "action": "delete",
            "resource": "database_1",
        },
        {
            "actor": "admin_user",
            "action": "delete",
            "resource": "database_1",
        },
        {
            "actor": "agent",
            "action": "deploy",
            "resource": "database_2",
        },
        {
            "actor": "finance_bot",
            "action": "transfer",
            "resource": "acct_123",
        },
    ]
    run_mocked_agent(engine, sample_actions)