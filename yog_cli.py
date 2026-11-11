
import argparse
import json
import sys
from pathlib import Path

from yog import load_policy


def main():
    parser = argparse.ArgumentParser(
        description="YOG Engine CLI - check policy decisions."
    )

    parser.add_argument(
        "--policy",
        default="all_examples.yog",
        help="Path to the .yog policy file (default: all_examples.yog)",
    )
    parser.add_argument("--actor", help="Actor requesting the action")
    parser.add_argument("--action", help="Action to check")
    parser.add_argument("--resource", help="Resource the action targets")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print the policy evaluation trace",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run predefined authorization examples",
    )

    args = parser.parse_args()

    policy_path = Path(args.policy)
    if not policy_path.is_file():
        parser.error(f"Policy file not found: {policy_path}")

    try:
        engine = load_policy(str(policy_path))
    except Exception as exc:
        print(f"Could not load policy: {exc}", file=sys.stderr)
        return 2

    if args.demo:
        examples = [
            ("a_admin", "can_delete", "database_1"),
            ("a_agent", "can_delete", "database_1"),
            ("b_agent", "can_deploy", "database_2"),
            ("b_agent", "can_deploy", "payments_service"),
        ]

        for actor, action, resource in examples:
            result = engine.check(actor, action, resource)
            print(
                f"{actor} -> {action}({resource}): "
                f"{result['decision']}"
            )
            print(f"  Reason: {result['reason']}")
        return 0

    if not all([args.actor, args.action, args.resource]):
        parser.error(
            "Provide --actor, --action and --resource, or use --demo."
        )

    result = engine.check(args.actor, args.action, args.resource)

    print(json.dumps(result, indent=2 if args.trace else None))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())