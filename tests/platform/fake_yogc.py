"""A scripted stand-in for `yogc`, used to test the engine process management and fault handling.

Usage:  python fake_yogc.py MODE validate POLICY
        python fake_yogc.py MODE batch-json POLICY

Modes: ok | crash | hang | garbage | bad_compile | crash_after_one
The answer to a request is ALLOW when the resource starts with "ok", REQUIRE_APPROVAL for "deploy",
otherwise DENY; a request with args.bad set returns a request-level error.
"""
import json
import sys
import time

mode, command = sys.argv[1], sys.argv[2]

if command == "validate":
    if mode == "bad_compile":
        print("policy.yog:1:1: error: nope", file=sys.stderr)
        sys.exit(1)
    print("ok")
    sys.exit(0)

served = 0
for line in sys.stdin:
    served += 1
    if mode == "crash":
        sys.exit(3)
    if mode == "hang":
        time.sleep(60)
    if mode == "garbage":
        print("this is not json", flush=True)
        continue
    if mode == "crash_after_one" and served == 2:
        sys.exit(4)
    request = json.loads(line)
    if (request.get("args") or {}).get("bad"):
        print(json.dumps({"error": {"message": "bad request", "line": 0, "column": 0}}), flush=True)
        continue
    resource = request.get("resource", "")
    decision = "ALLOW" if resource.startswith("ok") else ("REQUIRE_APPROVAL" if resource == "deploy" else "DENY")
    print(json.dumps({"decision": decision, "reason": "fake", "matched_line": 1, "policy_version": 2,
                      "obligations": [{"name": "audit", "args": [resource]}] if decision == "ALLOW" else []}),
          flush=True)
