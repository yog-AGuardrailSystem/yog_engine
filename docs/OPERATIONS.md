# Operating YOG

Status: written for the Python platform in `yog_platform/`. Container and Kubernetes files under `deploy/` are
**unverified** (no container runtime was available when they were written).

## Deployment shapes
- **In-process** (`yog_platform.gateway`, `claude_hook`): simple, but agent code can bypass it.
- **Sidecar** (`python -m yog_platform serve`): an HTTP PDP. Enforcement is real only if the agent has no
  credentials and no network path to the tools except through a gateway that calls the sidecar.
- **Claude Code**: add `examples/claude_code/guard.yog` through a `PreToolUse` hook (see `yog_platform/claude_hook.py`).

## Keys and bundles
1. `python -m yog_platform bundle keygen --out keys/ --key-id main` (keep the private key offline or in a secret store).
2. `bundle build --dir policy/ --version N --key ... --key-id main --out policy.yogb --self-tests tests.json`.
3. Sidecars get only the public key (`--pub main:main.pub`). Rotate by trusting both keys, signing with the new one,
   then dropping the old.
4. Bundles expire (`--days`), and a sidecar refuses a lower version than it runs (downgrade protection).

## Rollout and rollback
`Syncer` (`--registry DIR|URL --channel stable`) stages a new bundle, runs its self-tests, then swaps atomically.
A failed self-test or bad signature leaves the running policy untouched.

## State consistency contract
YOG never reads a clock or a database. The caller supplies `state` (with `state_version`) and `now`; the decision
echoes them. The gateway owns freshness: reject state older than your bound, and keep counters (rate limits) in a
store outside YOG. Replaying a request with the same policy and state gives the same decision.

## Failure behaviour
Any engine crash, hang, missing policy or audit-write failure yields DENY with an error. Clients must treat anything
but an explicit ALLOW as a refusal. A partition between gateway and sidecar means deny unless you configure an explicit,
logged read-only allowlist (not provided by default).

## Observability
`GET /metrics` (decision counts, errors, cache hits), `GET /healthz`, hash-chained audit log (verify with the audit
verifier). OpenTelemetry export is not implemented.

## Known gaps
No supervised soak test, no external security review, no published packages. See `docs/ROADMAP.md`.
