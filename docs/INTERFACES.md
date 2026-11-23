# YOG interfaces

Contracts between the engine and everything around it: callers, bindings, the sidecar, the gateway.
Status per section is marked **implemented** (in this repository and tested) or **specified** (a contract
that the component implementing it must meet).

## 1. Check request (JSON) , implemented

```json
{
  "request_id": "7c1e...",
  "actor": "agent_17",
  "action": "run_tool",
  "resource": "sql_exec",
  "args":  { "query": "SELECT 1", "limit": 5, "tags": ["a", "b"], "opts": { "dry_run": true } },
  "env":   { "stage": "prod" },
  "state": { "version": 12, "values": { "deletes_last_10m": 3 } },
  "now":   1700000000,
  "facts": [ { "predicate": "tool_call", "args": ["sql_exec", "query"] } ]
}
```

`actor`, `action` and `resource` are required strings. Everything else is optional. Unknown top-level fields
are rejected (a typo such as `arg` must not silently produce a default deny). The engine entry points are
`yog_check_json()` and `yogc check-json` / `yogc batch-json`.

### Flattening (deterministic)

| Field | Becomes |
|---|---|
| `args.k = v` | `arg("k", v)` |
| `args.o.k = v` | `arg("o.k", v)` (objects nest with dotted keys, up to 8 levels) |
| `args.k = [v1, v2]` | `arg("k", v1)`, `arg("k", v2)` (one fact per element; elements must be scalars) |
| `env.*` | `env(key, v)` with the same rules |
| `state.values.*` | `state(key, v)` with the same rules |
| `state.version = n` | `state_version(n)` |
| `now = n` | `now(n)` |
| `facts[i]` | `predicate(args...)`, 1 to 16 scalar arguments, predicate `[a-z][A-Za-z0-9_]*` |

Facts are emitted in this order: `args`, `env`, `state_version`, `state`, `now`, `facts`, each in the
order they appear in the request. JSON value mapping: string to text, integer to int, `true`/`false` to
bool. **Rejected:** `null`, numbers with a fraction or exponent, integers outside signed 64-bit, arrays
inside arrays or arrays of objects, duplicate object keys, invalid UTF-8, NUL characters, lone surrogate
escapes, nesting deeper than 16, more than 20,000 values, more than 4,096 facts, input over 1 MiB, and a
`facts` predicate that is a built-in name.

A policy reads these facts only through matching declarations:
`input arg(text, any)`, `input env(text, any)`, `input state(text, any)`, `input state_version(int)`,
`input now(int)`. Request values never pass through policy text, so a value containing quotes, `;` or
newlines cannot forge a fact.

## 2. Check result (JSON) , implemented

```json
{
  "decision": "REQUIRE_APPROVAL",
  "reason": "require_approval clause at line 22 matched",
  "matched_line": 22,
  "policy_version": 2,
  "obligations": [ { "name": "audit", "args": ["prod_call", "sql_exec"] } ],
  "trace": "..."
}
```

`decision` is `ALLOW`, `DENY` or `REQUIRE_APPROVAL`. `obligations` is always present (possibly empty);
argument types are preserved (string, integer, boolean). `trace` appears only when requested. A failed
check is `{"error": {"message": "...", "line": 0, "column": 0}}` and callers **must treat it as DENY**.
`yogc` exit codes: 0 allow, 3 deny, 4 require approval, 2 error or usage, 1 compile error.

The sidecar (section 6) adds `request_id`, `policy_hash`, `state_version` and `cached` to results.

## 3. C API , implemented

Declared in `yog/include/api/yog.h`. Highlights:

- `Yog *yog_compile(source, length, &error)`, `yog_free`
- `bool yog_check_json(yog, json, length, trace, &result, &error)`
- `bool yog_check(yog, actor, action, resource, context_text, trace, &result, &error)`: the text context is for
  **trusted** callers only; untrusted values go through the JSON path
- `YogDecision { YOG_ALLOW, YOG_DENY, YOG_REQUIRE_APPROVAL }`, `YogResult` with `matched_line` and
  `obligations`
- `char *yog_result_to_json(yog, result)`, `yog_error_to_json`, `yog_string_free`
- `yog_set_limits` / `yog_get_limits`: five budgets (steps, depth, solutions, milliseconds, bytes)
- `yog_version()`, `YOG_VERSION_STRING`, `yog_policy_version()`, `yog_decision_name()`

Ownership: `yog_result_free` releases everything in a `YogResult`. A `Yog` is immutable after
`yog_set_limits` and may be shared between threads. **ABI policy:** structs may gain fields at the end;
until 1.0 a rebuild is required on any change.

## 4. Trace format , specified

Text trace today (`> ?- goal`, `> try rule ...`). The structured form planned for the sidecar is a list of
events `{id, parent, kind, line, text}` with `kind` one of `goal`, `try_clause`, `builtin`, `decision`,
capped in size and flagged `truncated`. Traces contain request values: treat them as sensitive.

## 5. Policy bundle , implemented (`yog_platform/bundle.py`)

A signed bundle is a JSON document:

```json
{
  "format": "yog-bundle-1",
  "manifest": {
    "policy_version": 41,
    "created": "2026-11-23T12:00:00Z",
    "not_after": "2027-11-23T12:00:00Z",
    "engine_language_version": 2,
    "key_id": "release-2026",
    "files": { "main.yog": "<sha256 hex>" }
  },
  "files": { "main.yog": "<policy text>" },
  "signature": "<base64 Ed25519 signature over the canonical manifest JSON>"
}
```

The canonical manifest is JSON with sorted keys, no whitespace and UTF-8. The `policy_hash` is the SHA-256
of the manifest's canonical JSON. Verification fails closed on: unknown format, bad signature, unknown
`key_id`, expired `not_after`, any file whose hash differs, a `policy_version` lower than the one in force
(downgrade), or a language version the engine does not support.

## 6. Sidecar HTTP API , implemented (`yog_platform/sidecar.py`)

| Endpoint | Purpose |
|---|---|
| `POST /v1/check` | body is a check request (section 1); returns a check result (section 2) |
| `GET /v1/policy` | `{policy_hash, policy_version, loaded_at}` |
| `POST /v1/policy/reload` | `{ "bundle": "<path>" }`: verify, compile, swap atomically |
| `GET /healthz` | 200 when a policy is loaded |
| `GET /metrics` | Prometheus text counters |

Any internal error returns HTTP 500 with a body the client must treat as DENY. Request bodies are limited
to 1 MiB.

## 7. Approval token , implemented (`yog_platform/approvals.py`)

When the decision is `REQUIRE_APPROVAL` the gateway creates an approval request bound to the exact call:

```json
{ "approval_id": "...", "request_hash": "<sha256 of the canonical request>", "policy_hash": "...",
  "expires_at": 1700000300 }
```

An approver returns a token: `HMAC-SHA256(secret, approval_id | request_hash | policy_hash | expires_at |
approver)`. The gateway executes the tool only if the token verifies, the request hash equals the hash of
the call about to run, the policy hash is unchanged, it has not expired and it has not been used. Tokens
are single-use.

## 8. Audit record , implemented (`yog_platform/audit.py`)

One JSON line per decision, hash-chained:

```json
{"seq": 7, "ts": 1700000000, "request_hash": "...", "policy_hash": "...", "state_version": 12,
 "decision": "ALLOW", "obligations": [], "prev_hash": "...", "hash": "sha256(prev_hash | canonical record)"}
```

Records contain hashes, not raw arguments, so the log does not hold secrets by default.
