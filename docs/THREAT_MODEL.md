# Threat model

Scope: YOG used as the policy decision point (PDP) for an AI agent that calls tools. This extends
[SECURITY.md](SECURITY.md), which covers the engine itself. Each threat names the control that addresses it
and the test that checks it.

## 1. Components and trust

| Component | Trust | Notes |
|---|---|---|
| Policy author | trusted | writes and reviews policies; policies are untrusted *input to the compiler* (limits apply) |
| Engine (`libyog`, `yogc`) | trusted | pure, deterministic, fail-closed |
| Gateway | trusted | the enforcement point: builds requests, enforces decisions and obligations, holds credentials |
| Sidecar | trusted | hosts the engine, verifies and loads bundles, writes the audit log |
| State provider | trusted for the values it supplies | owns counters and flags; YOG only reads them |
| Approver | trusted human or system | authenticated; may only approve a specific request |
| **Agent / model** | **untrusted** | its tool calls are the thing being judged |
| **Tool output, web pages, files** | **untrusted** | may contain instructions aimed at the agent |

The central assumption: **YOG decides, the gateway enforces.** A perfect policy is worth nothing if the
agent can reach a tool without passing through the gateway.

## 2. Threats

| # | Threat | Control | Test |
|---|---|---|---|
| T1 | Agent bypasses the gateway and calls a tool directly | agent holds no downstream credentials and has no network path except via the gateway (deployment rule, section 3) | `gateway` bypass test: direct downstream call without a gateway-issued credential fails |
| T2 | Request values forge facts (`x"); fact role(evil, admin`) | JSON requests become typed facts, never policy text | `test_json` injection cases |
| T3 | Path traversal (`/work/../etc`) or relative paths defeat prefix rules | `under()` normalises first; absolute and relative never match | `test_builtin`, `diff_v2` |
| T4 | Catastrophic regex (ReDoS) hangs the PDP | linear-time NFA; pattern/text size limits | `test_builtin` hostile-pattern test |
| T5 | Huge policy or request exhausts CPU or memory | step, depth, solution, time and memory limits; JSON size, depth and node limits | `test_security`, `test_json` |
| T6 | Malformed or ambiguous request is treated as allow | strict parser; any error is a DENY result; unknown fields, duplicate keys, nulls, floats rejected | `test_json` |
| T7 | Unicode tricks (confusables, combining marks, overlongs) | engine does bytewise comparison; invalid UTF-8 rejected; **extractors must canonicalise** | `test_json` unicode; extractor tests |
| T8 | TOCTOU: approved call differs from the call executed | approval token binds the request hash, policy hash and expiry; single-use | `gateway` approval tests |
| T9 | Replay of an approval | single-use token, short TTL | `gateway` approval tests |
| T10 | Policy tampering in transit or at rest | signed bundles (Ed25519), key id, expiry, hash per file, no downgrade | `bundle` tests |
| T11 | Stale decision served after policy or state changed | decision cache keyed on full request, policy hash and state version; cleared on reload | `sidecar` cache tests |
| T12 | Audit log altered or truncated | hash chain; verifier detects edits, reordering and truncation of the tail it can see | `audit` tests |
| T13 | Secrets in traces and logs | audit records hold hashes, not arguments; traces are opt-in and marked sensitive; redaction hook | documented |
| T14 | Poisoned tool output steers the agent into a harmful call | output never grants permission; the gateway marks untrusted provenance as an input (`arg_taint`) that policies can deny on | policy examples |
| T15 | Forged state (counters, "tests passed" flag) | state comes only from the state provider over an authenticated channel; the agent cannot supply `state` | gateway rule: `state`/`now` are set by the gateway, request fields from the agent are ignored |
| T16 | Approver impersonation | approval endpoint authenticates the approver; token carries approver id | deployment rule |
| T17 | PDP down or slow | gateway fails closed: timeout and any error mean DENY | `sidecar` fault tests |
| T18 | Rollback to an older, weaker policy | bundle `policy_version` must not decrease | `bundle` tests |

## 3. Deployment rules (required for the guarantees above)

1. The agent process gets **no credentials** for downstream tools or databases; the gateway does.
2. The network path from the agent to tools passes only through the gateway.
3. The gateway overwrites `actor`, `env`, `state` and `now` itself; it never copies them from agent input.
4. Obligations are enforced by the gateway; if it cannot perform one (for example the audit log is
   unwritable), it denies the call.
5. Policy bundles are signed offline; only public keys are configured on the sidecar.
6. Approval secrets and audit logs are not readable by the agent's user.

## 4. State-writer trust

Counters (rate limits) and flags ("tests passed") are facts about the world that YOG cannot verify.
Whoever can write them can change decisions. They must live in a store only the gateway or a dedicated
state provider can write, and the `state.version` in the request lets the audit trail show which snapshot a
decision used.

## 5. Out of scope

Compromise of the gateway or sidecar host, side channels, malicious policy authors, and the correctness of
extractors beyond the rules above. A bundle signing key leak is handled by key rotation (a new `key_id` and
an updated trusted-key list on every sidecar).
