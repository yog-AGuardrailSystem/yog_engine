# Security model

YOG is an authorization engine for actions proposed by applications and AI
agents. This document states what it protects, what it assumes, and where the
remaining risk is. It is a threat model for the current v1 implementation, not
a claim that the implementation is production-ready.

## 1. Assets and non-goals

**Assets**

- the integrity of the compiled policy (a policy must not silently change);
- the correctness of each ALLOW/DENY decision (fail closed);
- isolation between requests (one request's context must not affect another);
- availability under adversarial or malformed policy input;
- memory safety of the compiler and evaluator.

**Non-goals for v1**

- authenticating the caller or the policy author;
- protecting the host from a malicious embedder that links the library;
- distributed policy distribution, signing or revocation;
- enforcing obligations (logging, redaction, approval workflows) after a
  decision;
- sandboxing arbitrary native code — YOG policies contain no I/O or native
  calls.

## 2. Trust boundaries

| Component | Trust | Consequence |
| --- | --- | --- |
| Policy source | **untrusted** in multi-tenant use | bounded by caps, acyclic rules, fail-closed evaluation |
| Request (`actor`, `action`, `resource`) | untrusted input | treated as constant text, never parsed as policy |
| Context facts | **must be trusted** | facts can grant capabilities; see §5 |
| Embedding process | trusted | owns the `Yog`, chooses limits and when to check |
| Compiled module | trusted after `yog_compile()` | immutable and shareable between threads |

### Critical rule: context is authorization data

`yog_check(..., context, ...)` accepts ground facts such as
`fact amount(acct_1, 9000)`. Those facts are logically appended to the policy.
If an agent can choose its own context, it can forge facts:

```text
fact role(attacker, admin)
```

Such a context may satisfy an admin rule. **Never pass model-generated or
end-user-generated context text to `yog_check()` without validation.** Build
context in the trusted enforcement layer from data the policy is meant to
trust (for example, the authenticated amount from a payment service), or
validate it against a fixed schema before passing it.

The context parser rejects anything other than `fact` statements, but that is
a structural check, not an authorization check.

## 3. Threat model

| Threat | Control | Evidence |
| --- | --- | --- |
| Unknown action is allowed | unknown decisions default to DENY | `test_unknown_action_denies`, conformance |
| Evaluation error becomes ALLOW | errors return `false`; `result->decision` is set to `YOG_DENY` before any work | `test_security` |
| Deny bypassed by clause order | contract always tries all deny clauses before allow clauses | Group R/V, `test_vm`, conformance |
| Recursion or cyclic rules exhaust the stack | C5 rejects recursion; depth and step caps bound the rest | `test_sema`, `test_security` |
| Malformed policy crashes the compiler | parser/sema diagnostics, sanitizers, fuzzing | `test_fuzz_smoke`, `fuzz_compile` |
| Huge policy exhausts memory | constant/predicate/clause/query/arg/goal caps | `docs/COMPILER.md` §8 |
| One request's context leaks into another | fresh evaluator per check, context module owned per call | `test_security` concurrency and isolation |
| Concurrent checks corrupt state | module is immutable; each check owns its store and trace | `test_security` (4 threads × 300 checks) |
| Agent supplies forged context | documented trust rule; context is facts only | this document §2, example README |
| Sensitive values leak through trace/reason | trace is opt-in; reasons contain clause lines, not bindings | `test_api`, `yogc` design |

## 4. Fail-closed contract

`yog_check()` returns:

- `true` + `YOG_ALLOW` — an allow clause matched and no deny clause did;
- `true` + `YOG_DENY` — a deny clause matched, no clause matched, or the
  action is unknown;
- `false` — a compile/evaluation error; `error.message` explains it.

On `false`, the result is still initialized with `result->decision ==
YOG_DENY`, so a caller that ignores the return value cannot accidentally treat
the error as an allow. Callers should still log and deny on `false`.

`yogc` follows the same rule: exit `0` allowed, `3` denied, `1` compile error,
`2` usage/I/O error. A wrapper must treat `1`/`2` as deny, not allow.

## 5. Request context isolation

Each `yog_check()` call:

1. parses and validates the context string into a temporary module;
2. creates a fresh engine with its own substitution store and trace buffer;
3. evaluates against the immutable compiled module;
4. frees the engine and context module.

No context fact is stored in the `Yog`. A subsequent call cannot observe a
previous context. The security test interleaves ALLOW, no-context, over-limit
and boundary requests, then runs four threads with different contexts against
the same `Yog`.

Context strings may use `;` or newlines between facts. Leading whitespace on
the first fact is ignored; a non-`fact` statement is rejected with
`request context may only contain fact statements`.

## 6. Resource limits

Policies are untrusted input. The default caps are:

| Limit | Default | Where |
| --- | --- | --- |
| evaluation steps per check | 1,000,000 | `YOG_VM_MAX_STEPS` |
| evaluation depth per check | 256 | `YOG_VM_MAX_DEPTH` |
| constants per module | 65,536 | `YOG_IR_MAX_VALUES` |
| predicates per module | 4,096 | `YOG_IR_MAX_PREDICATES` |
| clauses per module | 65,536 | `YOG_IR_MAX_CLAUSES` |
| queries per module | 4,096 | `YOG_IR_MAX_QUERIES` |
| arguments per atom | 64 | `YOG_IR_MAX_ARGS` |
| goals per clause | 256 | `YOG_IR_MAX_GOALS` |
| lexer nesting | 64 | `YOG_LEXER_MAX_INDENT` |

Steps and depth can be lowered per deployment:

```c
YogLimits limits = { .max_steps = 50000, .max_depth = 64 };
yog_set_limits(yog, limits);
```

Exceeding a limit is an evaluation error (`false`), never a partial or allowed
result. `test_security` forces both limits and asserts the error text and the
fail-closed decision.

Limits are a mitigation, not a hard real-time guarantee: a single clause can
still touch many facts before the step counter trips. Size policies and set
limits for the workload.

## 7. Concurrency contract

- `Yog` is immutable after `yog_compile()`.
- `yog_check()` and `yog_run_queries()` create their own engine, store and
  trace; concurrent calls on the same `Yog` are safe.
- `yog_set_limits()` mutates the `Yog`; call it during setup, before sharing
  the object. Concurrent `yog_set_limits()` with checks is a data race.
- `yog_free()` must not run while a check is in flight.

The module's text slices point into the compiler-owned source, which lives
until `yog_free()`. Do not free the `Yog` while another thread is using it.

## 8. Known limitations and residual risk

- **No policy signing or provenance.** A policy that reaches `yog_compile()` is
  trusted to be the intended policy. Verify policy files out of band (signed
  artifacts, review, immutable deployment).
- **No per-tenant isolation inside one module.** Compile one module per tenant
  if tenants must not share predicates.
- **No time/memory quota per request.** Step and depth caps bound CPU work, but
  the process RSS is not capped by the engine.
- **No recursion or aggregation.** This is a language limitation, not a safety
  guarantee; it also means some policies cannot be expressed and must be
  precomputed.
- **Context is a capability.** See §2. This is the most important operational
  rule in this document.
- **Trace may contain request values.** Traces include actor, action and
  resource text and bound values; treat trace output as sensitive and enable it
  only for debugging.
- **Fuzzing is not exhaustive.** `test_fuzz_smoke` runs on every build; a
  long-running libFuzzer campaign is still recommended before a production
  deployment.
- **The engine is not a sandbox.** It parses and evaluates a declarative
  language; it does not execute user code.

## 9. Security test map

| Test | Assertion |
| --- | --- |
| `test_step_limit_fails_closed` | error + `YOG_DENY` at the step cap |
| `test_depth_limit_fails_closed` | error + `YOG_DENY` at the depth cap |
| `test_context_is_isolated_between_checks` | context never survives a call |
| `test_context_rejects_non_facts` | context cannot contain rules/allow/deny |
| `test_repeated_compile_and_free` | ownership is clean under ASan |
| `test_concurrent_checks` | different contexts on one module stay independent |
| `test_fuzz_smoke` | malformed input never yields ALLOW on error |
| `test_unknown_action_denies` | unknown actions fail closed |

## 10. Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Contact the
maintainers privately with a minimal reproducer, the build configuration, and
the expected versus actual decision. Include whether the issue affects
confidentiality (context leakage), integrity (decision bypass) or availability
(hang/crash).
