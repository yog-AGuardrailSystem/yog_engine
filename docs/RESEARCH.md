# Research plan and positioning

This document records the questions YOG v1 is meant to answer, the experiments
that would answer them, and the claims that are **not** yet supported.

## 1. Working positioning

YOG is an experimental, C-based declarative policy compiler and authorization
engine. Its primary identity is **AI-agent guardrails**: a small, deterministic
decision point that an agent runtime calls before a tool invocation, API call,
shell command or financial transaction. General-purpose authorization (RBAC,
ABAC, ownership, deny overrides) is the underlying engine.

This is a working hypothesis, not an established result. The experiments below
test whether it is a useful identity: whether the language is expressive enough
for guardrail policies, whether decisions are cheap enough to sit in an agent
loop, and whether the fail-closed design survives adversarial input. If the
evidence does not support the positioning, the positioning changes.

## 2. RQ1 — performance

**Question:** what are the latency, throughput, memory and compile-time costs
of a YOG decision, and how do they scale with policy size and clause order?

**Hypotheses**

- H1.1: an in-process decision on a policy with tens of clauses is on the order
  of microseconds on commodity hardware.
- H1.2: default deny and joins scale with the number of facts/clauses because
  lookup is linear; indexing would reduce the slope.
- H1.3: process-per-request deployment is dominated by startup, so a batch or
  embedded deployment is necessary for high request volume.

**Current evidence** (local Debug build, see [`BENCHMARKS.md`](BENCHMARKS.md)):

- ~4.5 µs for the first matching allow clause, independent of corpus size;
- ~15 µs → ~885 µs for default deny as clauses grow 132 → 8,260;
- compile 0.67 ms → 224 ms over the same range;
- `yogc batch` 30,800 → 535 req/s; one `yogc check` 32 → 264 ms.

**Status:** H1.1 and H1.3 are supported locally; H1.2 is supported but the
optimization has not been implemented. No comparison with another engine has
been run.

**Next experiments:** release build; predicate/first-argument indexing; clause
ordering; cold start; Linux repeat; controlled multi-engine study.

## 3. RQ2 — expressiveness

**Question:** which authorization and guardrail patterns can YOG express
directly, and what is lost when translating to or from Cedar, OPA/Rego and
Casbin?

**Patterns to test**

| Pattern | YOG construct | Status |
| --- | --- | --- |
| RBAC | `role(User, Role)` facts and allow clauses | supported |
| ownership / team join | shared variable across atoms | supported |
| ABAC attributes | facts keyed by user/resource | supported |
| deny override | `deny` clause, fixed precedence | supported |
| negation as failure | `not atom` with bound variables | supported |
| numeric comparison | `<=`, `>=`, `==`, ... | supported |
| per-request facts | `check(context=...)` | supported |
| recursion | — | **rejected in v1** |
| aggregation / counting | — | **not expressible** |
| temporal / history | — | **not expressible** |
| obligations | — | **not expressible** |
| `or` in a body | multiple clauses | not a primitive |

**Method:** translate the shared corpus (`benchmarks/generated/`) to each
engine, compare decisions on the same requests, and record the translation
fidelity and the constructs that do not map. Casbin's standard model cannot
express the numeric clause without a custom function; that is a finding about
the comparison, not about YOG.

**Status:** adapters generate translations; no engine results yet. The
expressiveness comparison must report translation gaps explicitly, otherwise it
is not a like-for-like comparison.

## 4. RQ3 — security and reliability

**Question:** does the implementation fail closed and remain memory-safe and
isolated under adversarial policies and concurrent requests?

**Hypotheses**

- H3.1: unknown actions, evaluation errors and limit exhaustion never yield
  ALLOW.
- H3.2: request context cannot leak between checks or threads.
- H3.3: malformed policies cannot crash or hang the compiler/evaluator within
  the configured caps.

**Current evidence**

- `test_security`: step/depth limits, context isolation, 4-thread concurrency,
  repeated compile/free, fact-only context.
- `test_fuzz_smoke`: 1,500 deterministic malformed inputs.
- ASan/UBSan clean on the full C suite.
- Conformance cases for unknown actions, deny override, default deny.
- Threat model and residual risks in [`SECURITY.md`](SECURITY.md).

**Status:** supported for the tested cases. Not a proof. Long-running fuzzing,
a Linux CI sanitizer job and adversarial policy studies are still needed.

**Important negative result to preserve:** context facts are capabilities. An
agent that can choose its own context can forge `role(attacker, admin)`. The
enforcement layer must construct context from trusted data. This is documented
as a critical operational rule, not hidden as an implementation detail.

## 5. Architecture

```text
source
  -> lexer        indentation-aware tokens
  -> parser       AST with line/column
  -> sema         C0..C5: ground facts, one role per predicate,
                  range restriction, safe negation/comparison,
                  defined calls, acyclic dependencies
  -> IR           constant pool + predicate/clause table
  -> VM           unification, trail, backward chaining, negation
  -> authorization deny > allow > default deny
  -> C API/CLI    yog_compile / yog_check / yog_run_queries / yogc
```

Design choices relevant to the research questions:

- a small declarative language with no I/O, no native calls and no recursion;
- one decision predicate per action, arity 2, with explicit allow/deny clauses;
- a clause-table IR rather than bytecode, because v1 policies are acyclic and
  the table is easy to inspect and snapshot-test;
- a fresh evaluator per check, so an immutable compiled module can be shared
  across threads;
- fixed caps on steps, depth, constants, predicates, clauses, arguments and
  goals.

## 6. Limitations to state in any presentation

- No recursion, aggregation, temporal reasoning or obligations.
- No policy signing, distribution or multi-tenant isolation inside one module.
- Compile time and default-deny time grow with policy size; indexing is future
  work.
- Benchmarks are local, Debug-build, single-machine and not yet comparative.
- The property-based oracle covers a restricted policy shape.
- Fuzzing is a smoke test in CI, not a long campaign.
- The Python bindings and packaging are not part of this milestone.

## 7. Presentation outline

1. **Problem:** agents take actions; authorization must be decided before the
   action, deterministically and cheaply.
2. **Language:** facts, rules, allow/deny, negation, comparisons, context.
3. **Semantics:** backward chaining, deny > allow > default deny, fail closed.
4. **Architecture:** lexer → parser → sema → IR → VM → API/CLI.
5. **Correctness:** independent conformance A–V, property oracle, differential,
   sanitizers, fuzzing.
6. **Security:** threat model, limits, context isolation, concurrency; the
   context-is-a-capability rule.
7. **Performance:** what is measured, the scaling curve, what is not claimed.
8. **Expressiveness:** patterns supported, translation gaps to Cedar/OPA/Casbin.
9. **Limitations and next experiments.**
10. **Positioning:** what would have to be true for the AI-guardrail identity to
    be justified.

## 8. Claims policy

Until the experiments above are complete and reviewed:

- do not say YOG is faster than Cedar, OPA or Casbin;
- do not say YOG is safer or more secure in general;
- do not say YOG is more expressive;
- do say it is an experimental, fail-closed, C-based declarative engine with a
  tested authorization contract, bounded evaluation, and a reproducible
  benchmark/correctness harness.

Claims must name the workload, hardware, build type and measurement boundary.
