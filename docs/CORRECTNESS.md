# Correctness

This document describes how the C implementation is validated. The contract it
is validated against is [`COMPILER.md`](COMPILER.md); the security properties
built on top of it are in [`SECURITY.md`](SECURITY.md).

The guiding rule is that **agreement with `yog.py` is not sufficient**. Shared
bugs are invisible to a differential test, so the suite also contains
expectations stated directly from the specification, a property-based oracle
that does not use the YOG solver, sanitizer runs and fuzzing.

## 1. Layers of validation

| Layer | What it establishes | Where |
| --- | --- | --- |
| Unit and semantic tests | each stage obeys its own contract | `yog/tests/{lexer,parser,sema,ir,vm,api,security}` |
| Conformance corpus | Groups A–V produce the specified decisions | `yog/tests/conformance/cases.json` |
| Property-based oracle | generated policies match a non-YOG evaluator | `yog/tests/property/property_conformance.py` |
| Differential test | C and `yog.py` agree on queries and checks | `yog/tests/differential/diff_vs_python.py` |
| Sanitizers | no leaks, use-after-free or UB on the suite | `-DYOG_SANITIZE=ON` |
| Fuzzing | malformed policies do not crash or hang | `test_fuzz_smoke`, `fuzz_compile` |
| Security tests | fail-closed limits, context isolation, concurrency | `test_security` |

## 2. Unit and semantic tests

`ctest --test-dir yog/build --output-on-failure` runs:

| Test | Protects |
| --- | --- |
| `test_lexer` | tokens, indentation, CRLF/LF, comments, error stickiness |
| `test_parser` | AST shape, grammar restrictions, error positions |
| `test_sema` | C0–C5, role conflicts, range restriction, cycles |
| `test_ir` | clause table, wildcard slots, constant interning, dump stability |
| `test_vm` | unification, backtracking, negation, comparisons, context facts, precedence |
| `test_api` | ownership, diagnostics, trace opt-in, exact reason strings |
| `test_security` | limits, fail-closed errors, context isolation, concurrency |
| `test_fuzz_smoke` | deterministic malformed-input robustness |

## 3. Conformance corpus (Groups A–V)

`all_examples.yog` is the canonical demonstration and conformance corpus. It
contains one group per policy shape, with the expected outcome recorded next to
the query. `yog/tests/conformance/cases.json` states those outcomes again,
independently of both implementations:

- 38 authorization checks, including deny override (R, V), negation (S),
  numeric comparison (T), joins (C, U), default deny and unknown actions;
- 21 query results, which exercise the logical solver (`query` does not apply
  the deny/allow contract);
- 10 compile-error cases with the exact diagnostic substring promised by
  `COMPILER.md`.

Run it:

```sh
python yog/tests/conformance/run_conformance.py
```

The distinction between `query` and `check()` is deliberate and is asserted:
`query` reports whether a clause body is satisfiable, while `check()` applies
`deny > allow > default deny`. For example, Group R's payroll query is `TRUE`
(logically the allow body is satisfiable) while its authorization result is
`DENY` because the deny clause matches.

### Group I and the schema-placeholder trap

Group I needs `amount/2` to exist for semantic rule C4 even though the amount
is supplied per request through `check(context=...)`. The obvious workaround —
`fact amount(sentinel, 0)` — is unsafe: a request whose resource happened to
name the sentinel would receive a free `0 <= Limit`. Group I therefore defines
`amount/2` as a rule with a deliberately false guard:

```yog
fact reserved_schema(reserved_account, reserved_amount)
rule amount(Account, Amount):
    reserved_schema(Account, Amount)
    0 == 1
```

The rule satisfies C4, never produces a solution, and context facts (tried
before rules) remain the only source of amounts. The conformance suite asserts
that the sentinel cannot be used as an account.

## 4. Property-based oracle

`yog/tests/property/property_conformance.py` generates random acyclic policies
with:

- positive goals over `role`, `env`, `member`, `team_role`, `owner`, `level`,
  `required`;
- joins on a shared `Team` variable;
- integer comparisons (`Level >= Needed`);
- mixed allow and deny clauses in random order.

The oracle evaluates the same facts with plain Python dictionaries and sets.
It does not use the YOG parser, unifier or solver, so it can catch a bug shared
by the C and Python engines. Current default: 80 policies × 20 requests = 1,600
decisions, seed `20261112`.

```sh
python yog/tests/property/property_conformance.py
```

The generator deliberately avoids two Team-using patterns in one clause,
because the oracle evaluates patterns independently while YOG would join them.
That shape is covered by the standalone join patterns instead. Extending the
oracle to shared-variable conjunctions is tracked as future work.

## 5. Differential test against `yog.py`

```sh
python yog/tests/differential/diff_vs_python.py
```

This runs every `query` and every ground arity-2 request in
`all_examples.yog` through both engines and compares decisions, reasons and
bindings, for both LF and CRLF input. It is a compatibility check, not the sole
oracle.

## 6. Sanitizers and fuzzing

Build with ASan + UBSan:

```sh
cmake -S yog -B yog/build-asan -DCMAKE_BUILD_TYPE=Debug -DYOG_SANITIZE=ON
cmake --build yog/build-asan --parallel
ctest --test-dir yog/build-asan --output-on-failure
```

`test_fuzz_smoke` mutates four seed policies (including Group I and a
deny/negation policy) 250 times each, then feeds 500 random byte strings
through compile, query evaluation and check. It asserts that a failed check
reports `YOG_DENY`, never `YOG_ALLOW`.

Coverage-guided fuzzing is opt-in:

```sh
cmake -S yog -B yog/build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DYOG_SANITIZE=ON -DYOG_FUZZ=ON
cmake --build yog/build-fuzz --parallel
./yog/build-fuzz/fuzz_compile -max_len=4096 -timeout=10
```

The harness links the whole pipeline, so a finding in the lexer, semantic
analyser, IR builder, unifier or engine is reachable. See
`yog/tests/fuzz/fuzz_compile.c` for a manual Clang invocation.

## 7. Coverage matrix

| Requirement | Primary evidence |
| --- | --- |
| parsing | `test_lexer`, `test_parser`, compile cases |
| semantic analysis | `test_sema`, compile cases C0–C5 |
| unification | `test_vm`, property joins |
| backtracking | `test_vm`, property multi-clause policies |
| negation | `test_vm`, Groups S/U, conformance |
| comparisons | `test_vm`, Groups T/V, property `level_ge` |
| authorization | conformance A–V, property oracle, `test_api` |
| request context | `test_vm`, `test_security`, Group I, conformance |
| memory | ASan/LSan run, repeated compile/free, fuzz smoke |
| errors and limits | compile cases, `test_security` |

## 8. Known gaps

- There is no formal proof of the solver or of the authorization contract.
- The property generator covers a restricted policy shape (positive goals,
  joins, one comparison); it is not a general policy generator.
- `test_fuzz_smoke` is deterministic and small. Long-running libFuzzer
  campaigns have not yet been run in CI.
- Mutation testing (deliberately corrupting the implementation to check that
  the suite fails) has not been set up.
- Compiler performance on large policies is measured but not optimized; see
  [`BENCHMARKS.md`](BENCHMARKS.md).
- Cross-platform CI currently runs Linux; the local Windows/Clang run is not
  yet a second CI job.

## 9. Adding a case

1. Add the request to `all_examples.yog` (or a focused policy under
   `yog/tests/`).
2. Add the independently expected decision and reason fragment to
   `yog/tests/conformance/cases.json`.
3. If it is a new error class, add the source and expected diagnostic to
   `COMPILE_CASES` in `run_conformance.py`.
4. Run the conformance, property, differential and sanitizer suites.
