# YOG

An experimental, C-based declarative policy compiler and authorization engine.
YOG checks whether an application's or AI agent's action is allowed **before**
it happens, and returns **ALLOW / DENY** with the reason.

> **Status: experimental, not production-ready.** The lexer, parser, semantic
> analyser, clause-table IR, evaluator, C API and CLI are implemented and
> tested. The correctness, security and benchmark harnesses are in place. The
> Python bindings and packaging are not part of this milestone.

YOG's working identity is an **AI-agent guardrail** decision point: a small,
deterministic, fail-closed engine called before a shell command, database
write, API call or financial transaction. General authorization (RBAC, ABAC,
ownership, deny overrides) is the underlying engine. That identity is a
research hypothesis, not a completed claim; see [`docs/RESEARCH.md`](docs/RESEARCH.md).

## The decision contract

```text
fact role(alice, admin)

allow can_delete(User, DB):
    role(User, admin)
```

```console
$ yogc check policy.yog alice can_delete database_1
ALLOW|allow clause at line 3 matched
```

- **deny > allow > default deny**;
- an unknown action is denied;
- an evaluation error or limit violation is an error and the result is
  initialized to `DENY` (fail closed);
- policies are declarative: no I/O, no native calls, recursion rejected in v1.

## Repository layout

| Path | What it is |
| --- | --- |
| `all_examples.yog` | canonical demonstration and conformance corpus (Groups A–V) |
| `yog.py` | Python behavioural reference (not the sole correctness oracle) |
| `yog/` | C implementation: lexer → parser → sema → IR → VM → API → CLI |
| `yog/tests/` | C semantic/security tests, conformance, property, differential, fuzz |
| `examples/ai_guardrails/` | four runnable guardrail policies + enforcement demo |
| `benchmarks/` | corpus generator, C harness, orchestration, Cedar/OPA/Casbin adapters |
| `docs/COMPILER.md` | frozen language and compiler contract |
| `docs/ARCHITECTURE_CHEATSHEET.md` | plain-language architecture and file guide |
| `docs/CORRECTNESS.md` | how correctness is validated |
| `docs/SECURITY.md` | threat model, limits, context-isolation rules |
| `docs/BENCHMARKS.md` | benchmark methodology and local results |
| `docs/RESEARCH.md` | RQ1–RQ3, positioning, limitations, presentation outline |
| `yog/README.md` | architecture, build, test and C API guide |

## Build and test

```sh
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug
cmake --build yog/build --parallel
ctest --test-dir yog/build --output-on-failure

python yog/tests/conformance/run_conformance.py --yogc yog/build/yogc
python yog/tests/property/property_conformance.py
python yog/tests/differential/diff_vs_python.py --yogc yog/build/yogc
python -m pytest yog/tests -q
```

Sanitizers (GCC/Clang):

```sh
cmake -S yog -B yog/build-asan -DCMAKE_BUILD_TYPE=Debug -DYOG_SANITIZE=ON
cmake --build yog/build-asan --parallel
ctest --test-dir yog/build-asan --output-on-failure
```

On Windows, use a Visual Studio developer prompt (or run `vcvars64.bat`) so
`cl`/`nmake` and the Windows SDK are on `PATH`. See
[`yog/README.md`](yog/README.md) for details.

## AI guardrail demo

```sh
python examples/ai_guardrails/enforce_demo.py
```

The four policies cover shell commands, database writes, external API calls and
financial transfers. The demo includes unknown actions and malformed context to
show the fail-closed path. See
[`examples/ai_guardrails/README.md`](examples/ai_guardrails/README.md).

## Correctness and security

Correctness is validated by independent semantic tests, a conformance corpus
with hard-coded expected outcomes, a property-based oracle that does not use the
YOG solver, differential testing against `yog.py`, ASan/UBSan and fuzzing. See
[`docs/CORRECTNESS.md`](docs/CORRECTNESS.md).

The security model states the trust boundaries, the fail-closed contract,
evaluation limits and the concurrency contract. The most important operational
rule: **request context is authorization data**. An agent that controls its own
context can forge facts, so context must be built by the trusted enforcement
layer. See [`docs/SECURITY.md`](docs/SECURITY.md).

## Benchmarks

The suite separates engine latency from end-to-end CLI cost and reports p50,
p95, p99, throughput and approximate RSS. It also generates Cedar, OPA and
Casbin translations. The first results are local Debug-build measurements and
are **not** a comparison with other engines; see
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Contributing

- Never push to `main` directly. It is protected.
- Create a branch: `feature/<what-you-are-doing>`.
- Open a pull request into `main`; an admin must approve.

## License

MIT, see [LICENSE](LICENSE).
