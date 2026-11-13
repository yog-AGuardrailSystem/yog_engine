# Benchmarks

This document describes the benchmark methodology and the first local results.
It deliberately does **not** claim that YOG is faster, safer or more expressive
than Cedar, OPA or Casbin. Those claims require measurements on the same
hardware, build flags and semantics; the adapters exist so that such a study can
be run and reviewed.

## 1. Research question

RQ1 (from [`RESEARCH.md`](RESEARCH.md)): *what is the latency, throughput and
memory cost of a YOG decision, and how does it scale with policy size?*

The benchmark separates two costs that are often conflated:

- **runtime** — compile once, then time `yog_check()` repeatedly;
- **end-to-end** — invoke the `yogc` process, including startup, policy load,
  plumbing and output.

An AI guardrail usually cares about runtime on a long-lived process. A CLI
deployment or a per-request subprocess cares about end-to-end.

## 2. Workload

`benchmarks/gen_corpus.py` deterministically generates three policies with the
same shape:

| Corpus | Users | Resources | Predicates | Clauses | Constants |
| --- | ---: | ---: | ---: | ---: | ---: |
| small | 20 | 30 | 7 | 132 | 66 |
| medium | 200 | 200 | 7 | 1,058 | 432 |
| large | 2,000 | 1,000 | 7 | 8,260 | 3,112 |

Facts: `role`, `member`, `team_resource`, `public`, `clearance`,
`classification`. One decision predicate has four allow clauses:

1. admin role;
2. `member(User, Team)` + `team_resource(Team, Resource)` — a join;
3. manager + public resource;
4. `clearance(User, Level) >= classification(Resource, Needed)`.

Four requests are measured:

- **admin allow** — first allow clause matches quickly;
- **team join allow** — a two-atom join;
- **guest default deny** — every allow clause fails;
- **low clearance deny** — a numeric comparison fails after binding.

The deny cases are intentionally the expensive path: with no index, the engine
tries all four allow clauses and their facts before returning default deny. This
is the honest worst case for a fail-closed system.

## 3. Method

- Harness: `yog/tests/bench/bench_yog.c`, linked directly to `yog_api`.
- Timing: `QueryPerformanceCounter` on Windows, `CLOCK_MONOTONIC` elsewhere.
- Warm-up: at least 100 checks before sampling.
- Percentiles: nearest-rank over per-call samples (`p50`, `p95`, `p99`).
- Throughput: samples ÷ wall-clock elapsed.
- Memory: resident set before compile and after the measured checks, read from
  the OS; this is approximate and includes allocator slack.
- Orchestration: `benchmarks/run_benchmarks.py` writes
  `benchmarks/results/local.json` and `local.md`.

The results below are a local **Debug** build on Windows 11 with Clang 22
(`-O0 -g`, sanitizers off). They are not production numbers. A release build
with `-O2`/`-O3` and a different allocator will differ.

Reproduce:

```sh
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug
cmake --build yog/build
python benchmarks/run_benchmarks.py
```

## 4. First local results

Full tables: [`../benchmarks/results/local.md`](../benchmarks/results/local.md).
Summary (µs per engine check; lower is better):

| Corpus | admin allow | team join allow | guest deny | low-clearance deny | compile (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| small | 4.5 | 7.0 | 15.7 | 15.5 | 0.67 ms |
| medium | 4.3 | 25.2 | 96.6 | 99.6 | 7.7 ms |
| large | 4.6 | 211 | 885 | 884 | 224 ms |

End-to-end and batch:

| Corpus | one `yogc check` (mean) | `yogc batch` throughput | batch mismatches |
| --- | ---: | ---: | ---: |
| small | 32.2 ms | 30,800 req/s | 0 |
| medium | 40.0 ms | 9,850 req/s | 0 |
| large | 263.9 ms | 535 req/s | 0 |

Memory (RSS, approximate):

| Corpus | before compile | after checks | delta |
| --- | ---: | ---: | ---: |
| small | 3,964 KiB | 4,408 KiB | +444 KiB |
| medium | 3,996 KiB | 4,912 KiB | +916 KiB |
| large | 4,184 KiB | 9,328 KiB | +5,144 KiB |

### Observations (not claims)

- **Fast path is flat.** The admin clause costs ~4.5 µs regardless of corpus
  size because it matches the first fact of the first allow clause.
- **Default deny scales with policy size.** It is ~15 µs on the small corpus and
  ~885 µs on the large one. The engine currently scans clauses/facts linearly.
  This is the main optimization target for RQ1: indexing by predicate and by
  first argument, and clause ordering, would change the shape of this curve.
- **Compile time grows superlinearly.** 0.67 ms → 7.7 ms → 224 ms for
  132 → 1,058 → 8,260 clauses. Likely contributors: linear symbol-table
  lookups during semantic analysis and cycle detection. This is a real cost for
  per-request subprocess deployment; compile once and share the module.
- **Process startup dominates end-to-end.** A single `yogc check` costs tens to
  hundreds of milliseconds, while the decision itself is microseconds. Batch
  mode amortizes startup and is the right shape for high request volume.
- **The large policy is not necessarily representative.** It was generated to
  stress scaling, not to model a real tenant.

## 5. Cross-engine adapters

`benchmarks/adapters/` translates the same corpus for Cedar, OPA/Rego and
Casbin:

| Adapter | Translation | Status in this environment |
| --- | --- | --- |
| `opa_adapter.py` | facts → `data.json`, four clauses → Rego set rules | generated; `opa` not installed |
| `cedar_adapter.py` | users/resources → Cedar entities, clauses → four `permit` rules | generated; `cedar` not installed |
| `casbin_adapter.py` | role/team/public → `g`/`g2` RBAC; **no numeric clause** | generated; Python `casbin` not installed |

The adapters write their translations under
`benchmarks/results/translations/<engine>/<size>/` so the mapping can be
reviewed even when the engine is unavailable. When a tool is missing they emit
`available: false` and no timing numbers. They do not fabricate results.

Run an adapter:

```sh
python benchmarks/adapters/opa_adapter.py --size small
python benchmarks/adapters/cedar_adapter.py --size small
python benchmarks/adapters/casbin_adapter.py --size small
```

### Fairness checklist for a future comparison

1. Same hardware, OS, CPU frequency policy and background load.
2. Same semantics: deny > allow > default deny, unknown action denied, negation
   and numeric comparison where the engine supports them.
3. Same workload: identical facts, requests and allowed/denied mix.
4. Same measurement boundary: in-process decision vs process invocation.
5. Warm-up and enough samples for p95/p99; report the distribution, not only
   the mean.
6. Record build type, compiler, versions and whether caches are warm.
7. Publish the adapter code and generated inputs with the numbers.
8. Include a cold-start and a steady-state measurement.

Casbin's standard model cannot express the numeric clearance clause without a
custom function; any Casbin result must state that it covers a subset of the
corpus. This is why the adapter records `numeric_clause: false`.

## 6. Threats to validity

- Debug build, no CPU pinning, Windows desktop noise.
- The corpus is generated and regular; real policies have different clause
  ordering and cardinalities.
- The four requests do not represent the full distribution of actor/resource
  pairs.
- RSS includes the Python/OS process around the C harness; the deltas are
  indicative, not a heap profile.
- No long-running soak test yet.
- The benchmark is a single-machine study, not a controlled multi-engine
  experiment. No comparative claim is made.

## 7. Next experiments

1. Release build (`-O2`) and a repeat run on Linux CI for a second data point.
2. Index predicates and first arguments; re-measure default deny and joins.
3. Vary clause order to quantify the cost of a deny/allow scan.
4. Add a cold-start measurement that includes file I/O.
5. Install Cedar and OPA in a controlled environment and run the fairness
   checklist above.
6. Add a memory ceiling experiment for adversarial policies near the caps.
