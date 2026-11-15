# Benchmarks

This document describes the benchmark methodology, the local results, and the
cross-engine comparison. It deliberately does **not** claim that YOG is faster,
safer or more expressive than Cedar, OPA or Casbin. Numbers are reported by
measurement boundary, and differences in language runtime, policy model and
coverage are stated instead of hidden.

## 1. Research question

RQ1 (from [`RESEARCH.md`](RESEARCH.md)): *what is the latency, throughput and
memory cost of a YOG decision, and how does it scale with policy size?*

Two costs are separated:

- **runtime** — compile once, then time `yog_check()` repeatedly;
- **end-to-end** — invoke the `yogc` process, including startup, policy load,
  plumbing and output.

The cross-engine study adds a third distinction:

- **cli-process** — every sample spawns a process (`yogc check`, `opa eval`,
  `cedar authorize`);
- **library** — decisions inside a long-lived process (YOG's C engine and
  Casbin's Python enforcer).

CLI and library numbers are never mixed, and Casbin/YOG library numbers are
labelled as cross-language because one engine is C and the other is Python.

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
  With fewer than 100 samples, `p99` is the maximum; this is stated with each
  table.
- Throughput: samples ÷ wall-clock elapsed.
- Memory: resident set before compile and after the measured checks, read from
  the OS; this is approximate and includes allocator slack.
- Every adapter verifies the decision against the corpus and aborts on a
  mismatch rather than timing the wrong answer.

Reproduce the YOG-only study:

```sh
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug
cmake --build yog/build
python benchmarks/run_benchmarks.py
```

Reproduce the cross-engine comparison (Release `yogc` + `bench_yog`):

```sh
cmake -S yog -B yog/build-release -DCMAKE_BUILD_TYPE=Release
cmake --build yog/build-release
python benchmarks/gen_corpus.py
python benchmarks/compare.py
```

The comparison driver writes `benchmarks/results/comparison.json`,
`comparison.md` and `versions.json`.

## 4. YOG-only results

### 4.1 Debug build, first local run

Local **Debug** build on Windows 11 with Clang 22 (`-O0 -g`, sanitizers off).
Not production numbers.

Engine checks, mean µs:

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

### 4.2 Release build, library boundary

MSVC Release (`-O2`), same machine and corpus, measured by `bench_yog`.

| Corpus | admin allow | team join allow | guest deny | low-clearance deny | compile (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| small | 1 µs (p50) | 3 µs | 8 µs | 8 µs | 0.27 ms |
| medium | 1 µs | 14 µs | 57 µs | 57 µs | 4.2 ms |
| large | 1 µs | 140 µs | 559 µs | 559 µs | 122 ms |

Full p50/p95/p99 values are in
[`../benchmarks/results/comparison.md`](../benchmarks/results/comparison.md).
The Release build roughly halves the deny path and cuts compile time on the
large corpus from ~224 ms to ~122 ms.

### Observations (not claims)

- **Fast path is flat.** The admin clause costs ~1–2 µs in Release regardless
  of corpus size because it matches the first fact of the first allow clause.
- **Default deny scales with policy size.** It is ~8 µs on the small corpus and
  ~559 µs on the large one. The engine currently scans clauses/facts linearly.
  This is the main optimization target for RQ1.
- **Compile time grows superlinearly.** 0.27 ms → 4.2 ms → 122 ms for
  132 → 1,058 → 8,260 clauses. Likely contributors: linear symbol-table
  lookups during semantic analysis and cycle detection.
- **Process startup dominates end-to-end.** A single `yogc check` costs tens to
  hundreds of milliseconds, while the decision itself is microseconds.

## 5. Cross-engine comparison

### 5.1 What was measured

| Engine | Version | Boundary | Translation coverage |
| --- | --- | --- | --- |
| YOG | source commit in `comparison.md` | cli-process + C library | full corpus |
| OPA | 1.22.4 | cli-process (`opa eval`) | full corpus |
| Cedar | cedar-policy-cli 4.14.1 | cli-process (`cedar authorize`) | full corpus |
| Casbin | Python 1.43.0 | Python library | **no numeric clause** |

Every one of the 60 engine × size × request rows returned the expected decision.
Casbin cannot express the numeric clearance clause in its standard model; the
adapter records `numeric_clause: false`. The four requests still have the same
outcome without it, but Casbin is covering a subset of the policy.

### 5.2 CLI-process boundary (p50, µs)

Includes process startup, policy/entity load and output. N per request per run
is 30 (small), 20 (medium), 10 (large); the cell is the median of two runs.

| Corpus | Request | YOG `yogc check` | OPA `opa eval` | Cedar `cedar authorize` |
| --- | --- | ---: | ---: | ---: |
| small | admin allow | 31,865 | 101,698 | 127,715 |
| small | team join allow | 33,058 | 100,692 | 128,959 |
| small | guest deny | 32,429 | 112,637 | 128,238 |
| small | low clearance deny | 32,576 | 112,957 | 129,782 |
| medium | admin allow | 39,758 | 108,349 | 603,186 |
| medium | team join allow | 41,569 | 101,988 | 594,456 |
| medium | guest deny | 40,422 | 108,800 | 588,102 |
| medium | low clearance deny | 40,507 | 96,881 | 602,437 |
| large | admin allow | 146,710 | 114,425 | 4,350,820 |
| large | team join allow | 149,792 | 110,677 | 4,455,915 |
| large | guest deny | 151,022 | 107,662 | 4,241,234 |
| large | low clearance deny | 146,686 | 104,216 | 4,392,226 |

Interpretation, limited to this boundary:

- YOG's CLI cost tracks its compile time: ~32 ms on small, ~147–151 ms on
  large.
- OPA is essentially flat at ~97–115 ms; policy/data loading is fast relative
  to its process startup.
- Cedar grows with the entity set: ~128 ms on small, ~588–603 ms on medium and
  ~4.24–4.46 s on large. The measurement includes loading and hierarchy
  construction for 50 → 400 → 3,000 entities per invocation. This is a property
  of the CLI setup, not a claim about Cedar's decision speed once loaded.

These numbers do **not** establish that one engine is faster in general. They
describe process-per-request deployment on one machine.

### 5.3 Library boundary (p50, µs)

In-process decisions only. YOG is C and Casbin is Python; the languages and
runtimes differ, so this is cross-language. YOG: 5,000 / 2,000 / 500 samples
(small/medium/large). Casbin: 200 / 100 / 30 samples × 2 runs.

| Corpus | Request | YOG C library | Casbin Python |
| --- | --- | ---: | ---: |
| small | admin allow | 1 | 164 |
| small | team join allow | 3 | 185 |
| small | guest deny | 8 | 230 |
| small | low clearance deny | 8 | 234 |
| medium | admin allow | 1 | 196 |
| medium | team join allow | 14 | 225 |
| medium | guest deny | 57 | 587 |
| medium | low clearance deny | 57 | 418 |
| large | admin allow | 1 | 152 |
| large | team join allow | 140 | 162 |
| large | guest deny | 559 | 1,398 |
| large | low clearance deny | 559 | 1,411 |

Casbin remains under ~2.6 ms at p99; YOG's large-corpus deny path is ~1.4 ms at
p99. No general conclusion follows from a C/Python comparison, and Casbin's
policy is a documented subset.

### 5.4 Fairness checklist for future comparisons

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

## 6. Threats to validity

- Local Windows 11 desktop, no CPU pinning, no control for background load.
- CLI timings include process startup and, for Cedar, entity loading; they are
  not isolate-the-decision measurements.
- Casbin covers a subset of the corpus (no numeric clearance clause).
- The corpus is generated and regular; real policies have different clause
  ordering and cardinalities.
- The four requests do not represent the full distribution of actor/resource
  pairs.
- RSS includes the OS process around the C harness; deltas are indicative, not
  a heap profile.
- Peak RSS for OPA/Cedar child processes and concurrent request throughput are
  not measured.
- Large-corpus CLI runs use N = 10, so p99 equals the maximum there.
- No long-running soak test yet.

## 7. Next experiments

1. Repeat the comparison on Linux CI with the same pinned versions.
2. Index predicates and first arguments; re-measure default deny and joins.
3. Vary clause order to quantify the cost of a deny/allow scan.
4. Add a cold-start measurement that includes file I/O.
5. Add concurrent-load throughput and peak-RSS measurement for child processes.
6. Add a memory ceiling experiment for adversarial policies near the caps.
7. Increase large-corpus sample counts for Cedar once its load cost is isolated
   from the decision cost.
