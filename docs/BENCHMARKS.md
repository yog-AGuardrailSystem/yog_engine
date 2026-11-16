# Benchmarks

This document describes the benchmark methodology, the measurement boundaries,
the results, and the limits of what they support. It deliberately does **not**
claim that YOG is faster, safer or more expressive than Cedar, OPA or Casbin.
Numbers are reported by boundary, differences in language runtime and policy
coverage are stated instead of hidden, and at least one measured workload where
a competitor wins is reported.

The analysis plan and its expected losses are in
[`PREREGISTRATION.md`](PREREGISTRATION.md). The self-review checklist is in
[`BENCHMARK_REVIEW.md`](BENCHMARK_REVIEW.md).

## 1. Questions and boundaries

RQ1 (from [`RESEARCH.md`](RESEARCH.md)): *what is the latency, throughput and
memory cost of a YOG decision, and how does it scale with policy size?*

A single number per engine conflates four different costs. They are measured and
reported separately:

| Boundary | What it includes | Why it exists |
| --- | --- | --- |
| **cold** | fresh process, engine startup, policy/entity load, one decision, output | process-per-request deployment |
| **load** | compile/parse/prepare only, inside a warm process | policy onboarding cost |
| **warm** | steady-state decision after a warm-up | the cost an embedded engine pays per request |
| **service** | persistent OPA server over HTTP keep-alive | OPA's intended deployment shape |

Within each of those, the comparison is **same-runtime**: engines are paired only
when they execute in the same language runtime, in process.

| Pairing | YOG side | Competitor | Symmetry |
| --- | --- | --- | --- |
| `python-in-process` | ctypes binding | Casbin Python enforcer | both CPython |
| `rust-in-process` | safe Rust wrapper | Cedar Rust SDK | both Rust |
| `go-in-process` | Go binding over the C ABI | OPA Go SDK | **asymmetric**: only YOG crosses an FFI boundary |
| `c-reference` | native C harness | none | context only, cross-language |

The earlier first pass compared the YOG C library with Casbin's Python enforcer
and CLI-to-CLI. Those rows are not fairness evidence and are no longer used for
a superiority claim.

## 2. Workload

`benchmarks/gen_corpus.py` deterministically generates two profiles at three
sizes.

| Corpus | Users | Teams | Resources | Allow clauses (`common`) |
| --- | ---: | ---: | ---: | ---: |
| small | 20 | 5 | 30 | 3 |
| medium | 200 | 20 | 200 | 3 |
| large | 2,000 | 100 | 1,000 | 3 |

**`common`** — feature-matched; every engine can express it directly:

1. admin role;
2. `member(User, Team)` + `team_resource(Team, Resource)`;
3. manager + public resource.

**`full`** — adds a fourth clause,
`clearance(User, Level) >= classification(Resource, Needed)`. Casbin's standard
model cannot express it, so `full` is used only to measure the cost of that
gap. It is not the fair-comparison corpus.

The four canonical timed requests are:

- **admin allow** — first allow clause matches immediately;
- **team join allow** — a two-atom join;
- **guest default deny** — every allow clause fails;
- **unmapped deny** — every allow clause fails on a sentinel resource.

`benchmarks/gen_requests.py` additionally emits 300 deterministic requests per
profile and size, with expected outcomes from an independent oracle. They cover
admin, team-join, manager+public, clearance boundary, sentinel-deny and random
actor/resource pairs. Timing uses the four canonical requests; agreement uses
all 300.

## 3. Method

- **Runs:** 10 independent runs; 500 timed calls per request per run, after 50
  warm-up calls.
- **Statistic:** median of the 10 run medians. Pooled p95/p99 are reported in
  `benchmarks/results/boundaries.md`.
- **Interval:** 95% percentile bootstrap over the 10 run medians (1,000
  resamples, fixed seed). It quantifies sampling noise only.
- **Pinning:** the driver pins itself and its children to one CPU before
  measuring (`--pin-cpu 0`).
- **Decision gate:** every adapter checks the expected decision and aborts the
  run on a mismatch. No timing is ever reported for a wrong answer.
- **Clock:** `QueryPerformanceCounter` on Windows, `CLOCK_MONOTONIC` elsewhere.
  The Go harness uses `QueryPerformanceCounter` on Windows because `time.Now`
  is too coarse for microsecond decisions there.
- **Versions:** pinned in `benchmarks/results/versions.json`: OPA 1.22.4,
  `cedar-policy` 4.14.1, Casbin 1.43.0, YOG at the recorded commit.

### Reproduce

```sh
# C engine + shared library + bench harness
cmake -S yog -B yog/build-release -DCMAKE_BUILD_TYPE=Release
cmake --build yog/build-release

# bindings and competing SDK harnesses
python -m pip install casbin
cargo build --release --manifest-path bindings/rust/Cargo.toml
cargo build --release --manifest-path benchmarks/adapters/cedar_rust/Cargo.toml
go build -o benchmarks/results/bin/opa-bench ./benchmarks/adapters/opa_go
go build -o benchmarks/results/bin/yog-go-bench ./benchmarks/adapters/yog_go

# corpus, semantic equivalence, official validators, measurements
python benchmarks/gen_corpus.py
python benchmarks/gen_requests.py
python benchmarks/equivalence.py
python benchmarks/validate_translations.py
python benchmarks/compare.py --pin-cpu 0
python benchmarks/boundaries.py --pin-cpu 0
```

Artifacts: `comparison.json/md`, `boundaries.json/md`, `equivalence.json/md`,
`validation.json/md`, `versions.json`.

## 4. Feature gap (measured, not hidden)

| Feature | YOG | OPA / Rego | Cedar | Casbin (standard model) |
| --- | --- | --- | --- | --- |
| ground facts | `fact p(...)` | `data` documents | entities | policy CSV rules |
| RBAC | `role(User, Role)` | `data.role[user]` | group membership | `g` rules |
| ownership / join | shared variable | `some` + membership | `principal in resource.owner` | matcher + custom function |
| attribute flag | `public(Resource)` | `data.public` | `resource.public` | model column |
| numeric comparison | `>=` on bound integers | `>=` | `>=` | **not in the standard matcher** |
| deny override | `deny` clause, fixed precedence | explicit deny rules | `forbid` | `deny` model |
| negation as failure | `not atom` | `not` | `!` / `unless` | not in matcher |
| per-request facts | `context` string | `input` | request context | request values |
| recursion | rejected in v1 | supported | not supported | n/a |
| aggregation / counting | not expressible | comprehensions | not supported | not supported |

The numeric row is the only gap that changes an outcome in this corpus. On the
`full` profile, Casbin disagrees with the oracle on 46/300 (small), 41/300
(medium) and 60/300 (large) requests — 147 of 900. Every mismatch is a request
whose allow decision depends on `clearance >= classification`. That is the
measured cost of the gap, not a Casbin defect and not a translation failure.

## 5. Independent validation

Timing is only meaningful if all engines answer the same question.

- **Independent oracle.** `benchmarks/oracle.py` re-implements the corpus
  semantics without importing YOG, any binding or any adapter.
- **Decision gate.** `compare.py`, `boundaries.py` and `equivalence.py` abort on
  an unexpected decision.
- **Two Cedar translations.** `policy.cedar` (three/four permits) and
  `policy_alt.cedar` (one permit, disjunction) are written independently. Both
  reproduce the oracle on all 1,800 requests.
- **Official validators.** `yogc validate`, `opa check` and `cedar validate`
  accept every generated artifact for both profiles and all sizes. Casbin has
  no official static validator; it is exercised by the equivalence workload.
- **Totals.** 12,600 decisions compared (7 engine configurations × 2 profiles ×
  3 sizes × 300 requests). Unexpected mismatches: **0**. Expected feature-gap
  mismatches: 147 (Casbin, `full`).

Agreement on 1,800 requests is evidence about this corpus, not a proof of
language equivalence. There is no external human reviewer; see
[`BENCHMARK_REVIEW.md`](BENCHMARK_REVIEW.md).

## 6. Warm, same-runtime results (p50 µs)

Windows 11, MSVC Release, 10 runs × 500 calls, pinned to one CPU. Full intervals
and p95/p99 are in `benchmarks/results/comparison.md` and `boundaries.md`.

### 6.1 Python runtime (YOG-Python vs Casbin)

| Corpus | Request | YOG-Python | Casbin |
| --- | --- | ---: | ---: |
| small | admin allow | 8.7 | 132.7 |
| small | team join allow | 10.5 | 152.6 |
| small | guest deny | 12.5 | 206.6 |
| small | unmapped deny | 12.5 | 197.7 |
| medium | admin allow | 8.7 | 129.7 |
| medium | team join allow | 21.2 | 151.3 |
| medium | guest deny | 41.6 | 378.4 |
| medium | unmapped deny | 41.7 | 187.2 |
| large | admin allow | 8.7 | 132.4 |
| large | team join allow | 133.6 | 150.9 |
| large | guest deny | 364.2 | 1,350.8 |
| large | unmapped deny | 358.9 | 1,373.3 |

Within CPython, YOG is faster on every row. Casbin's three-atom matcher is
generic and interpreted; the YOG call crosses ctypes into the C engine, so the
comparison already includes binding overhead.

### 6.2 Rust runtime (YOG-Rust vs Cedar Rust SDK)

| Corpus | Request | YOG-Rust | Cedar SDK |
| --- | --- | ---: | ---: |
| small | admin allow | 1.8 | 10.9 |
| small | team join allow | 3.5 | 10.2 |
| small | guest deny | 5.4 | 8.7 |
| small | unmapped deny | 5.4 | 8.7 |
| medium | admin allow | 1.6 | 10.6 |
| medium | team join allow | 13.8 | 10.0 |
| medium | guest deny | 34.2 | 8.8 |
| medium | unmapped deny | 34.1 | 8.7 |
| large | admin allow | 1.8 | 10.5 |
| large | team join allow | 121.8 | 10.4 |
| large | guest deny | 345.4 | 8.8 |
| large | unmapped deny | 344.8 | 8.8 |

**This is the important negative result.** Cedar's decision cost is almost
constant (~8–11 µs) across corpus sizes, while YOG's default-deny and join
paths scan facts linearly and grow to ~350 µs. On the large corpus Cedar is
**40× faster** than YOG on deny and 12× faster on the team join, despite YOG's
compile step being cheaper. YOG only wins the first-match (`admin`) path.
No general "YOG is faster than Cedar" claim is possible, and none is made.

### 6.3 Go runtime (YOG-Go vs OPA Go SDK)

YOG-Go is a Go binding over the C ABI. It pays a syscall/cgo crossing on every
decision; OPA is native Go and pays none. Read this as an upper bound on YOG's
cost and a lower bound on OPA's.

| Corpus | Request | YOG-Go | OPA Go SDK |
| --- | --- | ---: | ---: |
| small | admin allow | 2.1 | 58.0 |
| small | team join allow | 3.7 | 47.6 |
| small | guest deny | 5.7 | 46.1 |
| small | unmapped deny | 5.6 | 40.0 |
| medium | admin allow | 1.9 | 177.3 |
| medium | team join allow | 14.2 | 164.6 |
| medium | guest deny | 34.5 | 154.8 |
| medium | unmapped deny | 34.5 | 156.3 |
| large | admin allow | 2.0 | 1,467.7 |
| large | team join allow | 123.5 | 1,472.5 |
| large | guest deny | 347.2 | 1,464.1 |
| large | unmapped deny | 348.0 | 1,463.3 |

OPA's prepared-query cost grows with the data set because its virtual documents
are evaluated over the same large in-memory store; the YOG binding's cost grows
because the engine scans facts. Both effects are visible and neither is hidden.

### 6.4 C reference

| Corpus | admin allow | team join allow | guest deny | unmapped deny |
| --- | ---: | ---: | ---: | ---: |
| small | 1.4 | 3.1 | 4.9 | 4.9 |
| medium | 1.3 | 13.3 | 33.7 | 33.6 |
| large | 1.3 | 121.8 | 341.6 | 346.9 |

This is YOG's best case: no binding and no FFI. It is reported for context only.

## 7. Load and cold results (p50)

### 7.1 Load / prepare (ms)

| Corpus | YOG C | YOG-Python | YOG-Rust | YOG-Go | Casbin | OPA Go | Cedar Rust |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 0.13 | 0.14 | 0.23 | 0.24 | 2.17 | 1.96 | 5.11 |
| medium | 2.07 | 1.87 | 1.97 | 2.00 | 9.59 | 2.03 | 13.56 |
| large | 65.3 | 62.2 | 55.7 | 57.8 | 71.0 | 1.92 | 70.0 |

YOG's compile time is competitive with Casbin and Cedar at small and medium
sizes, and is slightly cheaper than Cedar's parse+entity load even on the large
corpus. **OPA's prepared-query setup is 34× cheaper than YOG compilation on the
large corpus** and does not grow with the data set. Compile time is a YOG
weakness; this is an expected loss (H5 in the preregistration) and it is
reported as such.

### 7.2 Cold process per request (ms, guest-deny row shown)

| Corpus | YOG C CLI | YOG Rust | YOG Go | YOG Python | Casbin | OPA CLI | OPA Go | Cedar CLI | Cedar Rust |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 27.5 | 32.2 | 78.9 | 127.7 | 231.4 | 82.5 | 409.6 | 97.4 | 34.5 |
| medium | 31.5 | 32.6 | 76.5 | 130.8 | 238.0 | 81.1 | 400.1 | 474.9 | 47.2 |
| large | 81.8 | 89.3 | 138.7 | 179.5 | 313.7 | 92.4 | 428.8 | 3,176.1 | 105.3 |

Reading, limited to cold starts:

- The C CLI and Rust wrapper are the cheapest cold paths at every size, but the
  margin over `opa eval` shrinks from ~3× (small) to ~1.1× (large), and YOG-Go
  and YOG-Python lose to `opa eval` at the large size.
- Cedar CLI grows to ~3.2 s on large because it constructs the entity hierarchy
  per invocation. This is a property of the CLI setup, not of Cedar's decision
  speed once loaded — see the Cedar SDK row (~105 ms), which is dominated by
  Rust runtime startup.
- Go runtime startup (~400 ms for the OPA SDK binary) dominates its cold cost.
- A cold number is a deployment-shape result. It is not evidence about the
  decision engine.

### 7.3 Persistent OPA service (p50 µs)

| Corpus | admin | team join | guest deny | unmapped deny |
| --- | ---: | ---: | ---: | ---: |
| small | 640 | 913 | 718 | 919 |
| medium | 908 | 845 | 774 | 800 |
| large | 2,036 | 2,064 | 2,146 | 2,007 |

Server start to healthy: ~0.51–0.53 s; policy+data configure: 6–17 ms. A
persistent OPA server removes the ~400 ms process cost and lands at hundreds of
microseconds to ~2 ms per HTTP decision, which is the relevant comparison for a
service deployment and still far above an in-process call.

## 8. YOG-only historical results

Kept for the scaling story; these are Debug/Release C-harness numbers from the
first pass, not cross-engine evidence.

### 8.1 Debug build (mean µs)

| Corpus | admin allow | team join allow | guest deny | low-clearance deny | compile (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| small | 4.5 | 7.0 | 15.7 | 15.5 | 0.67 ms |
| medium | 4.3 | 25.2 | 96.6 | 99.6 | 7.7 ms |
| large | 4.6 | 211 | 885 | 884 | 224 ms |

One `yogc check` (mean): 32.2 ms / 40.0 ms / 263.9 ms. `yogc batch` throughput:
30,800 / 9,850 / 535 req/s.

### 8.2 Release build

| Corpus | admin allow | team join allow | guest deny | low-clearance deny | compile (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| small | 1 µs | 3 µs | 8 µs | 8 µs | 0.27 ms |
| medium | 1 µs | 14 µs | 57 µs | 57 µs | 4.2 ms |
| large | 1 µs | 140 µs | 559 µs | 559 µs | 122 ms |

Memory (RSS, approximate): +0.44 MiB / +0.92 MiB / +5.1 MiB for small / medium /
large after the measured checks.

Observations, not claims:

- the first-match path is flat in corpus size;
- default deny and joins scale with policy size because lookup is linear;
- compile time grows superlinearly;
- process startup dominates end-to-end deployment.

## 9. Threats to validity

- Single Windows 11 desktop; pinned to one CPU, but background load is not
  controlled. No Linux distribution is installed on the authoring machine, so
  the Linux data point must come from `bench.yml` and is not yet reported.
- The Go pairing is asymmetric: only YOG crosses an FFI boundary.
- Casbin covers a subset of the corpus; its `full` mismatches are the measured
  gap, not a defect.
- The corpus is generated and regular. Real policies differ in clause order,
  cardinality and attribute shape.
- Four requests are timed; 300 are used for agreement. Timing distributions for
  other actor/resource mixes may differ.
- Bootstrap intervals cover sampling noise only, not machine, OS, compiler or
  translation bias.
- RSS is an OS working-set reading, not a heap profile; peak RSS for OPA/Cedar
  child processes and concurrent throughput are not measured.
- No long-running soak test; no adversarial memory-pressure experiment yet.

## 10. What the evidence supports

Supported:

- YOG's in-process decision cost is microseconds on this corpus.
- The first-match path is flat in corpus size.
- Default deny and joins scale linearly and become expensive at large corpus
  sizes.
- YOG is faster than Casbin, the OPA Go SDK and (on the first-match path) the
  Cedar SDK in the same-runtime in-process comparison on this corpus.
- Every engine agrees with the independent oracle on the feature-matched
  corpus; Casbin's disagreement is fully explained by the missing numeric
  clause.

Not supported:

- that YOG is faster than Cedar in general — on large deny/join workloads Cedar
  is much faster;
- that YOG's compile time is competitive with OPA's prepared query — it is not;
- that these results generalize beyond Windows, this CPU and this corpus;
- that YOG is safer or more expressive than any competitor.

## 11. Next experiments

1. Repeat on Linux CI with the same pinned versions (blocking for platform
   generality).
2. Index predicates by name and first argument; re-measure default deny and
   joins, which are the measured losses against Cedar.
3. Reduce symbol-table and cycle-detection cost in the compiler; re-measure the
   large-corpus load loss against OPA.
4. Vary clause order to quantify the cost of a deny/allow scan.
5. Add concurrent-load throughput and peak RSS.
6. Add an adversarial memory-ceiling experiment near the caps.
7. Increase the request population for timing, not only for agreement.
