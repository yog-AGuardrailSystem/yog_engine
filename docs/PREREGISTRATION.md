# Preregistration: cross-engine comparison study

**Status: post-hoc for the 2026-11-15 Windows run, prospective for reruns.**

This document is the analysis plan for the same-runtime cross-engine
comparison. Several of its hypotheses were formed during the first benchmark
pass, and the Windows numbers in `benchmarks/results/comparison.md` were
produced before this file was written. The file is therefore **not** a
time-stamped preregistration of that run. It is a written commitment to the
hypotheses, the measurement protocol and the reporting rules for every rerun
(Linux CI, later hardware), and it records which findings were expected to go
against YOG. Where the first run disagreed with a hypothesis, the disagreement
is reported; the hypothesis is not retrofitted.

The earlier de-biasing review is the reason this file exists: the first pass
mixed language runtimes, used a corpus Casbin could not fully express, and
reported a single number per engine. Those problems are fixed in the protocol
below.

## 1. Research questions

- **RQ-A (decision cost):** within the same language runtime and the same
  feature set, how does YOG's steady-state decision cost compare with Casbin,
  Cedar and OPA?
- **RQ-B (phase cost):** how much of the cost is cold start, policy loading and
  steady-state evaluation?
- **RQ-C (semantics):** do the engines agree with an independent oracle on the
  same requests, and where they disagree, is the disagreement explained by a
  documented feature gap?
- **RQ-D (limits of the claim):** on which workloads is YOG measurably *slower*
  than a competitor, and does that survive the same-runtime correction?

No hypothesis below asserts that YOG is faster, safer or more expressive in
general.

## 2. Fixed design

| Item | Value |
| --- | --- |
| Corpus generator | `benchmarks/gen_corpus.py` (deterministic LCG) |
| Profiles | `common` (feature-matched, primary); `full` (numeric clause, gap measurement) |
| Sizes | small / medium / large |
| Requests | 300 per profile and size from `benchmarks/gen_requests.py`; 4 canonical timed requests from `common-requests.json` |
| Oracle | `benchmarks/oracle.py`, an independent implementation of the corpus semantics |
| Runs | 10 independent runs |
| Samples | 500 timed calls per request per run, after 50 warm-up calls |
| Statistic | median of run medians (p50); pooled p95/p99 reported separately |
| Interval | 95% percentile bootstrap over the 10 run medians (1,000 resamples, fixed seed) |
| Pinning | one CPU, pinned before any measurement; children inherit the mask |
| Decision gate | any unexpected decision aborts the run |
| Reported rows | every engine × size × request; no post-hoc exclusions |
| Primary boundary | same-runtime, in-process |
| Secondary boundary | cold process per request, load-only, persistent OPA HTTP |

Pinned engine versions: YOG at the commit in `versions.json`; OPA 1.22.4
(`opa` CLI and Go SDK); `cedar-policy` 4.14.1 (Rust SDK) and Cedar CLI 4.14.1;
Casbin 1.43.0.

## 3. Hypotheses and expected outcomes

Direction is stated before the rerun. "Expected loss" means the hypothesis
predicts that YOG will be slower or worse; it is recorded so that a positive
result cannot be presented as a surprise.

### H1 — Python same-runtime decisions

YOG-Python (ctypes binding) has a lower warm p50 than Casbin for all four
canonical requests at all three sizes.

*Expected loss:* none on this corpus. Casbin does more generic matching per
request and its policy model is interpreted. If Casbin wins on any row, the
"binding overhead explains YOG's cost" explanation is wrong and must be
withdrawn.

### H2 — Rust same-runtime decisions

YOG-Rust has a lower warm p50 than the Cedar Rust SDK on the first-match allow
path (admin, and team join at small size).

*Expected loss:* on the large corpus, default deny and the team-join scan are
predicted to be **slower** than Cedar, because YOG scans facts linearly while
Cedar evaluates a compiled policy over an indexed entity store. The earlier run
showed YOG ≈ 345 µs vs Cedar ≈ 9 µs on large deny; this is expected and is not
a defect of the experiment. A rerun that reverses this would be a genuine
surprise and must be investigated, not celebrated.

### H3 — Go same-runtime decisions

YOG-Go (syscall/cgo over the C ABI) has a lower warm p50 than the OPA Go SDK
for all four requests at all sizes.

*Expected loss:* the YOG-Go number includes an FFI crossing that OPA does not
pay. If OPA wins a row, the FFI explanation is insufficient and the result
stands as measured. This pairing is asymmetric by construction and is reported
as bounds, not as a pure engine comparison.

### H4 — Cold start

A fresh process that compiles/loads the policy and answers one request is faster
for YOG C CLI and YOG Rust than for `opa eval` and `cedar authorize` on the
small corpus.

*Expected loss:* the margin is predicted to shrink as the corpus grows. On the
large corpus YOG Rust is predicted to be at best within noise of `opa eval`,
YOG-Go and YOG-Python are predicted to lose to it, and Cedar CLI is predicted to
be much slower because it loads and constructs the entity hierarchy per
invocation. OPA is predicted to stay roughly flat across sizes.

### H5 — Load / prepare

YOG compile time is lower than Cedar's policy parse + entity load at every
size.

*Expected loss:* OPA's prepared-query setup is predicted to be **faster** than
YOG compilation on the large corpus (single-digit milliseconds vs tens of
milliseconds). Compile time is a known YOG weakness; this hypothesis is
expected to lose.

### H6 — Semantic equivalence

All engines agree with the independent oracle on 100% of `common` requests.

*Expected loss:* on the `full` profile Casbin is predicted to disagree on the
subset of requests whose outcome depends on `clearance >= classification`. The
mismatch count is a measurement of the feature gap, not a translation failure.
If Casbin matches those requests, the gap claim is wrong.

### H7 — No overall ranking

No hypothesis predicts that YOG is the fastest engine across all rows. The
report must state at least one workload where a competitor wins and must not
convert a same-runtime win into a general superiority claim.

## 4. Analysis rules

1. Report all measured rows, including losses, with intervals.
2. Compare only within a boundary. Cold, load, warm and service numbers are
   never combined into a single score.
3. Do not drop an engine because it is inconvenient. If a tool is unavailable,
   report the artifact and the reason.
4. Do not choose the request mix after seeing results. The 300-request workload
   and the four canonical requests are generated deterministically.
5. A difference is described as a difference on this corpus and machine, not as
   a property of the engine.
6. Any translation change after seeing a mismatch must be recorded in the
   review checklist, and the equivalence run must be repeated.
7. Bootstrap intervals quantify sampling noise only. They do not cover machine,
   OS, compiler or translation bias; those are listed as threats.

## 5. Falsification

The study fails its own standard if any of the following happens:

- a decision mismatch is ignored or averaged away;
- a cross-language comparison is presented as same-runtime;
- Casbin's `full`-profile mismatches are described as a Casbin bug rather than
  a feature gap;
- the numeric clause is added to the `common` corpus to make Casbin fail, or
  removed from `full` to make it pass;
- the conclusion claims YOG is faster in general while a measured row shows the
  opposite;
- the report omits cold or load costs because they favour a competitor.

## 6. Deviations and known gaps

- The 2026-11-15 run is Windows-only. No Linux distribution is installed on the
  authoring machine; the Linux build and binding jobs pass in CI, but the Linux
  measurement job has not yet produced data. Until it does, platform generality
  is not claimed.
- The Go pairing is asymmetric (FFI on the YOG side). This is disclosed, not
  corrected, because no native Go implementation of YOG exists.
- There is no external human reviewer. Independent evidence comes from the
  oracle, two independently written Cedar translations, the official validators
  and the decision gate. The limitation is recorded in
  [`BENCHMARK_REVIEW.md`](BENCHMARK_REVIEW.md).
