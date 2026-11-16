# Benchmark review checklist

**External review: not performed.** No independent human has reviewed this study.
This document is the authors' self-review. It records what was checked, what the
evidence for each check is, and what remains unverified. It is published so a
reader can see where the study is weak rather than infer that it is settled.

The eight de-biasing points below were the acceptance criteria for this pass.
Each one lists its artefact and its residual limitation.

## 1. Same-runtime pairings

| Point | Status | Evidence | Residual limitation |
| --- | --- | --- | --- |
| YOG-Python vs Casbin, both in CPython | done | `compare.py` boundary `python-in-process`; both call in-process | ctypes adds a boundary on the YOG side, so the win is not purely engine-internal |
| YOG-Rust vs Cedar Rust SDK | done | `compare.py` boundary `rust-in-process`; both are Rust binaries | YOG's wrapper also crosses into C; Cedar is pure Rust |
| YOG-Go vs OPA Go SDK | done, **asymmetric** | `compare.py` boundary `go-in-process`; YOG pays syscall/cgo FFI | OPA pays no FFI. Reported as bounds, never as a pure engine comparison |
| C engine vs competitors | reported as `c-reference` only | `comparison.md` | Cross-language; context, not fairness evidence |

The earlier first pass compared the YOG C library with Casbin's Python enforcer
and CLI with CLI. Those rows are no longer used for any superiority claim.

## 2. Separate cold, load, warm and service boundaries

| Point | Status | Evidence |
| --- | --- | --- |
| Cold process per request | done | `boundaries.py` section `cold`, 10 runs per row |
| Load / prepare only | done | `boundaries.py` section `load`; compile/parse/prepare per harness |
| Warm steady state | done | `compare.py` and `boundaries.py` section `warm`, 500 calls after 50 warm-up |
| Persistent service | done | `boundaries.py` section `service`, OPA HTTP with keep-alive |

The four are never combined into one score. `BENCHMARKS.md` keeps them in
separate sections and states that a cold number is a deployment-shape result.

**Residual limitation:** only OPA is measured as a persistent service, because it
is the only engine with a native server mode. A "YOG as a service" number does
not exist.

## 3. Independent translations and semantic equivalence

| Point | Status | Evidence |
| --- | --- | --- |
| Independent oracle | done | `benchmarks/oracle.py` imports no YOG code, binding or adapter |
| Second Cedar translation | done | `policy.cedar` (permit per clause) and `policy_alt.cedar` (single permit with `\|\|`) |
| Workload size | done | 300 deterministic requests per profile and size; 1,800 in total |
| Decision gate | done | every driver aborts on an unexpected decision |
| Official validators | done | `validate_translations.py`: `yogc validate`, `opa check`, `cedar validate` on both translations |

Result: 12,600 decisions compared (7 engine configurations × 2 profiles × 3
sizes × 300 requests). Unexpected mismatches: **0**. Expected feature-gap
mismatches: 147 (Casbin on `full`).

**Residual limitation:** "independent" means written by the same author from the
corpus, not by a second person. The oracle and the alternate translation reduce
the chance that one translation style drives the result, but they are not
external review. No external human reviewer is available.

## 4. Feature-matched corpus and explicit gap table

| Point | Status | Evidence |
| --- | --- | --- |
| Feature-matched `common` profile | done | `gen_corpus.py`; admin role, team join, manager+public, owner |
| Numeric gap isolated in `full` | done | `clearance >= classification` only in `full` |
| Gap measured, not guessed | done | `equivalence.md`; Casbin 46/41/60 of 300 on `full` |
| Gap table published | done | `BENCHMARKS.md` section 4 |

`compare.py` refuses the `full` profile by design; `full` is covered by
`equivalence.py`. Casbin's mismatches are described as a feature gap, not a
translation failure or a Casbin bug.

**Residual limitation:** one gap is measured. Other differences (deny override
semantics, negation, context handling) are listed qualitatively but not
quantified per request.

## 5. Linux, CPU pinning, at least 10 runs, intervals

| Point | Status | Evidence |
| --- | --- | --- |
| 10 runs | done | `--runs 10` in `compare.py` and `boundaries.py` |
| 95% intervals | done | percentile bootstrap over run medians, 1,000 resamples, fixed seed |
| CPU pinning | done | `adapters/pin.py`; driver pins itself and children (`--pin-cpu 0`) |
| Linux data point | **not done in this run** | Windows 11 only; `bench.yml` is set up for Linux CI |

Every Windows number in `BENCHMARKS.md` is from the pinned run. Intervals cover
sampling noise only. They do not cover machine, OS, compiler or translation
bias.

**Residual limitation:** platform generality is not claimed. The Linux workflow
is the mechanism for closing this, and its output must be reported even if it
disagrees with the Windows numbers.

## 6. Preregistered hypotheses including expected losses

| Point | Status | Evidence |
| --- | --- | --- |
| Hypotheses written down | done | `PREREGISTRATION.md` H1–H7 |
| Expected losses stated | done | H2 large deny/join, H3 FFI asymmetry, H4 large cold, H5 OPA prepare |
| Honest status of the document | done | marked post-hoc for the 2026-11-15 Windows run |
| Falsification criteria | done | `PREREGISTRATION.md` section 5 |

The document does not pretend the first Windows run was preregistered. It is a
commitment for reruns.

**Residual limitation:** because it is post-hoc for the first run, a reader
should weight it as a statement of analysis rules, not as protection against
post-hoc hypothesis selection for that run.

## 7. Honest claims

Checked against the results:

- No text claims YOG is faster in general. `BENCHMARKS.md` states that Cedar is
  ~40× faster on large deny and ~12× faster on large team join.
- OPA's prepared-query setup is reported as 34× cheaper than YOG compile on the
  large corpus, an expected loss.
- YOG is described as an experimental C-based engine, not production-ready.
- The Go pairing is labelled asymmetric everywhere it appears.
- The `common` corpus is used for timing; `full` only for the gap.

## 8. Reproducibility

- Deterministic corpus and request generators; no random seeds outside them.
- Pinned versions: OPA 1.22.4, `cedar-policy` 4.14.1, Casbin 1.43.0, YOG commit
  in `versions.json`.
- Harnesses are built from source in the repository; no prebuilt binaries are
  committed.
- `benchmarks/results/bin/` and `benchmarks/results/tmp/` are build outputs and
  are ignored.
- One command sequence reproduces every artefact (`BENCHMARKS.md` §3).

**Residual limitation:** the committed JSON/Markdown artefacts are from one
Windows machine. A rerun on different hardware will produce different numbers,
and that is expected.

## What would change the conclusion

The study would be invalidated, not merely weakened, if:

- an unexpected decision mismatch were found and not treated as a failure;
- the Casbin gap were recoded as a translation error;
- a cross-language row were presented as same-runtime;
- the `common` corpus were changed after seeing results;
- the Linux rerun contradicted a headline result and the Windows result were
  kept anyway.

None of these happened in this pass. External review remains the largest open
gap, followed by the missing Linux data point.
