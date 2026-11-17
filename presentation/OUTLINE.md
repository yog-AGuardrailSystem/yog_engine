# Benchmark deck — talk outline

A 15-slide deck for a 12–15 minute talk plus a 5-minute live demo. The deck is
built from committed results; do not edit numbers inside the `.pptx`.

| Item | Where |
| --- | --- |
| Deck | `presentation/yog-benchmark-deck.pptx` |
| Generator | `presentation/build_deck.py` |
| Numbers | `benchmarks/results/comparison.json` (warm), `boundaries.json`, `equivalence.json` |
| Demo | `python examples/ai_guardrails/live_demo.py --step` |
| Demo script | `docs/DEMO.md` |
| Method | `docs/BENCHMARKS.md`, `docs/PREREGISTRATION.md`, `docs/BENCHMARK_REVIEW.md` |

Rebuild after a results change:

```sh
python presentation/build_deck.py
python presentation/preview_deck.py   # optional rough PNGs, no Office needed
```

## Timing at a glance

| Block | Slides | Time |
| --- | --- | --- |
| Framing | 1–3 | 2:30 |
| The policy and the evidence | 4–7 | 4:30 |
| Results | 8–11 | 3:30 |
| Limits and verdict | 12–13 | 2:00 |
| Close | 14–15 | 1:30 |
| **Total talk** | 1–15 | **~14:00** |
| Demo (optional before Q&A) | — | 5:00 |

If you are cut to 10 minutes, drop slide 5 (correctness detail) and slide 11
(load/cold), keep 9 (the loss), and say the demo command instead of running it.

## Per-slide notes

**1 — Title (0:00, 0:30).** Open on the decision point, not the language: an
agent runtime must answer "is this allowed?" before every tool call. Say the
study is about whether the answer is defensible, not about winning.

**2 — Problem (0:30, 1:00).** The model is untrusted input; a wrong ALLOW is an
action, a wrong DENY is an outage. Read the contract panel: deny > allow >
default deny, unknown action → DENY, evaluation error → DENY.

**3 — Scope (1:30, 1:00).** One line of architecture, then the amber box. Say
"experimental, not production-ready, not a proof of safety" out loud. It buys
credibility for the results.

**4 — Language (2:30, 1:15).** Read the two allows and the deny. The point is
precedence: being an admin does not unlock `cmd_rm_rf`. The reason string is part
of the API, because an enforcement point that cannot explain a deny is bypassed.

**5 — Evidence (3:45, 1:15).** Expected answers come from
`benchmarks/oracle.py`, which shares no code with the engine. 12,600 decisions,
0 unexpected mismatches, 147 expected Casbin feature-gap mismatches. A wrong
answer aborts the run before timing.

**6 — Method (5:00, 1:15).** Four boundaries answer four questions. Only
same-runtime pairings are compared; the Go row is highlighted because only YOG
crosses FFI. 10 runs × 500 calls, pinned CPU, 95% bootstrap over runs.

**7 — Workload (6:15, 1:00).** The timing corpus is feature-matched on purpose.
The `full` profile adds `clearance >= classification` to price Casbin's gap; it
is never used for a superiority claim.

**8 — Python result (7:15, 0:45).** YOG wins despite paying ctypes overhead;
Casbin interprets a generic matcher per request. Scope the claim to this corpus.

**9 — Rust result (8:00, 1:15).** The important slide. Say the loss first:
Cedar is ~40× faster on large deny and ~12× on large team join, because Cedar is
a flat ~9 µs engine and YOG scans facts linearly. YOG wins only first-match.

**10 — Go result (9:15, 0:45).** Asymmetric pairing. Treat the gap as an upper
bound on YOG and a lower bound on OPA, not a pure engine comparison.

**11 — Load, cold, service (10:00, 1:00).** Change the boundary and the winner
changes. OPA prepares a large policy 34× faster than YOG compiles it; Cedar CLI
cold start is dominated by rebuilding entities (~3.2 s); YOG has no service mode.

**12 — Threats (11:00, 1:00).** Read three aloud: one machine, no external
reviewer, four timed requests. Offer `docs/BENCHMARK_REVIEW.md`.

**13 — Verdict (12:00, 1:00).** Keep both columns up. Left: microseconds
in-process, flat first-match, linear and expensive deny/join, wins over Casbin
and OPA-Go here, oracle agreement. Right: not faster than Cedar in general, not
competitive with OPA's prepared query on load, not generalisable, not safer or
more expressive, not production-ready.

**14 — Close (13:00, 0:45).** The next work is indexed predicates and cheaper
compilation, not a new narrative. Offer the demo command.

**15 — Appendix (Q&A, 0:20).** Leave up for provenance questions: artifacts,
pinned versions, what is still missing (Linux measurement job, service mode,
concurrency and RSS).

## Demo placement

Run the demo after slide 14 if the room is engaged, otherwise after slide 4 to
make the language concrete. `docs/DEMO.md` has the run of show, the four acts
and the failure/fallback table. The one rule: **do not ad-lib numbers** — read
them from the deck or rerun the harness.

## Q&A cheat lines

- *"Is it faster?"* — In-process on this corpus yes, against Casbin and the OPA
  Go SDK; no against Cedar on large deny and join, and no on load against OPA.
- *"Why not compare one number?"* — Cold, load, warm and service are different
  costs; blending them hides which deployment is being described.
- *"Can I trust the timings?"* — Read the boundary, the pinned versions and the
  bootstrap caveat; the gap list is in `docs/BENCHMARK_REVIEW.md`.
- *"Is it safe?"* — It is fail-closed and tested against limits and malformed
  input, but it is not a proof of safety and has no external review.
- *"What is next?"* — Index predicates, cut compile cost, run Linux, add a
  service boundary with concurrency and RSS measurements.
