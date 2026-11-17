# Demo run-of-show

A five-minute live demo of the enforcement point, plus the one measured
scoreboard slide. Everything here runs from the repository with the Release
build; no network, no external services, no API keys.

## Prepare once

```powershell
# Release engine + CLI (yogc.exe, yog.dll, bench_yog.exe)
cmake -S yog -B yog/build-release -DCMAKE_BUILD_TYPE=Release
cmake --build yog/build-release

# Sanity check: 14 scenarios, expected decisions, exit 0
python examples\ai_guardrails/live_demo.py --no-color
```

If `yogc` is somewhere else, pass `--yogc path\to\yogc.exe`.

## The one command to run on stage

```powershell
python examples\ai_guardrails/live_demo.py --step
```

`--step` pauses between the four acts so you can talk. `--bench` appends the
measured scoreboard at the end; `--no-color` is the fallback if the terminal does
not render ANSI colour.

## Run of show

**0:00 — Frame the point.** An agent does not "answer a question"; it calls
tools. The runtime has to decide *before* the tool call, deterministically, and
the answer has to survive a confused or adversarial model. The demo is that
decision point.

**0:30 — Act 1, shell (Enter).** Four commands through one policy.

- `agent_sandbox` + `cmd_ls` → ALLOW, "allow clause at line 19 matched".
- `agent_support` + `cmd_ls` → DENY: the agent is not inside the sandbox.
- `agent_admin` + `cmd_rm_rf` → DENY. **This is the point of deny-over-allow:**
  being an admin does not unlock a destructive command.
- `agent_admin` + `cmd_curl_pipe_sh` → DENY for the same reason.

Say: the decision is declarative and readable; the reason is machine- and
human-readable, so the runtime can log *why* it blocked.

**1:30 — Act 2, production database (Enter).**

- app service to staging → ALLOW.
- app service to production → DENY.
- database admin to production → ALLOW.
- unknown agent → DENY. Nothing about "unknown" is an error path that accidentally
  allows; the default is deny.

**2:30 — Act 3, money (Enter).**

- amount 4,000 vs the 5,000 limit → ALLOW.
- amount 9,000 → DENY.
- no amount proof at all → DENY. **Absence of evidence is not permission.**
- blocked account → DENY from an explicit deny clause.

Say the security rule out loud: the amount arrives through request context, so
the **trusted enforcement layer** must build that context from the payment
service. An agent that can write its own context can forge facts. Context is a
capability, not a hint.

**3:30 — Act 4, fail closed (Enter).**

- unknown action `can_browse_web` → DENY, with the reason that no clause defines
  the action.
- malformed context (`rule amount(X): p(X)`) → the engine rejects the context and
  the demo treats it as DENY.

Say: an evaluation error is never an allow. That is the property that matters
more than speed.

**4:15 — Scoreboard (`--bench`).** Read only these lines:

- Largest corpus, warm, same language runtime: YOG's first-match path is
  2–9 µs against Casbin's ~132 µs and OPA's ~1,470 µs.
- **Cedar is ~40× faster than YOG on the large deny and ~12× on the large team
  join.** It is a flat ~9 µs engine; YOG scans facts linearly.
- OPA prepares a large policy ~34× faster than YOG compiles it.
- Go is asymmetric: only YOG crosses an FFI boundary, so read it as a bound.

Close with: *"No general superiority claim. The interesting result is where the
design loses, and that is what the next iteration fixes."*

## If something breaks

| Symptom | Fix |
| --- | --- |
| `yogc not found` | build `yog/build-release`, or pass `--yogc` |
| Colour codes print literally | rerun with `--no-color` |
| Font/terminal too small | the demo prints one decision per line; widen the window |
| You are out of time | run without `--step`, it finishes in about 2 seconds |

## Backup: no terminal at all

The deck's results slides carry the same numbers, and
`benchmarks/results/comparison.md` plus `boundaries.md` are committed. If the
live demo fails, show the deck and offer the command afterwards; do not ad-lib
numbers.
