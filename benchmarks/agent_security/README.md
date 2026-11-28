# Agent Security Benchmarks

Deterministic, offline policy-interception harnesses for YOG against
[AgentDojo](https://github.com/ethz-spylab/agentdojo) and
[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), an OWASP Agentic AI
(ASI01-ASI10) coverage suite and a cross-step information-flow evaluator, plus
a live AgentDojo `FunctionsRuntime` adapter and ASR runner.

The consolidated write-up is
[`docs/AGENT_SECURITY_REPORT.md`](../../docs/AGENT_SECURITY_REPORT.md).

## What this measures (and what it does not)

- **Measured:** Policy interception on each benchmark's canonical tool calls
  using YOG's `ReferencePDP` (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`).
  - *Strict utility:* fraction of benign tasks where every ground-truth call is
    `ALLOW`.
  - *Assisted utility:* fraction of benign tasks where no ground-truth call is
    `DENY` (`REQUIRE_APPROVAL` is counted because a human can approve it).
  - *Interception:* fraction of injection/attack cases where at least one
    attacker call is `DENY` or `REQUIRE_APPROVAL` (not executed without human
    approval).
- **Not measured offline:** End-to-end LLM attack success rate (ASR), which
  depends on the model, prompt, and live environment. `run_agentdojo_live.py`
  runs that measurement but needs an API key and has not been run in CI.

Both `agentdojo` and the InjecAgent JSON files are **optional** dependencies.
Core repository tests run without them.

## Results at a glance

| Suite | Evidence | Result |
| --- | --- | --- |
| AgentDojo | 97 benign tasks, 27 injection tasks (26 measurable offline) | Assisted utility 100%; injection interception 24/26 (92.3%) |
| InjecAgent | 2,108 cases across four datasets | User utility 100%; case interception 100%; hard DENY 56.7% (`dh`) / 3.1% (`ds`) |
| OWASP Agentic | 12 scenarios (ASI01-ASI10 + 2 benign) | 12/12 pass; 100% attack interception; 100% benign utility |
| Information flow | 7 synthetic read-then-sink scenarios | 7/7 pass; tainted writes DENY, untainted writes ALLOW |
| OpenFGA | 900 requests | 0 translation mismatches |
| Stress | 1-8 threads, 2,000 facts | ~19k-21k ops/s, 0 errors, 2,792.8 KiB peak heap |

## Commands

### AgentDojo (offline)

Requires `agentdojo` installed in the Python interpreter:

```powershell
%TEMP%\yog_ad_venv\Scripts\python.exe benchmarks/agent_security/evaluate_agentdojo.py
```

Outputs `benchmarks/agent_security/results/agentdojo.json` and
`benchmarks/agent_security/results/agentdojo.md`.

### InjecAgent (offline)

Requires InjecAgent's `tools.json` and `test_cases_*.json` (default:
`%TEMP%\injecagent`, override with `--data-dir`):

```powershell
python benchmarks/agent_security/evaluate_injecagent.py
```

Evaluates all four datasets (`dh_base`, `ds_base`, `dh_enhanced`,
`ds_enhanced`). Outputs `benchmarks/agent_security/results/injecagent.json`
and `benchmarks/agent_security/results/injecagent.md`.

### OWASP Agentic AI coverage

```powershell
python benchmarks/agent_security/evaluate_owasp.py
```

Outputs `benchmarks/agent_security/results/owasp.json` and
`benchmarks/agent_security/results/owasp.md`.

### Cross-step information flow (synthetic)

```powershell
python benchmarks/agent_security/evaluate_info_flow.py
```

Runs a source tool, records its output in `yog_platform.info_flow`, then checks
later sinks. The same write is `ALLOW` without tracking and `DENY` with it.
Outputs `benchmarks/agent_security/results/info_flow.json` and
`benchmarks/agent_security/results/info_flow.md`.

### Validate policies with the C engine

```powershell
Get-ChildItem benchmarks/agent_security/policies/*.yog | ForEach-Object { yog\build\yogc.exe validate $_.FullName }
```

## Live AgentDojo pipeline integration

Use `guarded_runtime_class` to plug YOG into AgentDojo's `TaskSuite` without
monkeypatching:

```python
from agentdojo.task_suite.load_suites import get_suite
from benchmarks.agent_security.guard import ToolGuard, load_policy
from benchmarks.agent_security.agentdojo_adapter import guarded_runtime_class

suite = get_suite("v1", "banking")
guard = ToolGuard(load_policy("agentdojo_banking"))
GuardedRuntime = guarded_runtime_class(suite.name, guard)

utility, security = suite.run_task_with_pipeline(
    pipeline,
    user_task,
    injection_task,
    injections,
    runtime_class=GuardedRuntime,
)
```

`run_agentdojo_live.py` wraps this into a model-in-the-loop runner that reports
utility and ASR with and without the guard:

```powershell
# No model calls; compiles the policy and prints the plan.
%TEMP%\yog_ad_venv\Scripts\python.exe benchmarks/agent_security/run_agentdojo_live.py --suite banking --dry-run

# One pair against a real model (needs the provider key).
$env:OPENAI_API_KEY = "..."
%TEMP%\yog_ad_venv\Scripts\python.exe benchmarks/agent_security/run_agentdojo_live.py `
    --suite banking --model gpt-4o-mini-2024-07-18 `
    --user-task user_task_0 --injection-task injection_task_0 --baseline
```

## Temporal and information-flow facts

The agent policies can consume platform-projected facts from
`yog_platform/history.py` and `yog_platform/info_flow.py`:

- `recent_call`, `recent_calls_total`, `last_call_age`, `sequence_followed`
- `arg_tainted`, `arg_flow`, `taint`

`ToolGuard` accepts an `InfoFlowTracker` and a `taint_outputs` mapping. The live
AgentDojo runtime calls `guard.observe()` after every successful tool call, so a
source tool's output taints later arguments. The synthetic evaluator uses this
path with `policies/taint_exfiltration.yog`.

These are host-level features, not native C VM operators; a policy that needs
them must run through the gateway (or another host that projects the facts).
See `tests/platform/test_temporal_and_flow.py` and
`tests/platform/test_agent_security.py`.

## Limitations

1. **Offline AgentDojo** evaluates ground-truth canonical calls rather than
   model-generated calls. Tasks with empty ground truth (`travel/injection_task_6`)
   cannot be measured offline, and read-only phishing visits
   (`slack/injection_task_3`) or benign reminders (`travel/injection_task_2`)
   are not intercepted without URL reputation or intent classification.
2. **Offline InjecAgent** datasets name attacker tools without attacker
   arguments, so `injecagent_least_privilege.yog` classifies tools by name
   (`read`, `sensitive_read`, `write`, `destructive`) rather than inspecting
   parameters. The 442 plain `read` attacker calls still pass. The synthetic
   information-flow evaluator closes the read-then-write sequence, but
   InjecAgent itself cannot exercise it without arguments.
3. **Reference PDP:** The offline harness uses `yog_platform.pdp.ReferencePDP`
   so no C build is required; all policies are also validated with `yogc`.
4. **No live ASR number:** the live runner exists and its `--dry-run` is
   tested, but a model run needs an API key and budget.
5. **OpenFGA** equivalence is against a local tuple-graph evaluator, not a live
   server.
6. **Information flow** matches recorded string values (exact or substring for
   tokens of at least `min_token_len`). It does not follow base64, encryption or
   paraphrasing, and it is host-side fact projection rather than VM-level taint.
