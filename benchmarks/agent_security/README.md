# Agent Security Benchmarks (AgentDojo & InjecAgent)

Deterministic, offline policy-interception harnesses for YOG against
[AgentDojo](https://github.com/ethz-spylab/agentdojo) and
[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), plus a live
AgentDojo `FunctionsRuntime` adapter.

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
- **Not measured:** End-to-end LLM attack success rate (ASR), which depends on
  the model, prompt, and live environment.

Both `agentdojo` and the InjecAgent JSON files are **optional** dependencies.
Core repository tests run without them.

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

Outputs `benchmarks/agent_security/results/injecagent.json` and
`benchmarks/agent_security/results/injecagent.md`.

### Validate policies with the C engine

```powershell
yog\build\yogc.exe validate benchmarks/agent_security/policies/agentdojo_banking.yog
yog\build\yogc.exe validate benchmarks/agent_security/policies/agentdojo_workspace.yog
yog\build\yogc.exe validate benchmarks/agent_security/policies/agentdojo_slack.yog
yog\build\yogc.exe validate benchmarks/agent_security/policies/agentdojo_travel.yog
yog\build\yogc.exe validate benchmarks/agent_security/policies/injecagent_least_privilege.yog
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

## Limitations

1. **Offline AgentDojo** evaluates ground-truth canonical calls rather than
   model-generated calls. Tasks with empty ground truth (`travel/injection_task_6`)
   cannot be measured offline, and read-only phishing visits
   (`slack/injection_task_3`) or benign reminders (`travel/injection_task_2`)
   are not intercepted without URL reputation or intent classification.
2. **Offline InjecAgent** datasets name attacker tools without attacker
   arguments, so `injecagent_least_privilege.yog` classifies tools by name
   (`read`, `sensitive_read`, `write`, `destructive`) rather than inspecting
   parameters.
3. **Reference PDP:** The offline harness uses `yog_platform.pdp.ReferencePDP`
   so no C build is required; all policies are also validated with `yogc`.
