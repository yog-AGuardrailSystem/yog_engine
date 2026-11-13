# AI guardrail examples

Four runnable policies for the decision point an agent runtime should call
before a tool invocation. Each policy uses the same contract:

```text
deny > allow > default deny
```

so an unknown action, a missing fact or an evaluation error is never an allow.

| Policy | Action | Key idea |
| --- | --- | --- |
| `shell_commands.yog` | `can_run_command` | sandbox + safe list; destructive commands denied even for admins |
| `database_access.yog` | `can_write` | production writes denied unless the caller is a database admin |
| `api_calls.yog` | `can_call_api` | role → scope → endpoint join, one clause per scope |
| `financial_transactions.yog` | `can_transfer` | per-request amount, limit fact, blocked-account deny |

Run the enforcement demo:

```sh
python examples/ai_guardrails/enforce_demo.py
```

It builds 18 scenarios (including unknown actions and malformed context) and
checks them through `yogc check`. A denied request exits `3`; an evaluation
error is treated as `DENY` by the demo.

Validate the policies directly:

```sh
yogc validate examples/ai_guardrails/shell_commands.yog
yogc explain  examples/ai_guardrails/database_access.yog
yogc check    examples/ai_guardrails/financial_transactions.yog \
              fin_agent can_transfer acct_ops --context "fact amount(acct_ops, 4000)"
yogc check    examples/ai_guardrails/financial_transactions.yog \
              fin_agent can_transfer acct_ops --context "fact amount(acct_ops, 9000)"
```

## Context is a capability

`financial_transactions.yog` receives the amount through
`check(context=...)`. Context facts are logically appended to the policy, so an
agent that can choose its own context can forge facts. The enforcement layer
must build context from trusted data (for example, the amount returned by the
payment service), never from raw model output.

The same warning applies to any policy that uses context to supply roles,
ownership or scope. See [`../../docs/SECURITY.md`](../../docs/SECURITY.md).

## Why the financial policy uses a false-guard rule

YOG has no "declare this predicate, its facts arrive at runtime" statement.
The unsafe workaround is a sentinel fact:

```yog
fact amount(reserved_account, 0)   # do not do this
```

A request whose resource is named `reserved_account` would then pass
`0 <= Limit`. Instead, `amount/2` is defined as a rule with a guard that can
never be true; context facts are tried before rules, so they remain the only
source of amounts:

```yog
fact reserved_schema(reserved_account, reserved_amount)
rule amount(Account, Amount):
    reserved_schema(Account, Amount)
    0 == 1
```

## Mapping to the security controls

| Control | Example |
| --- | --- |
| fail closed | unknown action in `shell_commands.yog` |
| deny override | destructive command for an admin |
| negation | `not on_call` shape in the conformance corpus; `not role(...)` in `database_access.yog` |
| numeric limit | `financial_transactions.yog` |
| per-request context | `financial_transactions.yog` |
| bounded evaluation | limits documented in `docs/SECURITY.md` §6 |
