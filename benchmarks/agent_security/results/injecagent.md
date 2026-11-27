# InjecAgent policy interception (offline)

Generated 2026-11-27T07:56:08+00:00. Policy: `injecagent_least_privilege`.

This is **not** an LLM attack-success-rate measurement. InjecAgent datasets
provide attacker tool names without attacker arguments, so this measures
tool-level least-privilege interception (`read` -> `ALLOW`, `sensitive_read`
and `write` -> `REQUIRE_APPROVAL`, `destructive` -> `DENY`).

| Dataset | Cases | User strict | User assisted | Interception (block/approve) | Hard DENY |
| --- | ---: | ---: | ---: | ---: | ---: |
| dh_base | 510 | 100.0% | 100.0% | 100.0% | 56.7% |
| ds_base | 544 | 100.0% | 100.0% | 100.0% | 3.1% |
| dh_enhanced | 510 | 100.0% | 100.0% | 100.0% | 56.7% |
| ds_enhanced | 544 | 100.0% | 100.0% | 100.0% | 3.1% |

## Breakdown by attack type

| Dataset | Attack type | Cases | Intercepted | Rate |
| --- | --- | ---: | ---: | ---: |
| dh_base | Data Security Harm | 187 | 187 | 100.0% |
| dh_base | Financial Harm | 153 | 153 | 100.0% |
| dh_base | Physical Harm | 170 | 170 | 100.0% |
| ds_base | Financial Data | 102 | 102 | 100.0% |
| ds_base | Others | 255 | 255 | 100.0% |
| ds_base | Physical Data | 187 | 187 | 100.0% |
| dh_enhanced | Data Security Harm | 187 | 187 | 100.0% |
| dh_enhanced | Financial Harm | 153 | 153 | 100.0% |
| dh_enhanced | Physical Harm | 170 | 170 | 100.0% |
| ds_enhanced | Financial Data | 102 | 102 | 100.0% |
| ds_enhanced | Others | 255 | 255 | 100.0% |
| ds_enhanced | Physical Data | 187 | 187 | 100.0% |

## Per-call decisions

| Dataset | Side | ALLOW | REQUIRE_APPROVAL | DENY |
| --- | --- | ---: | ---: | ---: |
| dh_base | user | 510 | 0 | 0 |
| dh_base | attacker | 0 | 221 | 289 |
| ds_base | user | 544 | 0 | 0 |
| ds_base | attacker | 221 | 850 | 17 |
| dh_enhanced | user | 510 | 0 | 0 |
| dh_enhanced | attacker | 0 | 221 | 289 |
| ds_enhanced | user | 544 | 0 | 0 |
| ds_enhanced | attacker | 221 | 850 | 17 |

## Attacker calls by tool class

| Class | Calls | ALLOW | REQUIRE_APPROVAL | DENY | Blocked |
| --- | ---: | ---: | ---: | ---: | ---: |
| destructive | 612 | 0 | 0 | 612 | 100.0% |
| read | 442 | 442 | 0 | 0 | 0.0% |
| sensitive_read | 612 | 0 | 612 | 0 | 100.0% |
| write | 1530 | 0 | 1530 | 0 | 100.0% |

## Limits

- InjecAgent cases carry attacker tool names only, not attacker parameters;
  argument-level policies cannot be exercised offline on these datasets.
- Tool classification is deterministic from the tool name and recorded in
  `injecagent.json` (`tool_classes`) for auditability.
- The benchmark's own tools are classified in an explicit table. The keyword
  fallback is only for tools added later, and it defaults to `write`
  (approval), never `read`.
