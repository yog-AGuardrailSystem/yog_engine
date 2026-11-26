# InjecAgent policy interception (offline)

Generated 2026-11-26T18:32:22+00:00. Policy: `injecagent_least_privilege`.

This is **not** an LLM attack-success-rate measurement. InjecAgent datasets
provide attacker tool names without attacker arguments, so this measures
tool-level least-privilege interception (`read` -> `ALLOW`, `sensitive_read`
and `write` -> `REQUIRE_APPROVAL`, `destructive` -> `DENY`).

| Dataset | Cases | User strict | User assisted | Interception (block/approve) | Hard DENY |
| --- | ---: | ---: | ---: | ---: | ---: |
| dh_base | 510 | 47.1% | 100.0% | 100.0% | 60.0% |
| ds_base | 544 | 47.1% | 100.0% | 100.0% | 3.1% |

## Breakdown by attack type

| Dataset | Attack type | Cases | Intercepted | Rate |
| --- | --- | ---: | ---: | ---: |
| dh_base | Data Security Harm | 187 | 187 | 100.0% |
| dh_base | Financial Harm | 153 | 153 | 100.0% |
| dh_base | Physical Harm | 170 | 170 | 100.0% |
| ds_base | Financial Data | 102 | 102 | 100.0% |
| ds_base | Others | 255 | 255 | 100.0% |
| ds_base | Physical Data | 187 | 187 | 100.0% |

## Per-call decisions

| Dataset | Side | ALLOW | REQUIRE_APPROVAL | DENY |
| --- | --- | ---: | ---: | ---: |
| dh_base | user | 240 | 270 | 0 |
| dh_base | attacker | 0 | 204 | 306 |
| ds_base | user | 256 | 288 | 0 |
| ds_base | attacker | 153 | 918 | 17 |

## Limits

- InjecAgent cases carry attacker tool names only, not attacker parameters;
  argument-level policies cannot be exercised offline on these datasets.
- Tool classification is deterministic from the tool name and recorded in
  `injecagent.json` (`tool_classes`) for auditability.
