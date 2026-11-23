# YOG compared with Cedar, OPA, OpenFGA and the agent-guardrail products

Written 2026-11-23 from public documentation and papers (sources at the end). Vendor posts are cited for what the
vendor *says its product does*, not as independent measurements; where a number comes from a vendor it is marked.
This page also records what YOG deliberately does not claim.

## At a glance

| | YOG | Cedar (AWS) | OPA / Rego | OpenFGA / Zanzibar |
|---|---|---|---|---|
| Question it answers | may this agent call this tool with these arguments (ALLOW / DENY / REQUIRE_APPROVAL + obligations) | may this principal do this action on this resource | any policy question over JSON | is this user related to this object |
| Default and precedence | default deny; DENY > REQUIRE_APPROVAL > ALLOW | default deny; forbid beats permit | you write the rule that combines results | relationship tuples, no deny |
| Typed schema | `input` declarations, tool schema (`schema.py`) | entity and action schema, strict/permissive/partial validation | none (optional type checking of the policy) | authorization model |
| Third outcome ("ask a human") | built in, bound to request hash + policy hash | not built in | up to the caller | no |
| Obligations (do X when allowed) | built in, data returned to the enforcement point | no | arbitrary decision documents | no |
| Static analysis | lint codes A001-A013, bounded comparison, optional Z3 proof | SMT-based analysis (equivalence, "does A permit more than B") with soundness work | partial evaluation, Regal linter | model checks |
| Formal assurance | generated and exhaustive tests only (no proof) | model and proofs in Lean, differential random testing against the Rust code | none for the engine | n/a |
| Agent specifics | shell / SQL / URL / Kubernetes extractors, context taint, MCP proxy, Claude Code hook, delegation facts | used under agent products (see below) | used by some agent gateways | not the usual fit |
| Maturity | experimental, one team, no external review | production at AWS, open source | production, CNCF graduated | CNCF incubating (OpenFGA) |

## What the others do that YOG now matches

* **Shadow / log-only rollout** (AgentCore's `LOG_ONLY`): `Gateway(mode="shadow")`, `serve --shadow`, `claude_hook --shadow`.
* **Policy comparison** (Cedar's analysis): `compare` finds a replayable request the new policy permits more; a Z3 proof
  covers the fragment it supports (`smt.py`). Cedar's analysis is complete for Cedar; YOG's is bounded or fragment-limited
  and says so in its output.
* **Schema validation**: `Schema` plus analysis codes A009-A013 and gateway refusal of calls that do not conform.
* **Multi-hop delegation** (AWS agent-chain reference design): gateway-built `acting_for` / `delegated` / `has_scope` /
  `chain_depth` facts; scopes only narrow along the chain.
* **Decision logs and metrics** in OPA's decision-log shape, OTLP metrics export.
* **Partial evaluation** for tool lists: a sound over-approximation of which tools could ever be allowed.
* **Import path**: a Cedar subset converts to YOG v2, refusing anything it cannot translate exactly.

## What YOG does not claim

* **No proof.** Cedar's team proves its authorizer in Lean and tests the Rust implementation against that model. YOG has
  determinism, ordering and monotonicity laws checked on generated and exhaustively enumerated small policies, and a
  C-versus-reference differential. That is evidence, not a proof (docs/SPEC.md, Appendix A).
* **No performance claims against other engines.** The benchmark study exists (docs/BENCHMARKS.md) but has not had
  independent review; vendor numbers such as AWS's "42-60x faster than Rego" are theirs and are not repeated here.
* **Bounded analysis.** `compare` is exhaustive only when its universe is; otherwise it says "inconclusive". The Z3 proof
  holds for well-typed requests and a fragment of the language.
* **Not a security boundary by itself.** In-process adapters can be bypassed; enforcement needs a gateway or sidecar that
  holds the tool credentials (docs/OPERATIONS.md, docs/THREAT_MODEL.md).
* **No external security review yet.**

## Where the others are ahead

* Cedar: a verified core, an SMT analysis that is complete for the language, a large user base, entity hierarchies (YOG has
  no group membership primitive beyond facts and rules).
* OPA: a general data model and non-boolean documents, a mature ecosystem of tooling and bundles.
* OpenFGA: relationship graphs at scale with a purpose-built store.

## Sources

* Cedar: *Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization* (arXiv 2403.04651);
  *How We Built Cedar with Verification-Guided Development* (arXiv 2407.01688); AWS Open Source Blog, "Lean into verified
  software development"; docs.rs/cedar-policy (validation modes, partial evaluation as experimental features).
* AWS: Amazon Bedrock AgentCore Policy documentation (deny-by-default, `LOG_ONLY`); AWS Security Blog, "Why Policy in Amazon
  Bedrock AgentCore chose Cedar for securing agentic workflows" and "Enforce least-privilege authorization in multi-agent AI
  chains using Cedar".
* TrueFoundry AI Gateway Cedar guardrails documentation (policy at the MCP pre-tool hook).
* Microsoft, "Securing MCP: a control plane for agent tool execution" (Agent Governance Toolkit).
* Styra, Oso, Teleport and Permit.io comparisons of OPA, Cedar and Zanzibar-style systems (each is a vendor of one of the
  products compared and is read accordingly).
