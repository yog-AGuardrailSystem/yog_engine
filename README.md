# YOG

A small, deterministic policy language and decision engine for **AI agents that call tools**. YOG is the *policy
decision point*: before an agent runs a shell command, writes to a database, calls an API or moves money, the
enforcement point asks YOG, and YOG answers **ALLOW**, **DENY** or **REQUIRE_APPROVAL**, with the reason and any
obligations (things the caller must do, such as write an audit record). YOG never executes anything.

The engine is C11 with a Python reference implementation used for differential testing. Around it is a pure-Python
platform: a gateway, an MCP proxy, an HTTP sidecar, signed policy bundles, a hash-chained audit log, approvals,
extractors for shell/SQL/HTTP/Kubernetes, analysis tools, and integrations (Claude Code hook, LangChain, OpenAI Agents
SDK, Claude Agent SDK, Rust, WebAssembly).

> **Status: experimental, not production-ready.** Nothing is published to PyPI, crates.io or npm, there has been no
> external security review, and several parts are explicitly marked unverified below. What is tested, and how, is stated
> next to each feature. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the item-by-item status and
> [`docs/COMPARISON.md`](docs/COMPARISON.md) for how YOG relates to Cedar, OPA and others (including what it does *not*
> claim).

## The decision contract

```text
version 2
input arg(text, any)

fact allowed_tool("read_file")

deny run_tool(Agent, Tool):
    arg("input.path", P)
    matches(P, "(^|/)\.env$")

require_approval run_tool(Agent, "deploy"):
    obligation audit("deploy requested")

allow run_tool(Agent, Tool):
    allowed_tool(Tool)
    obligation audit(Tool)
```

```console
$ yogc check-json policy.yog request.json
{"decision":"ALLOW","reason":"allow clause at line 13 matched","obligations":[{"name":"audit","args":["read_file"]}]}
```

- **DENY > REQUIRE_APPROVAL > ALLOW > default deny.** An unknown action is denied.
- **Obligations are data.** They come only from the winning kind of clause, in clause order, de-duplicated. A DENY carries
  none. The enforcement point must perform every obligation or refuse the call.
- **Fail closed.** Any evaluation error, type error, limit violation or malformed request is an error that callers treat
  as DENY.
- **Injection-proof requests.** A JSON request is flattened into typed facts by a strict C parser; its values never pass
  through policy text, so an agent cannot inject policy by choosing its arguments.
- **Deterministic.** The engine never reads a clock, a file or the network. State and time arrive in the request
  (`state`, `now`), so a decision can be replayed from the request and the policy.
- Declarative: no I/O, no native calls, no recursion. Built-ins: `in`, `matches` (linear-time regular expressions, no
  backtracking), `glob`, `under` (normalised paths, `..` cannot escape), `starts_with`, `ends_with`, `contains`, and
  `cidr` for IPv4 and IPv6.

The language is specified in [`docs/SPEC.md`](docs/SPEC.md) (including the decision semantics and the laws they satisfy),
the request and result formats in [`docs/INTERFACES.md`](docs/INTERFACES.md), and the threat model in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## What is in the box

### Engine (`yog/`, C11)

Lexer, parser, semantic analysis (compile rules C0-C9), clause-table IR, evaluator, public C ABI and the `yogc` command.

```console
$ yogc validate policy.yog                         # compile only
$ yogc check policy.yog alice can_delete database_1
$ yogc check-json policy.yog request.json          # typed JSON request, JSON result
$ yogc batch-json policy.yog < requests.jsonl      # long-lived, one result per line
$ yogc explain policy.yog [ACTOR ACTION RESOURCE]  # which clauses apply
```

Exit status: `0` allow, `3` deny, `4` require approval, `2` usage or I/O error, `1` compile error.

Resource limits (steps, depth, solutions, memory, wall clock) are enforced and fail closed. A **first-argument index** over
facts (predicates with 16 or more facts) makes a lookup late in a large policy about 150 times faster in a single-machine
measurement ([`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)); it only prunes candidates, so unification still decides.

### Platform (`yog_platform/`, pure Python, no dependencies)

| Component | What it does |
| --- | --- |
| `gateway.py` | The enforcement point. Builds the request so agent input stays under `input.*` and cannot forge facts the gateway knows; performs obligations (`audit`, `rate_limit`, `max_output_bytes`); tracks context taint after untrusted content; refuses on any doubt. **Shadow mode** (`mode="shadow"`) records what the policy would have done without blocking. |
| `mcp_proxy.py` | A stdio proxy in front of an MCP server. Optionally trims `tools/list` to the tools the policy could ever allow. |
| `sidecar.py` | HTTP decision service (`/v1/check`, `/healthz`, `/metrics`, policy reload). Fail closed, audited, cached safely. `--shadow` for log-only rollouts. |
| `bundle.py`, `ed25519.py`, `policy.py` | Ed25519-signed policy bundles (manifest, key id, expiry, per-file hashes, downgrade refusal, bundled self-tests); staged atomic swap with rollback; registry sync. |
| `audit.py`, `approvals.py`, `cache.py` | Hash-chained audit log; approval tokens bound to the exact request, policy and expiry, single use; decision cache keyed on the full request, policy hash and state version. |
| `extractors/` | Shell, SQL, HTTP and Kubernetes extractors that turn a tool argument into facts, reporting `parsed: false` rather than guessing. |
| `claude_hook.py` | A Claude Code `PreToolUse` hook: ALLOW leaves Claude Code's own permission flow alone, DENY blocks, REQUIRE_APPROVAL asks the user, any error blocks. |
| `delegation.py` | Delegation chains for sub-agents: `acting_for`, `delegated`, `has_scope`, `chain_depth` facts supplied by the gateway; a sub-agent's scopes can only narrow. |
| `schema.py` | A tool schema (argument names and types, obligation arities): the gateway refuses calls that do not conform. |
| `decision_log.py`, `telemetry.py` | OPA-shaped decision logs (request values redacted by default), a latency histogram in `/metrics`, a dependency-free OTLP/HTTP metrics exporter. |
| `engine.py`, `pdp.py` | Persistent `yogc batch-json` process (fail closed on crash, hang or garbage), in-process and HTTP decision points, the reference interpreter as a stand-in. |

### Developer tools (`python -m yog_platform ...`)

| Command | Purpose |
| --- | --- |
| `fmt` | Canonical formatter (idempotent, meaning-preserving). |
| `analyze [--schema S.json]` | Static checks A001-A013: unused rules, shadowed or duplicate clauses, actions that can never be allowed, unknown obligations, and schema mismatches. |
| `test FILE.yogtest` | Policy test runner with clause coverage. |
| `diff OLD NEW --requests R.json` | Which of these requests change decision. |
| `compare OLD NEW [--smt]` | Everything the new policy permits that the old one did not, over a bounded universe of requests, with replayable counterexamples. Says *inconclusive*, never *equivalent*, unless the universe was enumerated exhaustively. `--smt` adds a Z3 proof for the supported fragment (needs `z3-solver`). |
| `import-cedar FILE -o OUT` | Converts a subset of Cedar (permit/forbid, scopes, `when`/`unless` over `context`, `has`, `like`, `contains`) to YOG v2, refusing everything else with a line number. |
| `bundle keygen\|build\|verify` | Create keys, sign and verify bundles. |
| `serve` | Run the sidecar (`--decision-log`, `--otlp-endpoint`, `--shadow`, `--registry`, ...). |

### Integrations

| Where | What | Verified how |
| --- | --- | --- |
| Claude Code | `python -m yog_platform.claude_hook --policy examples/claude_code/guard.yog` as a `PreToolUse` hook | tests; C engine and reference agree on 15 hook requests |
| Python agents | `yog_platform/adapters/`: `guard_function`, LangChain-style tools, OpenAI Agents SDK decorator, Claude Agent SDK hook; example in `examples/agents/python/` | tests with stand-in tools. **Not run against the real frameworks.** |
| Python binding | `bindings/python/` (ctypes over the C ABI) | CI |
| Rust | `bindings/rust/`: safe wrapper and a `GuardedTool` for tool calls | CI |
| WebAssembly / JavaScript | `bindings/wasm/`: Emscripten build of the engine and a fail-closed wrapper | the CI `wasm` job builds and tests it; the job is marked non-blocking and has run once |

An in-process guard can be bypassed by the agent's own code. For enforcement the agent must hold no credentials for the
tools and reach them only through a gateway or sidecar. See [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Quick start

```sh
# build the engine
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug
cmake --build yog/build --parallel
ctest --test-dir yog/build --output-on-failure

# try the platform with the Python reference as the engine (nothing to build)
python examples/agents/python/guarded_tools.py

# guard Claude Code (add to .claude/settings.json)
#   {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command",
#     "command": "python -m yog_platform.claude_hook --policy examples/claude_code/guard.yog"}]}]}}
# start with --shadow to log what it would block without blocking anything

# run a sidecar
python -m yog_platform bundle keygen --out keys --key-id main
python -m yog_platform serve --bundle policy.yogb --pub main:keys/main.public --yogc yog/build/yogc --audit audit.log
```

On Windows use a Visual Studio developer prompt (or `vcvars64.bat`) so `cl` and `nmake` are on `PATH`. Windows Application
Control can block freshly built executables on some machines; CI is the reliable test path there. See
[`yog/README.md`](yog/README.md).

## Testing and correctness

| Layer | What it checks |
| --- | --- |
| C unit and security tests (`ctest`) | each compiler stage, limits, the JSON loader, thread safety, ABI struct layout |
| `yog/tests/conformance`, `property` | black-box cases with hard-coded outcomes; a property oracle that does not use the YOG solver |
| `yog/tests/differential/diff_v2.py` | C engine versus the independent Python reference on a curated corpus and seeded random policies |
| `yog/tests/differential/diff_small_models.py` | **exhaustive**: every policy of at most two clauses over a fixed vocabulary against every request (39,384 comparisons) |
| `tests/platform/` (about 680 tests) | the platform, including decision laws (determinism, order independence, deny and allow monotonicity, precedence, obligation locality), a soundness property for tool-list filtering, and a Cedar differential test |
| Fuzzing | compile, JSON and regular-expression fuzz harnesses (smoke run in CI; no long campaign yet) |
| CI | Linux, macOS and Windows builds, ASan/UBSan on Linux, bindings, WebAssembly |

```sh
python yog/tests/differential/diff_v2.py --yogc yog/build/yogc
python yog/tests/differential/diff_small_models.py --yogc yog/build/yogc
YOGC=$PWD/yog/build/yogc python -m pytest tests yog/tests -q
```

**What this is not:** there is no machine-checked proof of the decision laws. Cedar's team proves its authorizer in Lean;
YOG has the tests above, stated as evidence rather than proof ([`docs/SPEC.md`](docs/SPEC.md), Appendix A). See
[`docs/CORRECTNESS.md`](docs/CORRECTNESS.md) and [`docs/SECURITY.md`](docs/SECURITY.md).

## Repository layout

| Path | What it is |
| --- | --- |
| `yog/` | C engine, `yogc`, C tests, conformance, property, differential and fuzz harnesses |
| `reference/yog_ref.py` | independent Python implementation of the language, used for differential testing |
| `yog_platform/` | gateway, sidecar, bundles, audit, approvals, extractors, tools, adapters |
| `bindings/{python,rust,wasm}/` | language bindings over the public C ABI |
| `examples/` | guardrail policies, the Claude Code guard and schema, delegation, agent examples |
| `tests/` | platform tests, golden extractor cases |
| `benchmarks/` | corpus generator, harnesses, Cedar/OPA/Casbin adapters |
| `deploy/` | Dockerfile and Kubernetes manifest (**unverified**: written without a container runtime) |
| `docs/` | see below |

### Documentation

| Document | Contents |
| --- | --- |
| [`SPEC.md`](docs/SPEC.md) | the language, built-ins, obligations, limits, decision semantics and laws |
| [`INTERFACES.md`](docs/INTERFACES.md) | JSON request/result formats, C API, sidecar endpoints |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`SECURITY.md`](docs/SECURITY.md) | trust boundaries, threats and mitigations |
| [`OPERATIONS.md`](docs/OPERATIONS.md) | deployment, keys and rotation, shadow-mode rollout, state contract, observability, failure behaviour |
| [`COMPARISON.md`](docs/COMPARISON.md) | YOG against Cedar, OPA, OpenFGA and agent-guardrail products |
| [`ROADMAP.md`](docs/ROADMAP.md) | every planned item with its real status |
| [`COMPILER.md`](docs/COMPILER.md), [`ARCHITECTURE_CHEATSHEET.md`](docs/ARCHITECTURE_CHEATSHEET.md) | compiler internals and a plain-language tour |
| [`CORRECTNESS.md`](docs/CORRECTNESS.md), [`BENCHMARKS.md`](docs/BENCHMARKS.md), [`PREREGISTRATION.md`](docs/PREREGISTRATION.md), [`BENCHMARK_REVIEW.md`](docs/BENCHMARK_REVIEW.md), [`RESEARCH.md`](docs/RESEARCH.md) | validation, the benchmark study and the research framing |
| [`AGENT_SECURITY_REPORT.md`](docs/AGENT_SECURITY_REPORT.md) | AgentDojo, InjecAgent, OWASP Agentic, temporal/info-flow and OpenFGA results, with explicit limits |
| [`RFC_TEMPLATE.md`](docs/RFC_TEMPLATE.md), [`../CONTRIBUTING.md`](CONTRIBUTING.md) | how to propose a language change; how to contribute |

## Known gaps

* No external security review and no beta users; nothing is published to a package index.
* No formal proof of the decision core.
* The adapters for LangChain, the OpenAI Agents SDK and the Claude Agent SDK are tested with stand-ins, not the real libraries.
* The WebAssembly build has passed CI once and is non-blocking; the Docker and Kubernetes files are unverified.
* The `compare` analysis is bounded, and the Z3 proof covers a fragment of the language.
* The Cedar importer covers a subset (no entity hierarchies or entity attributes).
* A REPL, language server and VS Code syntax extension exist, but there is no debugger UI and no long fuzzing campaign.
* The agent-security benchmarks measure offline policy interception, not live LLM attack success; the live ASR runner exists but has not been run with a model.
* Native C temporal/sequence operators and VM history buffers are not implemented; `yog_platform` projects those facts for the gateway, and the agent-security guard uses host-side taint to gate benchmark sinks.
* Only facts are indexed (not rule or decision clauses). The benchmark study found Cedar much faster on large deny and join
  workloads before indexing; that comparison has not been repeated.

## Benchmarks

The suite separates cold, load, warm and persistent-service boundaries, compares engines only inside the same language
runtime, and checks every decision against an independent oracle. On the feature-matched corpus YOG was faster than Casbin
and the OPA Go SDK in-process, but **Cedar was much faster on large deny and join workloads**, and OPA prepares a large
policy faster than YOG compiles it. No general superiority is claimed. See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

Agent-facing evidence is separate and deliberately conservative: offline policy interception on AgentDojo and
InjecAgent, OWASP Agentic AI coverage scenarios, cross-step information flow, workspace-local URL provenance,
OpenFGA translation equivalence, concurrency and memory ceilings. These are **not** live LLM attack-success-rate
measurements. See [`docs/AGENT_SECURITY_REPORT.md`](docs/AGENT_SECURITY_REPORT.md).

## Contributing

Never push to `main` directly; it is protected. Branch as `feat/<topic>` from the latest `main`, open a pull request, and an
admin must approve. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Code contributed before the change was released under MIT; its
original notice is kept in `NOTICE`.
