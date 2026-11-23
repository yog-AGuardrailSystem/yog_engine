# YOG Roadmap

Status: draft for team review. Baseline: `main` at `1306ac2`.

YOG is the **policy decision point (PDP)** for agents calling MCP tools. It returns
`ALLOW`, `DENY` or `REQUIRE_APPROVAL` (plus obligations). It never executes tools
and never orchestrates. Enforcement belongs to the gateway.

## 1. Baseline

Built: C11 lexer, parser, semantic analysis (C0-C5), clause-table IR, backtracking VM,
C API, `yogc`, Python (ctypes) and Rust bindings, unit / conformance / differential /
property / fuzz-smoke / security tests, benchmark study (Casbin, Cedar, OPA),
`docs/SECURITY.md`, `examples/ai_guardrails`, Linux CI with sanitizers.

Missing: typed values (only text and integers), recursion, outcomes beyond
ALLOW/DENY, obligations, modules, state/time, JSON requests, indexing, hot reload,
ABI version, JSON traces, signing, audit log, TypeScript/WASM, gateway, extractors,
sidecar, approvals, distribution, Windows/macOS CI, libFuzzer in CI.

Known hygiene issues: version/license mismatch (root 0.1.0 MIT vs bindings 0.1.0a1
Apache-2.0); Python wheel does not bundle `libyog`; `YOG_VM_MAX_SOLUTIONS` defined in
`yog/src/vm/vm.h` but never enforced; no wall-clock or memory guard; the root `yog.py`
reference interpreter and the `bindings/python/yog` package share the import name `yog`.

## 2. Decisions

- **License: Apache-2.0 everywhere.** Root `LICENSE`, `README.md`, every `pyproject.toml` and `Cargo.toml` are aligned in P0-4.
- **Single version** across C library, Python and Rust packages, starting at `0.2.0-alpha.1` (`0.2.0a1` for Python).
- Unenforced resource caps are a DoS hole in a fail-closed engine: treat them as security fixes.
- `yog_studio` is out of scope until a WASM build exists.
- Recursion/tabling is 1.x. For 1.0, precompute role inheritance into facts and add a stdlib `under(path, prefix)` for resource trees.
- **No compound terms in the VM for 1.0.** Typed scalars (text, int, bool); JSON request records are flattened into typed `input` facts by the loader; lists are ground constants used through `in/2`.
- **Outcome lattice:** DENY > REQUIRE_APPROVAL > ALLOW > default deny. Obligations attach only to ALLOW and REQUIRE_APPROVAL, are unioned and deduplicated in a deterministic order, and are enforced by the gateway, never by YOG.
- Imports, hashing, signing, caching and the audit log live in the loader/sidecar/gateway layer. The C core stays I/O-free and dependency-free.
- Regex built-ins use a linear-time (non-backtracking) engine.
- Sidecar in Rust over the Rust binding; MCP gateway and extractors in Python over the Python binding.
- 1.0 = typed language, outcomes/obligations, signed bundles, sidecar, MCP gateway, approvals, Linux/Windows/macOS CI. 1.x = distribution and recursion.
- Decision cache key = full input + policy hash + state version.
- Rate-limit counters and "tests passed" flags live outside YOG. The gateway/state provider owns them; the threat model names who may write them.

## 3. Task table

Implementation of each item is one branch and one pull request. "Gate" items block the next phase.
The full engineering detail for each item (files, functions, tests, acceptance) is kept with the
implementation plan; this table is the shared index.

### Phase 0: foundations, spec, hygiene, early CI

| ID | Task | Depends on | Gate |
|---|---|---|---|
| P0-0 | Local toolchain (C compiler, CMake, Python 3.11) and a recorded baseline test run | - | no |
| P0-1 | `docs/SPEC.md` v2 language spec (types, `input`, `version`, outcomes, obligations, built-ins, encoding, integer overflow, identity/delegation, taint labels, limits) + `docs/RFC_TEMPLATE.md` | - | yes |
| P0-2 | `docs/INTERFACES.md` + `docs/schemas/`: JSON request/result, C API/ABI, trace, signed bundle, approval token, performance targets | P0-1, P0-7 | yes |
| P0-3 | `docs/THREAT_MODEL.md`: bypass, TOCTOU, forged input, poisoned output, exhaustion, tampering, replay, audit/trace secrets, state-writer and approver trust | - | yes |
| P0-4 | Hygiene: Apache-2.0, single version + `yog_version()`, rename reference interpreter to `reference/yog_ref.py`, cleanup | - | no |
| P0-5 | Resource guards: enforce `YOG_VM_MAX_SOLUTIONS`, wall-clock and memory limits | - | no |
| P0-6 | CI: Windows + macOS runners, libFuzzer job (builds on open PR #20) | - | no |
| P0-7 | Throwaway MCP gateway prototype in `prototypes/` with `FINDINGS.md` | - | feeds P0-2 |
| P0-9 | Keep this roadmap aligned with the implementation plan | - | no |
| P0-10 | Repo triage: unmerged branches, open PRs, stale files, `CONTRIBUTING.md`, branch protection | - | no |

**Phase 0 gate:** spec frozen with prototype findings folded in; hygiene merged; CI green on three OSes.

### Phase 1: core language

| ID | Task | Depends on |
|---|---|---|
| P1-0 | Test-first scaffolding: conformance cases and reference-interpreter support written before each feature | per feature |
| P1-1 | `version` statement, `input` declarations, typed values (bool, ground lists), JSON request loader | Phase 0 gate |
| P1-2 | `require_approval`, `obligate`, three-pass lattice, ABI version, structured error codes, `yogc` exit code 4 | P1-1 |
| P1-3 | Built-ins: `in`, `matches`, `glob`, `under`, string helpers, `cidr`, identity/scope helpers | P1-1 |
| P1-4 | State and time inputs (`state`, `now`), time built-ins | P1-2 |
| P1-5 | Modules/imports resolved by the loader, with source maps | P1-2 |
| P1-6 | Reference interpreter, differential and property parity for all of the above | each step |

Demo cut: P1-1, P1-2, P1-3 (`matches`, `under`).
**Phase 1 gate:** conformance, differential, property, unit, ASan/UBSan and fuzz smoke green on three OSes.

### Phase 2: engine hardening

| ID | Task |
|---|---|
| P2-1 | JSON proof traces with redaction (required by the demo) |
| P2-2 | First-argument indexing and predicate hash (replace linear scans) |
| P2-3 | ABI v1 structs, reference-counted hot reload |
| P2-4 | Static analysis: `yogc analyze`, `yogc can`, `yogc diff` |
| P2-5 | Signed bundles (Ed25519), policy hash, hash-chained audit log schema |
| P2-6 | Decision cache (key in section 2) |
| P2-7 | Benchmarks including Linux and service-boundary numbers |

**Phase 2 gate:** trace schema and API structs frozen (ABI v1); performance targets recorded.

### Phase 3: integrations and tooling (after the Phase 2 freeze)

| ID | Task |
|---|---|
| P3-1 | Python package: new API, bundled `libyog`, platform wheels |
| P3-2 | Rust crate: static build via `cc`, `yog-sys` + `yog` split |
| P3-3 | TypeScript/WASM package |
| P3-4 | Sidecar server (Rust, HTTP then gRPC) with audit log and cache |
| P3-5 | Extractors (SQL, shell, HTTP, k8s) with golden tests |
| P3-6 | Production MCP gateway (rebuilt from the prototype), obligations, output guard |
| P3-7 | Approval workflow bound to request hash + policy hash + TTL |
| P3-8 | Tooling: formatter, linter, REPL, `.yogtest` runner, LSP, VS Code syntax |
| P3-9 | Examples and demo assets |
| P3-10 | Agent-framework adapters (Python: LangChain, OpenAI Agents SDK, Claude Agent SDK; Rust: `GuardedTool`) |

Gateway rule: bypass must be impossible. The agent holds no credentials and tools are reachable only through the gateway.

### Phase 4 (1.x): distribution

| ID | Task |
|---|---|
| P4-1 | Signed policy distribution with staged self-test and rollback |
| P4-2 | Stateless PDP replicas (container image, Kubernetes manifests) |
| P4-3 | Fail-closed behaviour on timeout/partition, cache at scale |
| P4-4 | State consistency contract (versioned snapshots) |
| P4-5 | OpenTelemetry metrics and traces |
| P4-6 | Fault-injection tests |

### Phase 5: release readiness

| ID | Task |
|---|---|
| P5-1 | End-to-end agent scenarios in CI |
| P5-2 | Red-team suite and sustained fuzzing |
| P5-3 | Soak and concurrency testing |
| P5-4 | External security review and disclosure policy (team-commissioned) |
| P5-5 | Packaging and signed release automation |
| P5-6 | Documentation: tutorial, cookbook, operations, migration, API reference |
| P5-7 | Beta with real users, then the 1.0 spec freeze |

## 4. Readiness levels

1. **Demo-ready:** Phase 0 gate + P1-1..P1-3 + P2-1 + must-haves. Runs on the prototype gateway, upgraded and labeled demo-only; it does not wait for Phase 3.
   - Must have: frozen request/trace formats, updated bindings, minimal gateway, one extractor wired in, `REQUIRE_APPROVAL` with a simple approver bound to argument hash + TTL, scripted scenario (real agent, 1-2 real MCP servers, breakable staging environment).
   - Should have: bypass-proofing shown, fail-closed demo, policies for drop table, `rm -rf /`, prod deploy, and an injected "ignore previous rules" tool output.
   - Rehearse with a recorded fallback. Say "deterministic and fail-closed, hardening underway", never "production ready".
2. **Pilot-ready** (single node, internal): sidecar, signing, audit log, resource limits, extractors for real tools, red-team pass, production gateway.
3. **Production 1.0:** cross-OS CI, real libFuzzer campaign, external security review, packaging, migration guide, beta with real users, 1.0 spec freeze with SemVer.

## 5. Agents written in Python or Rust

Supported today as in-process library use:

- **Python:** `bindings/python/yog/__init__.py` (ctypes over the C ABI): `Yog.compile`, `check`, `evaluate`, `limits`, context manager. Needs `libyog` via `YOG_LIBRARY` / `YOG_LIB_DIR`; the wheel does not bundle it yet (P3-1).
- **Rust:** `bindings/rust/src/lib.rs`: `Yog::compile`, `check`, `check_with_context`, `limits`, `set_limits`. `build.rs` links the C library; the crate is unpublished (P3-2).
- **Pattern:** wrap every tool call (agent-framework tool or MCP client call) in `check()` before executing. On DENY or any error, do not execute (fail closed). With v2, `REQUIRE_APPROVAL` pauses until an approval bound to the argument hash arrives.
- **Caveats:** in-process enforcement can be bypassed by agent code, so production needs the gateway/sidecar to hold credentials (P3-4, P3-6); bindings only know ALLOW/DENY and text-fact context until P1-2 and P3-1; nothing is published to PyPI or crates.io; no TypeScript/WASM binding (P3-3). Framework adapters are P3-10.
- **Starting point:** `examples/ai_guardrails/enforce_demo.py`.

## 6. Merge rules

Every feature merges with spec text, conformance cases, a reference-interpreter update and fuzz coverage. Core and integrations live in separate directories with separate release cadences. No shipped wrapper before the API and trace freeze (prototype and demo-only code excepted). Nothing merges with red CI.

## 7. Verification per gate

- `cmake -B build -DYOG_SANITIZE=ON && cmake --build build && ctest` in `yog/` (MSVC build on Windows)
- `yog/tests/conformance/run_conformance.py`, `yog/tests/differential/diff_vs_python.py`, `yog/tests/property/property_conformance.py`, `examples/ai_guardrails/enforce_demo.py`
- `pytest` (`yog/tests/engine`, `tests/`, `bindings/python/tests`); `cargo test` in `bindings/rust`
- `benchmarks/run_benchmarks.py` and `benchmarks/compare.py`
- Demo/pilot: scripted agent scenario and red-team suite in CI on Linux, Windows and macOS

## 8. Status (updated with each commit on `feat/yog-v2`)

Legend: **done** = implemented, tested locally and in this branch; **partial** = some of the item is
done (see note); **unverified** = written but not built or run on this machine; **todo** = not started.

Local test environment: Windows laptop, MSVC `/W4 /WX`, Python 3.11. Application Control blocks some
freshly built executables and `yog.dll`, so the Python/Rust binding tests, Rust, Go, WASM and container
items can only be verified by CI or on another machine.

| ID | Status | Note |
|---|---|---|
| P0-0 | done | VS 2022 Build Tools, Python 3.11 installed; cargo/go/emcc/docker are NOT installed |
| P0-4 (a-d) | done | Apache-2.0, single version, `reference/yog_ref.py`, .gitignore |
| P0-5 | done | step/depth/solution/time/memory limits |
| P0-9 | done | roadmap aligned |
| P1-1 | partial | `version`, `input`, bool, typed context done; JSON request loader: todo |
| P1-2 | done | `require_approval`, obligations, lattice, exit code 4, API/yogc |
| P1-3 | partial | in, matches, glob, under, starts_with, ends_with, contains, cidr (IPv4 only) |
| P1-6 | done | reference interpreter rewritten; `diff_v2.py` (81 curated + 3,000 random per seed) |
| P1-1 (JSON) | done | `yog_check_json`, strict JSON reader, typed flattening, `yogc check-json` / `batch-json`; 161 checks in `test_json` |
| P0-1/2/3 | done | `docs/SPEC.md`, `INTERFACES.md`, `THREAT_MODEL.md`, `RFC_TEMPLATE.md` written to match the implementation |
| P1-4 | done | state/time are request inputs (`state`, `state_version`, `now`); policies compare them with ordinary goals |
| P1-5 | partial | imports are expanded by the Python loader (`yog_platform/imports.py`), not by a C API |
| P2-5 | partial | Ed25519 (RFC 8032 vectors), signed bundles, hash-chained audit log: in `yog_platform/`, tested |
| P2-6 | done | decision cache (`yog_platform/cache.py`) |
| P3-7 (core) | done | approval tokens bound to request hash, policy hash, expiry, single use |
| P3-1/P3-2 (bindings) | partial | Python and Rust bindings and the Windows Go adapter updated to the new `YogResult` layout, `REQUIRE_APPROVAL`, obligations and `check_json`; a C test pins the struct layout. **Rust is unverified** (cargo not installed); Python binding tests need CI (Application Control blocks `yog.dll` here) |
| P3-4 | done (Python) | sidecar in `yog_platform/sidecar.py` (the roadmap said Rust; Rust is not installed here); 65 platform tests |
| P2-3 | partial | atomic policy swap in `PolicyManager` (stage, self-test, swap, close old); no C-level refcounted handle |
| P4-1 | done | `Syncer` pulls signed bundles from a directory or HTTP registry; refuses downgrade, tampering and corrupt registries and keeps serving |
| P4-3 | done | fail-closed on engine crash/hang/timeout, missing policy, unwritable audit log; tested with a scripted fake `yogc` |
| P3-5 | done | SQL, shell, HTTP and Kubernetes (JSON) extractors with golden tests in `tests/golden/extractors/` (87 cases) and hostile-input tests. They report `parsed: false` instead of guessing |
| P3-6 | done (Python) | `yog_platform/gateway.py`: request building that keeps agent input apart from facts the gateway knows, approvals, obligations (audit, rate_limit, max_output_bytes), context taint, fail-closed; `mcp_proxy.py` stdio proxy; 49 end-to-end tests with the real extractors and policy (reference interpreter as PDP) |
| P3-7 | done | approval flow wired through the gateway and the proxy (`_meta.yog_approval_token` is stripped before forwarding) |
| P1-6 (JSON) | done | `reference/yog_ref.py` mirrors the C JSON loader (`request_to_facts`, `check_json`) |
| P3-8 | partial | Python tooling (`python -m yog_platform`): formatter (idempotent, meaning-preserving), static analysis (A001-A008), `.yogtest` runner with clause coverage, policy diff, bundle keygen/build/verify, `serve`. Not done: REPL, LSP, VS Code extension, a C-level `yogc fmt/analyze` |
| P2-1 | partial | structured trace converter (`yog_platform/trace.py`); the engine still emits text traces |

| P3-10 | partial | Claude Code `PreToolUse` hook (`yog_platform/claude_hook.py`, `examples/claude_code/guard.yog`); shell extractor now exposes `arg` words so `cat .env` is caught. Not done: LangChain/OpenAI/Rust adapters |
| P4-2 | unverified | `deploy/Dockerfile`, `deploy/kubernetes/sidecar.yaml` written without a container runtime |
| P4-4/P4-5 | partial | state contract and failure behaviour documented in `docs/OPERATIONS.md`; metrics endpoint exists, no OpenTelemetry |
| P0-10 | partial | `CONTRIBUTING.md` added; no repo triage report |
| F4 | done | delegation chains: gateway builds `acting_for`/`delegated`/`has_scope`/`chain_depth` facts from a trusted `Principal`; scopes only narrow (`yog_platform/delegation.py`, `examples/ai_guardrails/delegation.yog`) |
| F1 | done | shadow (log-only) mode in gateway, sidecar (`--shadow`) and Claude hook; documented in OPERATIONS.md |
| F2 | done | `compare` CLI and `yog_platform/compare.py`: bounded enumeration with counterexamples, never claims equivalence unless exhaustive; `yog_platform/smt.py`: optional Z3 proof for the supported fragment, counterexamples replayed on the reference |
| F3 | done | tool schema (`yog_platform/schema.py`): the gateway refuses calls that do not conform; analysis codes A009-A013 (`analysis_schema.py`); `analyze --schema`; sample `examples/claude_code/schema.json` |
| F5 | done | `yog_platform/partial_eval.py`: sound over-approximation of which tools could ever be allowed; `Gateway.visible_tools`, `McpProxy(visible=...)` tool-list filtering, `pdp.check_batch`; 200-seed soundness test |
