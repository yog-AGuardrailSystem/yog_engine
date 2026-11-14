# YOG Engine Architecture: Quick Cheat Sheet

## The short explanation

YOG is a rulebook for deciding whether an action is allowed. An application
provides a `.yog` policy and asks YOG about an action. YOG checks the policy
and returns **ALLOW** or **DENY**, along with a reason. A matching deny wins;
if no allow rule matches, YOG denies by default.

## A mentor-ready explanation

> "A policy is written as facts and rules. The C engine reads and checks it,
> turns it into a form that is quick to evaluate, and then answers requests.
> Its decision layer checks deny rules before allow rules and defaults to deny.
> The Python version is a reference we compare against; tests also check the
> expected answers independently."

## How one request moves through the system

```text
policy.yog
    |
    v
CLI (yogc) or C API
    |
    v
read words -> understand statements -> check policy rules
    |
    v
store the checked policy in an internal form
    |
    v
match facts and rules for a request
    |
    v
deny wins -> otherwise allow if matched -> otherwise deny
    |
    v
decision + explanation
```

In everyday terms, the first stages make sure the rulebook is readable and
consistent. The evaluator then looks for evidence that a rule applies. The
final decision step turns those matches into an authorization answer.

## The C engine, in plain language

The stages are separate so each part has one job:

| Stage | What it does |
| --- | --- |
| Lexer | Breaks the policy text into meaningful pieces, like words and punctuation. |
| Parser | Groups those pieces into facts, rules, and queries. |
| Semantic checks | Catches policies that are written correctly but do not make sense, such as a rule calling something that was never defined. |
| Internal representation (IR) | Stores the checked policy in a consistent form the evaluator can use. |
| Evaluator (VM) | Tries facts and rules, follows their conditions, and finds matches. |
| Authorization layer | Applies YOG's decision order: deny, then allow, then default deny. |
| C API and CLI | Let another program or a person use the engine. |

### Important concepts

- **Fact:** information the policy can use, such as `role(alice, admin)`.
- **Rule:** a conclusion that follows when its conditions match.
- **Allow / deny:** rules that describe authorization decisions.
- **Query:** asks whether a logical statement has a match; it is not itself an authorization decision.
- **Context:** extra facts supplied for one request. They are kept separate from other requests.
- **Fail closed:** an unknown action or evaluation problem must not accidentally allow an action.

## What is the Python code for?

[`yog.py`](../yog.py) is a Python reference implementation of the language.
It gives the project a second implementation to compare against. It is not
the C engine's front end.

[`yog_cli.py`](../yog_cli.py) is a small Python command-line interface around
that reference implementation. The C engine's command-line program is
[`yog/tools/yogc.c`](../yog/tools/yogc.c).

## File and folder guide

| Path | How to describe it |
| --- | --- |
| [`README.md`](../README.md) | Project overview, decision rules, and common build/test commands. |
| [`all_examples.yog`](../all_examples.yog) | Main collection of example policies and requests used by the project. |
| [`yog.py`](../yog.py) | Python reference interpreter. |
| [`yog_cli.py`](../yog_cli.py) | Python CLI for trying the reference interpreter. |
| [`pyproject.toml`](../pyproject.toml) | Python package metadata and build settings. |
| [`yog/CMakeLists.txt`](../yog/CMakeLists.txt) | Describes how to build the C libraries, tools, benchmark, and tests. |
| [`yog/include/api/yog.h`](../yog/include/api/yog.h) | Public C interface an application can call. |
| `yog/src/lexer/` | Reads policy text and identifies its pieces. |
| `yog/src/parser/` | Turns those pieces into structured statements. |
| `yog/src/sema/` | Checks that statements and rule references are valid. |
| `yog/src/ir/` | Builds and prints the evaluator's internal policy form. |
| `yog/src/vm/` | Matches requests against facts and rules and applies authorization decisions. |
| `yog/src/api/yog.c` | Connects the public C functions to the compiler and evaluator. |
| `yog/tools/yogc.c` | Implements the C command-line commands. |
| `yog/tools/lexdump.c` | Small developer tool for viewing lexer output. |
| `tests/` | Tests for the Python reference and small agent examples. |
| `yog/tests/` | C tests, policy conformance checks, Python-vs-C comparisons, property checks, and fuzz tests. |
| [`examples/ai_guardrails/`](../examples/ai_guardrails/) | Example policies for shell, database, API, and financial actions. |
| [`benchmarks/`](../benchmarks/) | Generates policies and measures engine and command-line performance. |
| [`docs/COMPILER.md`](COMPILER.md) | Exact language and decision behavior. |
| [`docs/CORRECTNESS.md`](CORRECTNESS.md) | What the tests check and how the different test methods fit together. |
| [`docs/SECURITY.md`](SECURITY.md) | Safety boundaries, evaluation limits, and request isolation. |
| [`docs/BENCHMARKS.md`](BENCHMARKS.md) | Benchmark setup and how to interpret the results. |
| [`docs/RESEARCH.md`](RESEARCH.md) | Research questions, project positioning, and limitations. |

### C source files worth knowing by name

| File | One-line answer |
| --- | --- |
| `yog/src/lexer/lexer.c` | Reads the policy characters and produces tokens. |
| `yog/src/parser/parser.c` | Parses tokens into statements and expressions. |
| `yog/src/sema/sema.c` | Checks policy consistency and rule safety. |
| `yog/src/sema/symbol_table.c` | Keeps track of which predicates exist and how they are used. |
| `yog/src/ir/ir_build.c` | Converts checked statements into the evaluator's internal form. |
| `yog/src/ir/ir_dump.c` | Prints that internal form for inspection. |
| `yog/src/vm/unify.c` | Manages matching values and variable bindings. |
| `yog/src/vm/engine.c` | Evaluates rules and produces query or authorization results. |
| `yog/src/api/yog.c` | Implements the public compile and check operations. |
| `yog/tools/yogc.c` | Handles command-line input and output. |

## Commands you may be asked about

| Command | Simple explanation |
| --- | --- |
| `yogc validate policy.yog` | Check and compile a policy without making a decision request. |
| `yogc check policy.yog alice can_delete database_1` | Ask whether Alice can perform `can_delete` on `database_1`. |
| `yogc run policy.yog` | Run the `query` statements written in the policy. |
| `yogc explain policy.yog` | Summarize the policy's decisions and limits. |
| `yogc ir policy.yog` | Show the internal form created from the policy. |
| `yogc batch policy.yog` | Check multiple requests supplied through standard input. |

The C library offers the same core work through the public functions in
`yog/include/api/yog.h`; a program can compile a policy once and check many
requests.

## How the project checks its own answers

- **Unit tests** check each C stage on its own.
- **Conformance tests** compare results with expected answers written down in
  advance.
- **Differential tests** compare the C engine with the Python reference.
- **Property tests** generate policies and compare results with a separate
  simple oracle.
- **Fuzz tests** try malformed input to catch crashes and unsafe behavior.
- **Benchmarks** measure speed and memory; they are performance measurements,
  not correctness tests.

Useful details live in [`docs/CORRECTNESS.md`](CORRECTNESS.md).

## Three principles to remember

1. **Deny takes priority:** a matching deny beats a matching allow.
2. **Unknown means deny:** the safe default is not to authorize.
3. **Keep requests separate:** context for one request must not leak into the
   next.
