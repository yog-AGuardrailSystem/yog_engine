# YOG compiler and evaluator (C)

This directory contains the C implementation of the YOG policy engine. It
turns a `.yog` policy into a validated clause-table IR and evaluates
authorization requests against it.

The language contract is frozen in [`../docs/COMPILER.md`](../docs/COMPILER.md).
`../yog.py` remains the behavioural reference; the C engine is validated both
against it and by independent semantic tests.

## Pipeline

```text
source
  -> lexer        src/lexer/       tokens, indentation, comments
  -> parser       src/parser/      AST (ast.h) with line/column information
  -> semantic     src/sema/        C0..C5 validation + predicate symbol table
  -> IR           src/ir/          constants, predicates, clauses, queries
  -> VM           src/vm/          unification, trail, backward chaining
  -> authorization src/vm/engine.c deny > allow > default deny
  -> C API        include/api/     yog_compile / yog_check / yog_run_queries
```

Each stage is its own static library (`yog_lexer`, `yog_parser`, `yog_sema`,
`yog_ir`, `yog_vm`, `yog_api`). A stage only depends on the one before it, so
the semantic analyser never sees the VM and the solver never applies the
allow/deny policy.

### Why a clause table instead of bytecode

Policies are small and v1 rejects recursion, so a resolved clause table is
sufficient and much easier to snapshot-test than bytecode. The VM still does
real backward chaining with unification and backtracking; only the
instruction encoding is deferred. If a later version supports recursion or
needs indexing, the clause table is the natural input to a bytecode compiler.

## Building

Requirements: CMake 3.16+, a C11 compiler, and (optionally) a sanitizer-capable
GCC or Clang.

```sh
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug -DYOG_SANITIZE=ON
cmake --build yog/build --parallel
ctest --test-dir yog/build --output-on-failure
```

On Windows, configure from a Visual Studio developer prompt or after running
`vcvars64.bat`. `-DYOG_SANITIZE=ON` is ignored for MSVC; use Clang or GCC to
run with AddressSanitizer and UndefinedBehaviorSanitizer.

If Windows Application Control blocks `yogc.exe`, the executable is being
denied by the machine's security policy. Ask the administrator to approve an
authorized build; this repository cannot override that policy.

Warnings are errors (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`,
or `/W4 /WX`).

## Testing

### C unit and semantic tests

```sh
ctest --test-dir yog/build --output-on-failure
```

| Test | Protects |
| --- | --- |
| `test_lexer` | token stream, indentation, CRLF, error stickiness |
| `test_parser` | AST shape, grammar restrictions, error positions |
| `test_sema` | C0–C5, role conflicts, range restriction, cycles |
| `test_ir` | clause table, wildcard slots, constant interning, dump |
| `test_vm` | unification, backtracking, context facts, precedence |
| `test_api` | ownership, diagnostics, trace opt-in, exact reasons |
| `test_security` | step/depth limits, fail-closed errors, context isolation, concurrency |
| `test_fuzz_smoke` | deterministic malformed-input robustness |

### Differential tests against the Python reference

```sh
python yog/tests/differential/diff_vs_python.py
```

This runs every query and every ground decision request in `all_examples.yog`
through both engines and compares the decision, reason and bindings. It is
also run by CI.

### Independent conformance and property tests

```sh
python yog/tests/conformance/run_conformance.py
python yog/tests/property/property_conformance.py
```

The conformance suite states the expected result for every Group A–V request
and every compile error directly in `cases.json`, independently of `yog.py`.
The property suite generates acyclic policies and compares the engine with a
plain-Python oracle that does not use the YOG solver. See
[`../docs/CORRECTNESS.md`](../docs/CORRECTNESS.md).

### Fuzzing

`test_fuzz_smoke` runs on every build. Coverage-guided fuzzing is opt-in:

```sh
cmake -S yog -B yog/build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DYOG_SANITIZE=ON -DYOG_FUZZ=ON
cmake --build yog/build-fuzz --parallel
./yog/build-fuzz/fuzz_compile -max_len=4096 -timeout=10
```

### Python reference tests

```sh
python -m pytest yog/tests -q
```

## Command-line front end

`yogc` is the developer tool built next to the libraries:

```sh
yogc run      policy.yog                 # evaluate every `query` statement
yogc ir       policy.yog                 # dump the compiled clause table
yogc validate policy.yog                 # compile only and report
yogc explain  policy.yog                 # summarise decisions, clauses and limits
yogc explain  policy.yog ACTOR ACTION RESOURCE [--context "..."] [--trace]
yogc check    policy.yog ACTOR ACTION RESOURCE [--context "fact amount(acct_1, 9000)"] [--trace]
yogc batch    policy.yog                 # "actor action resource [| context]" per stdin line
```

Exit status: `0` allowed/ok, `1` compile error, `2` usage or I/O error,
`3` denied.

## C API

```c
#include "api/yog.h"

YogError error;
Yog *yog = yog_compile(source, strlen(source), &error);
if (yog == NULL) {
    fprintf(stderr, "%d:%d: %s\n", error.line, error.column, error.message);
    return 1;
}

YogResult result;
if (!yog_check(yog, actor, action, resource, /*context=*/NULL, /*trace=*/false,
               &result, &error)) {
    fprintf(stderr, "%s\n", error.message);
} else {
    printf("%s: %s\n", result.decision == YOG_ALLOW ? "ALLOW" : "DENY",
           result.reason);
    yog_result_free(&result);
}
yog_free(yog);
```

`yog_compile()` copies the source, so the caller's buffer may be freed
immediately. `YogResult` strings are owned by the result. `yog_check()` returns
`false` only for evaluation or I/O errors; a denied request is a successful
check with `result.decision == YOG_DENY`. On `false`, `result.decision` is still
initialized to `YOG_DENY`, so a caller that ignores the return value cannot
accidentally allow the action.

Evaluation budgets can be lowered from their defaults:

```c
YogLimits limits = { .max_steps = 50000, .max_depth = 64 };
yog_set_limits(yog, limits);
```

The compiled module is immutable, and every `yog_check()` creates its own
evaluator, so concurrent checks on the same `Yog` are safe. Call
`yog_set_limits()` during setup, before sharing the object; concurrent
mutation is a data race. See [`../docs/SECURITY.md`](../docs/SECURITY.md).

## Source map

| Path | Responsibility |
| --- | --- |
| `src/lexer/token.h` | token vocabulary shared by lexer and parser |
| `src/lexer/lexer.c` | indentation-aware tokenizer, no I/O |
| `src/parser/ast.h` / `ast.c` | AST types, allocation and cleanup |
| `src/parser/parser.c` | recursive-descent parser |
| `src/sema/symbol_table.*` | `(name, arity)` symbol table with roles |
| `src/sema/sema.*` | C0–C5 validation |
| `src/ir/ir.h` | compiled module, clause table, dump API |
| `src/ir/ir_build.c` | AST → IR lowering |
| `src/ir/ir_dump.c` | stable, line-oriented IR dump |
| `src/vm/vm.h` | value space, store, engine types |
| `src/vm/unify.c` | substitution store, trail, unification |
| `src/vm/engine.c` | backward chaining, negation, precedence |
| `include/api/yog.h` | public API |
| `src/api/yog.c` | compiler facade and context compilation |
| `tools/yogc.c` | CLI |
| `tools/lexdump.c` | token-stream debugger |

## Design notes

- **Single responsibility per target.** The lexer knows nothing about the
  parser, the semantic analyser does not lower, and the solver does not decide
  authorization.
- **Ownership is explicit.** Every failure path in `yog_compile()` unwinds the
  AST, symbol table, IR and engine it has built so far.
- **Untrusted policies are bounded.** Depth, step count, clause count, constant
  count and argument counts are capped. Limits fail closed.
- **Requests are isolated.** The compiled module is immutable; every check owns
  a fresh evaluator, store and trace. Context facts never survive a call.
- **Recursion is rejected in v1.** This is a documented language limitation
  that makes termination predictable; it is not required by the architecture.
- **No premature indexing.** Predicate lookup is a linear scan over a dynamic
  array. The benchmark shows the cost on the default-deny path as policies
  grow ([`../docs/BENCHMARKS.md`](../docs/BENCHMARKS.md)); indexing and clause
  ordering are the next optimization step, not a v1 requirement.
