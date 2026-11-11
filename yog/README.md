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

### Differential tests against the Python reference

```sh
python yog/tests/differential/diff_vs_python.py --yogc yog/build/yogc
```

This runs every query and every ground decision request in `all_examples.yog`
through both engines and compares the decision, reason and bindings. It is
also run by CI.

### Python reference tests

```sh
python -m pytest yog/tests -q
```

## Command-line front end

`yogc` is the developer tool built next to the libraries:

```sh
yogc run   policy.yog                 # evaluate every `query` statement
yogc ir    policy.yog                 # dump the compiled clause table
yogc check policy.yog ACTOR ACTION RESOURCE [--context "fact amount(acct_1, 9000)"] [--trace]
yogc batch policy.yog                 # "actor action resource [| context]" per stdin line
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
check with `result.decision == YOG_DENY`.

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
- **Recursion is rejected in v1.** This is a documented language limitation
  that makes termination predictable; it is not required by the architecture.
- **No premature indexing.** Predicate lookup is a linear scan over a dynamic
  array, which is the right complexity for policies with tens of predicates.
  A hash table or per-predicate indexing can be added when profiling justifies
  it.
