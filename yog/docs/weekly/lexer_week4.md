# Week 4 — Lexer (C)

**Owner:** _<Viz_07>_  **Branch:** `feature/lexer-week4`  **Status:** done, ready for review

## What was built

| File | Purpose |
|---|---|
| `src/lexer/token.h` | Token types + `Token` struct. Shared with the parser; has no dependency on the lexer. |
| `src/lexer/lexer.h` | Public API: `lexer_init`, `lexer_next`, `lexer_error` (3 functions). |
| `src/lexer/lexer.c` | Implementation (indentation-aware, table-driven keywords/operators). |
| `tests/lexer/test_lexer.c` | 29 unit tests, no external framework. |
| `tools/lexdump.c` | Debug CLI: prints the token stream of a `.yog` file. |
| `CMakeLists.txt` | Builds the library, tests, and `lexdump`. |

## Build, test, debug

```bash
cmake -S . -B build -DYOG_SANITIZE=ON      # sanitizers on = catches memory bugs
cmake --build build
cd build && ctest --output-on-failure      # run the unit tests
./lexdump ../examples/example.yog          # see the tokens of any policy file
```

`lexdump` output is `LINE:COL TYPE [text]`. If the parser misbehaves, run
`lexdump` on the same file first to rule the lexer in or out.

## Token stream contract (what the parser can rely on)

- Blank lines and comment-only lines produce **no** tokens.
- Every other line ends with exactly one `NEWLINE` (even without a trailing `\n`).
- `INDENT`/`DEDENT` come **before** the first token of a line; one `DEDENT` per
  closed level; all open levels are closed before `EOF`. They are always balanced.
- `STRING` lexeme excludes the quotes; `INT` carries its value in `int_value`.
- Tokens point **into** the source buffer (no copies). Keep the buffer alive.
- After the first `TOK_ERROR` every call returns `TOK_ERROR`; after `EOF`, `EOF`.
  Details of the error: `lexer_error(&lx)` → message, line, column.

## Design notes (SOLID, as applied to C)

- **Single responsibility** — `token.h` is vocabulary only. In `lexer.c` every
  static function does one job (cursor movement, indentation, one scanner per lexeme).
  The lexer never prints, reads files, or allocates.
- **Open/closed** — keywords, operators and punctuation are *data tables*; token
  types come from one X-macro. A new keyword/operator is one new line, no logic change.
- **Liskov (C analogue)** — every `scan_*` function honours one contract (cursor on
  first byte in, just past the lexeme out), so the dispatcher treats them uniformly.
- **Interface segregation** — the parser sees three functions and `token.h`; the
  `Lexer` fields are private by convention.
- **Dependency inversion** — the lexer depends only on `(const char *, size_t)`,
  not on `FILE*` or `malloc`. That is why tests can use string literals.

## Verification (measured, GCC 13 / Ubuntu 24.04)

| Check | Result |
|---|---|
| Compile flags | `-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror` — clean |
| Unit tests | 29/29 pass, ~30,700 checks, under ASan + UBSan |
| Coverage (gcov) | 100% of lines (205), 100% of branches executed, 98.85% taken. The 2 untaken branches are defensive guards unreachable through the public API |
| Mutation testing | 22 deliberately injected bugs, **22 caught** (the first run caught 20 — two real test gaps, since fixed) |
| Differential test vs `reference/yog.py` | 6,023 comparisons (real policies in LF + CRLF, edge cases, random programs incl. broken ones): **0 mismatches** |
| Stress | 30,000 random byte inputs: always terminates, positions in range, INDENT/DEDENT balanced |

**Not tested:** clang, MSVC, macOS, valgrind (ASan used instead).

## Intentional differences from the Python reference

- Keywords/operators/punctuation are separate token types (`TOK_FACT`, `TOK_LTE`…)
  so the parser switches on an enum instead of comparing strings.
- Columns are tracked (needed for FR-2: errors with line **and** column).
- Integers outside 64 bits are an error (Python silently used big ints).
- Max 63 nested indentation levels (fixed-size stack, clean error, no overflow).
- ASCII-only identifiers (Python accepted Unicode letters). UTF-8 inside `"strings"` is fine.
- Line numbers of the closing `DEDENT`s/`EOF` at end of file follow "line after the last line".

## Known limitations / decisions for the team

- No string escapes in v1 (`"` cannot appear inside a string).
- `12abc` lexes as `INT` + `IDENT`; the parser should reject it.
- An indented first line produces `INDENT`; the parser should reject it.
- Tabs are rejected in indentation and inside lines (spaces only).

## Next week

- Parser (`src/parser/`) consumes `lexer_next()`; needs a `peek(k)` buffer on top
  (keep that in the parser, not the lexer).
