# YOG Parser Changes and Tests

## Changes made

- Replaced the token-array parser interface with a streaming parser that reads tokens from the existing lexer using `lexer_next()`.
- Aligned parser token handling with the lexer’s `Token` / `TokenType` definitions, including the actual token names and `start`/`length` text slices.
- Added parser-side lookahead to support recursive-descent parsing.
- Added AST declarations and implementation for terms, atoms, goals, bodies, statements, and programs.
- Added parser error reporting and a smoke-test program.
- AST text slices reference the original source buffer. Keep that buffer alive and unchanged until the AST is no longer needed, then free the AST with `yog_program_free()`.

## Files

- `parser.h`, `parser.c` — parser API and implementation
- `ast.h`, `ast.c` — AST structures and memory management
- `test_parser.c` — integration smoke test


Keep the lexer files unchanged. Ensure include paths match your project's directory structure.

## Run the tests

From the project root, create a build directory:

```sh
mkdir -p build
```

Compile using the strict C11 warning flags used for the lexer (adjust source paths and `-I` to match your layout):

```sh
cc -std=c11 \
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror \
  -I src \
  src/lexer/lexer.c \
  src/parser/ast.c \
  src/parser/parser.c \
  tests/parser/test_parser.c \
  -o build/test_parser
```

Run the smoke test:

```sh
./build/test_parser
```

The previously run smoke test reported:

```text
PASS: 4 statements; rule contains 4 goals
```

This verifies the tested sample only; it is not a complete grammar or error-handling test suite.

## Optional sanitizer run

```sh
cc -std=c11 -g -O1 \
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I src \
  src/lexer/lexer.c \
  src/parser/ast.c \
  src/parser/parser.c \
  tests/parser/test_parser.c \
  -o build/test_parser_san

./build/test_parser_san
```

If your headers are arranged under `include/yog/...`, update `-I src` and the include directives accordingly. A test passes only if it exits successfully and its assertions match the expected AST and error behavior.
