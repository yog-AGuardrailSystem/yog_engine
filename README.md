# YOG Engine

A small, deterministic policy engine for checking whether an AI agent's or
application's action is allowed **before** it happens.

> **Status:** early but working. The C lexer, parser, semantic analyser,
> clause-table IR, evaluator, C API and CLI are implemented and tested. The
> Python package/bindings are the next milestone.

## What it does

An app or AI agent proposes an action. YOG checks it against your rules and
returns **ALLOW / DENY** with the **reason**.

```text
fact role(alice, admin)

allow can_delete(User, DB):
    role(User, admin)

query can_delete(alice, database_1)
```

```console
$ yogc check policy.yog alice can_delete database_1
ALLOW|allow clause at line 3 matched
```

The precedence is **deny > allow > default deny**, so the engine is
fail-closed: an unknown action or an evaluation error never yields ALLOW.

## Repository layout

| Path | What it is |
| --- | --- |
| `all_examples.yog` | conformance corpus (Groups A–R and beyond) |
| `yog.py` | Python behavioural reference (parser, checker, engine) |
| `yog/` | C implementation: lexer → parser → sema → IR → VM → API → CLI |
| `yog/tests/` | C semantic tests, Python reference tests, differential tests |
| `docs/COMPILER.md` | frozen language and compiler contract |
| `yog/README.md` | architecture, build, test and API guide for the C engine |

## Build and test

```sh
cmake -S yog -B yog/build -DCMAKE_BUILD_TYPE=Debug -DYOG_SANITIZE=ON
cmake --build yog/build --parallel
ctest --test-dir yog/build --output-on-failure
python yog/tests/differential/diff_vs_python.py --yogc yog/build/yogc
python -m pytest yog/tests -q
```

On Windows, run the commands from a Visual Studio developer prompt (or after
`vcvars64.bat`). See [`yog/README.md`](yog/README.md) for the full build,
testing and C API documentation.

## How it's built

- **Core engine:** C11 (lexer, parser, semantic analyser, clause-table IR,
  unification/backtracking VM, authorization layer, C API, CLI).
- **Python reference:** `yog.py`, kept as the behavioural oracle and compared
  against the C engine on the conformance corpus.
- **Testing:** independent semantic tests (the specification decides the
  expected result) *and* differential tests (C versus Python), so a bug shared
  by both implementations is not invisible.
- **Python wrapper / packaging:** `ctypes` bindings and a pip-installable
  package are planned.

## Contributing (team members)

- Never push to `main` directly. It's protected.
- Create a branch: `feature/<what-you're-doing>`
- Push your branch and open a **Pull Request** into `main`.
- An **admin** must approve before it can be merged.

## License

MIT, see [LICENSE](LICENSE)
