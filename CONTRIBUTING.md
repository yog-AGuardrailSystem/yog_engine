# Contributing

- Branch from `main` as `feat/<topic>`; open a pull request; `main` is protected.
- C engine: build with `cmake -S yog -B build && cmake --build build && ctest --test-dir build` (warnings are errors).
- Python platform and reference: `pip install pytest && pytest tests/platform tests`; set `YOGC` to a built `yogc` to
  include the real-engine tests.
- Language changes need an entry in `docs/SPEC.md` (see `docs/RFC_TEMPLATE.md`), conformance cases, and the
  reference interpreter in `reference/yog_ref.py` updated so `yog/tests/differential/diff_v2.py` still agrees.
- Commit messages: imperative, prefixed with the roadmap item (e.g. `P3-5: ...`).
- Licence: Apache-2.0; by contributing you agree your work is licensed the same way.
