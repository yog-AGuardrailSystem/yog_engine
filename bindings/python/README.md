# YOG Python binding

A `ctypes` wrapper over the public YOG C ABI (`yog/include/api/yog.h`). It
executes the same shared library as the C tests; no policy logic is
reimplemented in Python.

## Build the shared library

```sh
cmake -S yog -B yog/build-release -DCMAKE_BUILD_TYPE=Release
cmake --build yog/build-release --target yog_shared
```

The binding searches `yog/build-release`, `yog/build`, then the system loader.
Set `YOG_LIBRARY=/absolute/path/to/yog.dll` (or `libyog.so`) to override.

## Use

```python
from yog import Yog

policy = Yog("""
fact role(alice, admin)
allow can_access(User, Resource):
    role(User, admin)
""")

print(policy.check("alice", "can_access", "db"))   # ALLOW
print(policy.check("bob", "can_access", "db"))     # DENY
print(policy.evaluate("bob", "can_access", "db"))  # ('DENY', 'no allow clause matched')
```

`Yog` is immutable after compilation; each check creates a fresh evaluator, so
instances can be shared between threads after `limits` is set. Evaluation
errors raise `YogEvaluationError`; callers that need fail-closed semantics must
catch it and deny.

`policy.limits` reads and sets `(max_steps, max_depth)`. `policy.resource_limits`
exposes every budget as a dict (`max_steps`, `max_depth`, `max_solutions`,
`max_millis`, `max_memory`); assigning a partial dict changes only those keys,
and `0` restores a default:

```python
policy.resource_limits = {"max_millis": 50, "max_memory": 8 * 1024 * 1024}
```

## Test

```sh
python -m pytest bindings/python/tests -q
```
