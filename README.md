# YOG Engine

A small, deterministic policy engine for checking whether an AI agent's or application's action is allowed **before** it happens.

> **Status:** 🚧 Early development (final-year project). Nothing is usable yet.

## What it does

An app or AI agent proposes an action. YOG checks it against your rules and returns **allow / deny** along with the **reason**.

```text
fact role(alice) = admin

rule can_delete(user, resource):
    role(user) == admin

query can_delete(alice, database1)   # -> allowed
```

From Python (planned):

```python
import yog

yog.load_policy("policy.yog")
yog.check(actor="alice", action="delete", resource="database1")
# {"allowed": true, "reason": "role(alice) == admin"}
```

## How it's built

- **Core engine:** written in C (lexer → parser → bytecode compiler → VM)
- **Python wrapper:** calls the C engine through `ctypes`
- **Distribution:** pip-installable package (planned)

## Contributing (team members)

- Never push to `main` directly. It's protected.
- Create a branch: `feature/<what-you're-doing>`
- Push your branch and open a **Pull Request** into `main`.
- An **admin** must approve before it can be merged.

## License

MIT, see [LICENSE](LICENSE)

