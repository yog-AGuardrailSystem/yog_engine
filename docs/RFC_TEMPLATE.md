# RFC: <short title>

- **Status:** draft | accepted | rejected | implemented
- **Author:**
- **Date:**
- **Affects:** language | C API / ABI | JSON formats | bundle format | tooling

## Motivation

What problem does this solve, and who hits it? Include a concrete policy or request that cannot be
expressed or decided correctly today.

## Proposal

The change, precisely enough to implement. Show the new syntax or API with examples. Say what the
engine does on every error path (it must fail closed).

## Compatibility

Does an existing policy, request or binding behave differently? If so, how is that signalled (a `version`
bump, a new field, a deprecation)?

## Security

New inputs, new resource use, new ways to forge or confuse a request. Update `docs/THREAT_MODEL.md` if a
trust boundary moves.

## Test plan

Which conformance cases, unit tests, differential cases and fuzz changes prove it. The change is not
accepted until `docs/SPEC.md`, the reference interpreter and the tests agree.

## Alternatives considered

What else was possible, and why not.
