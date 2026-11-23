# YOG language specification, version 2

Status: implemented in `yog/` (C engine) and `reference/yog_ref.py` (Python reference). Changes after
this point follow [RFC_TEMPLATE.md](RFC_TEMPLATE.md). Where this document and the code disagree, that is
a bug in one of them; the conformance and differential tests in `yog/tests/` are the arbiter.

YOG is a small, deterministic, non-recursive logic language for authorisation decisions. A policy is
evaluated against one request and answers `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, with optional
obligations. It never executes anything: the caller enforces the answer.

## 1. Design decisions

These were chosen deliberately and are the first things to challenge in review.

1. **No compound terms.** Values are text, integers and booleans only. Structured requests (JSON
   objects) are flattened into typed facts by the loader (section 9). This keeps unification, indexing and
   tracing simple.
2. **Lists are extra arguments.** There is no list literal; `in(X, a, b, c)` takes the candidates as
   arguments.
3. **Obligations are annotations inside the winning clause**, not separate statements, so they can use
   the clause's variables.
4. **Fail closed.** Any evaluation error (type mismatch, invalid pattern, exhausted limit, malformed
   request) is an error result that callers must treat as `DENY`. An error is never an `ALLOW`.
5. **Determinism.** Evaluation reads no clock, file, network or randomness. Time and state are request
   inputs (section 9). The same policy and request always give the same answer.
6. **Imports and crypto live outside the core.** The C core is pure: no I/O, no hashing, no signing.
7. **Recursion is rejected** in 2.x (rule 5, C5). It may be added later behind a new `version`.

## 2. Lexical structure

- Source is UTF-8. Lines are separated by `\n` or `\r\n`. Blank lines and `#` comments are ignored.
- Bodies are introduced by `:` and an indented block (spaces; consistent indentation).
- **Identifiers** start with a lowercase letter (`role`, `app.yaml`); **variables** start with an
  uppercase letter (`User`); `_` is a wildcard that never binds.
- **Strings** are `"..."`. There is **no escape syntax**: a string cannot contain `"`.
- **Integers** are optionally negative decimal numbers within the signed 64-bit range; an out-of-range
  literal is a lexical error.
- **Booleans** are `true` and `false`.
- **Reserved words:** `fact rule allow deny require_approval query not obligation input version true false`.
  The built-in predicate names (section 6) cannot be redefined.

## 3. Types

| Type | Written | Notes |
|---|---|---|
| text | `alice`, `"hello world"` | identifiers and quoted strings are the same type; compared bytewise |
| int | `42`, `-7` | 64-bit signed |
| bool | `true`, `false` | compared only with `==` and `!=` |

Values of different types are never equal, and comparing them is an evaluation error (`cannot compare a
string with an integer`, `cannot compare values of different types`). In particular `true` is not `1`.
Ordering comparisons (`< <= > >=`) work on int/int and text/text (bytewise, i.e. UTF-8 order).

## 4. Statements

```
version 2                                  # optional; must be the first statement
input   name(type, ...)                    # data supplied with each request
fact    name(const, ...)                   # ground data in the policy
rule    name(args): body                   # derived predicate
allow   action(Actor, Resource): body      # decision clauses
deny    action(Actor, Resource): body
require_approval action(Actor, Resource): body
query   name(args)                         # ask the engine (tooling and tests)
```

A body is one or more indented lines. Each line is a goal; all goals must hold (implicit AND):

- an atom `name(args)`;
- `not name(args)` (negation as failure);
- a comparison `A == B`, `A != B`, `A < B`, `A <= B`, `A > B`, `A >= B` (the left side must be a variable
  or a literal);
- a built-in call (section 6);
- `obligation name(args)`, allowed only in `allow` and `require_approval` bodies (section 7).

Disjunction is written as several clauses with the same head. Atoms always have at least one argument.

### 4.1 `version`

`version N` declares the language version the policy was written for. It must be the first statement and
appear once. `N` must be between 1 and the engine's supported version (currently 2); a newer version is
a compile error (`policy requires language version 3; this engine supports 1 to 2`). A policy without
the statement is version 1 and behaves as it always did. `yog_policy_version()` reports it.

### 4.2 `input`

`input name(text, int, bool, any)` declares a predicate whose facts arrive with each request. A type may
be `text`, `int`, `bool` or `any`. An input predicate:

- may be used in bodies like a fact predicate;
- cannot also be a `fact`, `rule` or decision head, and cannot be declared twice;
- has its constants type-checked at compile time (C6), and its request facts type-checked at evaluation
  time; a mismatch is an error, not an `ALLOW`.

## 5. Semantics

### 5.1 Decision

For a request `(actor, action, resource)` the engine looks for decision clauses whose head is
`action(Actor, Resource)` and evaluates them in three passes:

1. If any `deny` clause holds: **DENY**.
2. Else if any `require_approval` clause holds: **REQUIRE_APPROVAL**.
3. Else if any `allow` clause holds: **ALLOW**.
4. Else: **DENY** (default deny).

An action with no decision clause is `DENY` (`no allow/deny clause defines action X/2`). The `reason`
names the first clause of the winning kind that held (`allow clause at line 12 matched`); `matched_line`
is that line, or 0 for a default deny.

### 5.2 Evaluation

Backward chaining, depth first, clauses in source order. Facts are tried before rules; request facts
behave exactly like facts appended to the policy. Because recursion is rejected, evaluation terminates;
resource limits (section 10) bound the work regardless.

### 5.3 Negation

`not p(...)` succeeds when `p(...)` has no solution. Every variable in a negated atom must already be
bound (C3).

## 6. Built-in predicates

Built-ins are pure functions. All arguments must be bound before the call (C7). They can be negated.
Arguments of the wrong type (for example an integer passed to `contains`) are an evaluation error.

| Built-in | True when |
|---|---|
| `in(X, V1, V2, ...)` | `X` equals one of the candidates `Vi` (same type and value); takes `X` plus at least one candidate |
| `matches(Text, Pattern)` | the regular expression matches **anywhere** in `Text` (use `^` and `$` to anchor) |
| `glob(Text, Pattern)` | the whole text matches; `*` is any run of bytes (including `/`), `?` any one byte |
| `under(Path, Prefix)` | the normalised path equals the prefix or lies below it |
| `starts_with(Text, S)`, `ends_with(Text, S)`, `contains(Text, S)` | bytewise prefix, suffix, substring |
| `cidr(Ip, Network)` | the IPv4 address is inside `a.b.c.d/n` |

**Regular expressions** run on a linear-time NFA, so a hostile pattern cannot cause exponential
blow-up. Supported syntax: literals, `.` (any byte), `[abc]` `[a-z]` `[^...]`, `\d \w \s` and their
negations `\D \W \S` (ASCII), `\n \t \r`, `\x` for any other escaped literal, groups `( )`, alternation
`|`, repetition `* + ?` (not `{n,m}`, not lazy forms, no nested quantifiers like `a**`), anchors `^ $`, and a
leading `(?i)` for ASCII case-insensitivity. Matching works on UTF-8 bytes. An invalid pattern is an
evaluation error. Limits: pattern up to 256 bytes, text up to 4,096 bytes.

**`under`** normalises both arguments like a POSIX shell: `.` and empty segments disappear and `..`
removes the previous segment (`/..` stays at the root). A path is `under` a prefix when both are
absolute (or both relative) and the prefix's segments are a leading run of the path's. `/workshop` is not
under `/work`; `/work/../etc` is not under `/work`. It does **not** decode percent-escapes, resolve
symlinks, treat `\` as a separator or fold case; extractors must do that first. Up to 128 segments and
4,096 bytes.

**`cidr`** accepts dotted-quad IPv4 with no leading zeros; a malformed address is simply not inside any
network, while a malformed network in the policy is an evaluation error. IPv6 is not supported yet.

## 7. Obligations

```
allow can_run(Agent, Tool):
    allowed_tool(Tool)
    obligation audit("tool_call", Tool)
    obligation rate_limit(Agent, 10)
```

When the winning kind is `allow` or `require_approval`, the result carries the obligations of the
matching clauses of that kind: in clause order, one per `obligation` line, **deduplicated** (same name
and same argument values). Each is `{name, args[]}` with text, integer or boolean arguments. A `deny`
result has none. Obligations of non-winning kinds are not returned. An obligation argument may be a
literal or any variable the body binds (not `_`).

YOG never performs an obligation. The enforcement point (gateway or agent runtime) must, and must
refuse the action if it cannot. At most 256 distinct obligations per decision.

## 8. Compile-time rules

| Rule | Meaning |
|---|---|
| C0 | facts are ground (no variables) |
| C1 | a predicate has one role: fact, rule head, decision head or input; built-in names are reserved |
| C2 | every variable in a rule head is bound by the body |
| C3 | variables in `not` and comparisons are bound by an earlier atom; booleans compare only with `==`/`!=` |
| C4 | every called predicate is defined (built-ins always are) |
| C5 | the rule dependency graph is acyclic (no recursion) |
| C6 | constants passed to an input predicate match its declared types |
| C7 | built-in arguments are bound by an earlier atom |
| C8 | `version` is first, appears once and is supported |
| C9 | `obligation` appears only in `allow`/`require_approval` bodies and uses bound variables |

## 9. Requests and the JSON form

A request is `(actor, action, resource)` plus optional facts. The JSON form (see
[INTERFACES.md](INTERFACES.md)) flattens `args`, `env`, `state` and `now` into the typed facts
`arg/2`, `env/2`, `state/2`, `state_version/1` and `now/1`. A policy reads them by declaring
`input arg(text, any)` and so on.

**Time and state are inputs.** `now` is supplied by the caller as epoch seconds; the engine never reads
a clock. A policy that wants a time window writes `now(T)` and compares `T`. Counters ("at most 3 deletes
in 10 minutes") live outside YOG in a state provider that the caller trusts; YOG only sees their value.

**Text, integers and unicode.** Strings are UTF-8. The JSON loader rejects invalid UTF-8, NUL, null,
floats and nested arrays. YOG does not normalise Unicode: `"é"` and `"é"` are different
values, so extractors must canonicalise paths and commands before they reach a policy.

**Identity and taint.** Who is acting and whether a value came from untrusted content are ordinary
inputs (`env("principal", ...)`, `arg_taint("path", "untrusted")`). The gateway sets them; the policy
decides what to do with them.

## 10. Resource limits

Every limit is an evaluation error when exceeded. Defaults: 1,000,000 evaluation steps, depth 256,
100,000 solutions per query, 10 s wall clock (checked every 1,024 steps), 64 MiB evaluator memory,
256 obligations. Module limits: 65,536 constants, 4,096 predicates, 65,536 clauses, 4,096 queries, 64
arguments per atom, 256 goals per clause. JSON requests: 1 MiB, nesting 16, 20,000 values, 4,096 facts.
See [SECURITY.md](SECURITY.md).

## 11. Compatibility

Policies without a `version` statement or any v2 construct behave exactly as before. The C ABI and result
struct changed in 0.2.0 (new `YogDecision` value, obligations). The text context string of `yog_check()`
remains for trusted callers; untrusted values must use the JSON path.

## Appendix A. Decision semantics and the laws they satisfy

Evaluation of one request against one policy, in full:

```
decide(policy, request):
    facts := facts of the policy + facts derived from the request (section 9)
    if no allow/deny/require_approval clause defines the requested action:   return DENY (undefined action)
    if some deny clause is satisfied:                                        return DENY, no obligations
    if some require_approval clause is satisfied:                            return REQUIRE_APPROVAL, obligations(those clauses)
    if some allow clause is satisfied:                                       return ALLOW, obligations(those clauses)
    return DENY (default deny)
    any evaluation error (type error, limit exceeded, malformed request):    return error, which callers treat as DENY
obligations(clauses) = the obligation goals of the satisfied clauses of the winning kind, in clause order, de-duplicated
```

Laws that follow, each checked by `tests/platform/test_laws.py` over generated policies and by
`yog/tests/differential/diff_small_models.py` (exhaustively, C engine against the reference interpreter, for every policy of
at most two clauses over a fixed vocabulary):

1. **Determinism.** The same policy and request always give the same result.
2. **Order independence.** Reordering clauses never changes the decision or the set of obligations (it can change their
   order, which follows clause order).
3. **Deny monotonicity.** Adding a `deny` clause never makes a decision more permissive (DENY < REQUIRE_APPROVAL < ALLOW).
4. **Allow monotonicity.** Adding an `allow` clause never makes a decision less permissive.
5. **Precedence.** A satisfied `deny` clause cannot be overridden by any `require_approval` or `allow` clause; a satisfied
   `require_approval` clause overrides every satisfied `allow` clause.
6. **Obligation locality.** Obligations come only from clauses of the winning kind; a DENY carries none.
7. **Safe normalisation.** `under`, `matches`, `glob` and `cidr` never raise outside the evaluation-error channel and run in
   time bounded by the input size (the regular-expression engine is a Thompson simulation: no backtracking).

What is *not* claimed: there is no machine-checked proof of these laws. Cedar's team proves its authorizer in Lean and
differentially tests the Rust code against that model; the equivalent here would be a Lean or Coq model of this
pseudo-code plus a proof of laws 1-6, with the C engine tested against it. That work is not done; the evidence today is the
generated and exhaustive tests above.
