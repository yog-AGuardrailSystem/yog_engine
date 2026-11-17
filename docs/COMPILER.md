# YOG language and compiler contract

This document freezes the behaviour that both implementations must agree on:

- `yog.py` is the behavioural reference;
- the C compiler in `yog/` is the production implementation;
- `all_examples.yog` is the canonical demonstration and conformance corpus
  (Groups A–V).

The C implementation is validated in several independent ways:

1. **semantic tests** that state the expected authorization result directly
   (`yog/tests/sema`, `yog/tests/ir`, `yog/tests/vm`, `yog/tests/api`);
2. **conformance cases** with hard-coded decisions and diagnostics
   (`yog/tests/conformance/cases.json`);
3. **property tests** against a non-YOG oracle
   (`yog/tests/property/property_conformance.py`);
4. **differential tests** that compare the C engine with `yog.py`
   (`yog/tests/differential/diff_vs_python.py`).

Agreement with `yog.py` alone is not enough: a bug shared by both
implementations would be invisible. Group R, for example, independently
establishes that a matching deny overrides a matching allow. See
[`CORRECTNESS.md`](CORRECTNESS.md) for the full strategy.

`query` and `check()` answer different questions. `query` evaluates the
logical program and reports whether a clause body is satisfiable; `check()`
applies the authorization contract below. Group R's confidential-document
query is `TRUE` (the allow body is satisfiable) while `check()` returns `DENY`
because the deny clause matches.

## 1. Grammar

A program is a sequence of statements. Blank lines and `#` comment lines are
ignored. Blocks are indentation based; only spaces are allowed.

```text
statement := fact | rule | allow | deny | query
fact      := "fact" atom NEWLINE
rule      := "rule" atom ":" NEWLINE INDENT goal+ DEDENT
allow     := "allow" atom ":" NEWLINE INDENT goal+ DEDENT
deny      := "deny" atom ":" NEWLINE INDENT goal+ DEDENT
query     := "query" atom NEWLINE

goal      := atom | "not" atom | comparison
comparison:= term OP term
atom      := IDENT "(" term ("," term)* ")"      -- at least one term
term      := VAR | WILDCARD | IDENT | STRING | INT
OP        := "==" | "!=" | "<" | "<=" | ">" | ">="
```

Deliberate restrictions, matching the reference parser:

- zero-arity atoms such as `foo()` are syntax errors;
- a rule body must contain at least one goal;
- the left operand of a comparison must be a variable or a literal, so
  `foo == bar` is not a comparison and is rejected;
- there is no `or` operator. Disjunction is expressed with multiple clauses
  that share the same head predicate.

## 2. Terms and values

| Term | Meaning | Runtime value |
| --- | --- | --- |
| `User`, `DB` | variable (uppercase) | bound by unification |
| `_` | wildcard | a fresh variable per occurrence |
| `alice` | identifier constant | text |
| `"quoted text"` | quoted string constant | text |
| `42`, `-7` | integer constant | integer |

Text constants (identifiers and quoted strings) share one namespace and unify
when their bytes are equal. Integers are a separate namespace: `42` never
equals `"42"`.

Variables are clause-local. The same clause may be used twice in one body;
each activation receives a fresh frame, so those uses never share bindings.

## 3. Predicates and arity

A predicate is identified by `(name, arity)`. `role/1` and `role/2` are
different predicates.

Each predicate has exactly one role in a program:

| Role | Defined by | May appear in a body |
| --- | --- | --- |
| fact | `fact` statements, and per-request context | yes |
| rule head | `rule` statements | yes |
| decision head | `allow` / `deny` statements | yes, but not as a decision call from `check()` |

Mixing roles for the same `(name, arity)` is an error.

## 4. Semantic rules

The analyser reports the first violation in source order.

- **C0 — ground facts.** A fact may not contain variables or wildcards.
- **C1 — single role.** A predicate cannot be both a fact and a rule head, a
  fact and a decision head, or a rule head and a decision head.
- **C2 — range restriction.** Every variable in the head of a *rule* must be
  bound by an atom in its body. Decision heads are exempt because their
  arguments are supplied ground by `check()`. Wildcards are not allowed in a
  rule head.
- **C3 — safe negation and comparison.** Variables inside `not` and in a
  comparison must be bound by an *earlier* atom in the same body. Wildcards
  are not allowed in either position.
- **C4 — defined calls.** Every predicate called from a body must be defined
  by a fact or a rule.
- **C5 — acyclic dependencies.** The rule-dependency graph must be acyclic.
  Recursion is a current language limitation, not an architectural one: it is
  rejected so that evaluation always terminates within the step budget.

## 5. Evaluation

Evaluation is backward chaining with depth-first search and chronological
backtracking. For one atom, clauses are tried in this order:

1. facts of the predicate, in source order;
2. facts injected for the current request (context), in source order;
3. rules whose head is the predicate, in source order;
4. decision clauses for the predicate, in source order.

Goals in a body are solved left to right. On failure the engine backtracks to
the most recent choice point and undoes only the bindings made after it (a
trail). `query` statements enumerate every solution; bindings of variables
that came from wildcards are not printed.

### Negation

`not atom` is negation as failure. The atom is evaluated with the current
bindings; any bindings it makes are undone afterwards. `not atom` succeeds
exactly when `atom` has no proof. Because C3 guarantees that its variables are
already bound, negation never introduces new bindings.

### Comparisons

Comparisons are evaluated only after both operands have been bound. Integers
compare numerically, text compares bytewise, and comparing text with an
integer is an evaluation error. Supported operators are `==`, `!=`, `<`,
`<=`, `>`, `>=`.

## 6. Authorization

`check(actor, action, resource)` does not run the general solver directly on
the request. It applies the policy-combining contract:

1. Look up the decision predicate `action/2`. If it does not exist (or is not
   a decision head), return **DENY** with
   `no allow/deny clause defines action <action>/2`.
2. Try every **deny** clause for that predicate. The first clause whose body
   has a solution wins: **DENY**, reason
   `deny clause at line <n> matched`.
3. Try every **allow** clause. The first matching clause wins: **ALLOW**,
   reason `allow clause at line <n> matched`.
4. Otherwise return **DENY** with
   `default deny: no allow clause was satisfied`.

The precedence is therefore **deny > allow > default deny**. This is
fail-closed: an error or an unknown action never yields ALLOW.

Logical evaluation (`solve_atom` / `solve_goals`) lives in the VM and knows
nothing about ALLOW or DENY. Only the engine's `check()` layer applies the
contract above. This separation is what makes the solver reusable and
independently testable.

## 7. Request context

`yog_check()` accepts an optional context string of ground facts, separated by
`;`, for example:

```text
fact amount(acct_1, 9000)
```

Context facts are parsed, validated and compiled for that one request, then
appended to the program's facts logically. They never modify the compiled
program, and a context containing anything other than `fact` statements is
rejected. `request.*` namespaces and implicit request atoms are deliberately
not part of the language.

Context is **authorization data**: if the caller supplies
`fact role(attacker, admin)`, an admin rule may match. The enforcement layer
must construct context from trusted data, not from raw model or end-user
output. See [`SECURITY.md`](SECURITY.md) §2.

### Declaring a context-only predicate

C4 requires every predicate called from a body to be defined by a fact or a
rule. A predicate whose facts only arrive through context therefore needs a
declaration. Do **not** use a sentinel fact:

```yog
fact amount(reserved_account, 0)   # unsafe: grants 0 <= Limit to that resource
```

A sentinel fact creates a real solution for one resource. Use a rule with a
guard that can never be true instead:

```yog
fact reserved_schema(reserved_account, reserved_amount)
rule amount(Account, Amount):
    reserved_schema(Account, Amount)
    0 == 1
```

The rule satisfies C4, never produces a solution, and context facts (tried
before rules, §5) remain the only source of amounts. Group I in
`all_examples.yog` uses this pattern, and the conformance suite asserts that
the sentinel cannot be used as an account.

## 8. Limits (security controls)

Policies are untrusted input. The implementation enforces fixed caps in
addition to the acyclic-rule restriction:

| Limit | Value | Where |
| --- | --- | --- |
| maximum evaluation depth | 256 | `YOG_VM_MAX_DEPTH` |
| maximum evaluation steps | 1,000,000 | `YOG_VM_MAX_STEPS` |
| maximum constants | 65,536 | `YOG_IR_MAX_VALUES` |
| maximum predicates | 4,096 | `YOG_IR_MAX_PREDICATES` |
| maximum clauses | 65,536 | `YOG_IR_MAX_CLAUSES` |
| maximum queries | 4,096 | `YOG_IR_MAX_QUERIES` |
| maximum atom arguments | 64 | `YOG_IR_MAX_ARGS` |
| maximum goals per clause | 256 | `YOG_IR_MAX_GOALS` |
| maximum lexer nesting | 64 | `YOG_LEXER_MAX_INDENT` |

Exceeding a limit is an error (fail-closed), never a partial result.

The two per-check budgets are configurable through the public API:

```c
YogLimits limits = { .max_steps = 50000, .max_depth = 64 };
yog_set_limits(yog, limits);
```

A zero field keeps the default. Lowering the budgets is appropriate for
latency-sensitive guardrails; the module-size caps are compile-time constants.

## 9. Concurrency

A `Yog` is immutable after `yog_compile()`. `yog_check()` and
`yog_run_queries()` create their own evaluator, substitution store and trace,
so concurrent calls on one `Yog` are safe. `yog_set_limits()` mutates the
`Yog`; call it during setup, before sharing the object. `yog_free()` must not
run while another thread is using the module.

## 10. Errors

Compilation errors carry a 1-based line and column and a NUL-terminated
message. `yog_compile()` returns `NULL`; `yog_check()` returns `false` only
for evaluation or I/O errors, never for a denied request. On `false`, the
result is still initialized with `decision = YOG_DENY`, so ignoring the return
value cannot turn an error into an allow.

The diagnostics are part of the contract and are asserted by the tests:

- `facts must be ground (no variables): <name>/<arity>`
- `predicate <name>/<arity> is both a <role> and a <role>; pick one role for it`
- `variable <X> in head of <name> is never bound by the body`
- `variable <X> is not bound before `not``
- `variable <X> is not bound before a comparison`
- `<name>/<arity> is not defined by any fact or rule`
- `rule cycle: <name>/<arity> -> ...`

## 11. Ownership

- `yog_compile()` copies the source. The caller may free its buffer as soon as
  the call returns.
- AST text slices point into the compiler's copy, which stays alive until
  `yog_free()`.
- `YogResult` strings belong to the result and are released with
  `yog_result_free()`.
- The IR module owns its constant pool, clause table and predicate table;
  `yog_ir_free()` releases all of it.
