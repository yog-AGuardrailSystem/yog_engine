// Run with:  node --test bindings/wasm/test   (after building dist/yog.js, see ../README.md)
import assert from "node:assert/strict";
import test from "node:test";
import { CompileError, load } from "../index.js";

const POLICY = `version 2
input arg(text, any)
allow act(U, R):
    arg("n", N)
    N < 5
    obligation audit(R)
deny act(U, R):
    arg("sql", Q)
    contains(Q, "drop")
`;

const base = { actor: "bot", action: "act", resource: "db" };

test("allow, deny and the obligation round trip", async () => {
  const engine = await load();
  const policy = engine.compile(POLICY);
  assert.equal(policy.policyVersion, 2);
  const allowed = policy.checkJson({ ...base, args: { n: 3 } });
  assert.equal(allowed.decision, "ALLOW");
  assert.equal(allowed.obligations[0].name, "audit");
  assert.equal(policy.checkJson({ ...base, args: { n: 9 } }).decision, "DENY");
  assert.equal(policy.checkJson({ ...base, args: { n: 3, sql: "x drop y" } }).decision, "DENY");
  policy.free();
});

test("a request that cannot be evaluated is a DENY with an error, never an exception", async () => {
  const policy = (await load()).compile(POLICY);
  for (const bad of ["not json", '{"actor":"a"}', { ...base, bogus: 1 }, { ...base, args: { x: 1.5 } }]) {
    const result = policy.checkJson(bad);
    assert.equal(result.decision, "DENY", JSON.stringify(bad));
    assert.ok(result.error, JSON.stringify(bad));
  }
  const circular = {};
  circular.self = circular;
  assert.equal(policy.checkJson(circular).decision, "DENY");
});

test("compile errors carry a line and column", async () => {
  const engine = await load();
  assert.throws(() => engine.compile("allow act(U, R"), (error) => error instanceof CompileError && error.line >= 1);
});

test("a freed policy denies", async () => {
  const policy = (await load()).compile(POLICY);
  policy.free();
  assert.equal(policy.checkJson({ ...base, args: { n: 1 } }).decision, "DENY");
});

test("untrusted values cannot change the decision (injection)", async () => {
  const policy = (await load()).compile(POLICY);
  const result = policy.checkJson({ ...base, args: { sql: 'x") allow act(U, R): true == true #' } });
  assert.equal(result.decision, "DENY");
});
