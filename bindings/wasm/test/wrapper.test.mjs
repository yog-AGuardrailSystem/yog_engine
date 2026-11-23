// Tests the JavaScript wrapper's fail-closed behaviour against a scripted stand-in for the Emscripten module, so it runs
// without a WebAssembly build.  (engine.test.mjs runs the same API against the real module.)
import assert from "node:assert/strict";
import test from "node:test";
import { CompileError, load } from "../index.js";

function fakeModule({ compileError = null, replies = [] } = {}) {
  const heap = new Uint8Array(1 << 16);
  const view = new DataView(heap.buffer);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let top = 16;
  const freed = [];
  const put = (text) => {
    const bytes = encoder.encode(text);
    const pointer = top;
    heap.set(bytes, pointer);
    heap[pointer + bytes.length] = 0;
    top += bytes.length + 1;
    return pointer;
  };
  const queue = [...replies];
  return {
    freed,
    _malloc: (size) => {
      const pointer = top;
      top += size + 1;
      return pointer;
    },
    _free: (pointer) => freed.push(pointer),
    lengthBytesUTF8: (text) => encoder.encode(text).length,
    stringToUTF8: (text, pointer) => {
      const bytes = encoder.encode(text);
      heap.set(bytes, pointer);
      heap[pointer + bytes.length] = 0;
    },
    UTF8ToString: (pointer) => {
      let end = pointer;
      while (heap[end] !== 0) end += 1;
      return decoder.decode(heap.subarray(pointer, end));
    },
    getValue: (pointer) => view.getInt32(pointer, true),
    setValue: (pointer, value) => view.setInt32(pointer, value, true),
    _yog_wasm_compile: (_source, _length, errorSlot) => {
      if (compileError) {
        view.setInt32(errorSlot, put(JSON.stringify({ error: compileError })), true);
        return 0;
      }
      return 7;
    },
    _yog_wasm_check_json: () => {
      const next = queue.shift();
      return next === undefined ? 0 : put(typeof next === "string" ? next : JSON.stringify(next));
    },
    _yog_wasm_free_string: (pointer) => freed.push(pointer),
    _yog_free: () => {},
    _yog_policy_version: () => 2,
    _yog_version: () => put("0.2.0-alpha.1"),
  };
}

const load_ = (module) => load(async () => module);
const REQUEST = { actor: "a", action: "x", resource: "r" };

test("explicit decisions pass through", async () => {
  const module = fakeModule({ replies: [{ decision: "ALLOW", reason: "ok", obligations: [] }, { decision: "REQUIRE_APPROVAL", reason: "ask", obligations: [] }] });
  const policy = (await load_(module)).compile("p");
  assert.equal(policy.checkJson(REQUEST).decision, "ALLOW");
  assert.equal(policy.checkJson(REQUEST).decision, "REQUIRE_APPROVAL");
  assert.equal(policy.policyVersion, 2);
});

test("anything that is not an explicit decision becomes a DENY", async () => {
  const module = fakeModule({
    replies: [{ error: { message: "bad", line: 1, column: 2 } }, "not json", { decision: "MAYBE" }, { decision: "ALLOW", error: { message: "both" } }, {}],
  });
  const policy = (await load_(module)).compile("p");
  for (let i = 0; i < 5; i += 1) {
    const result = policy.checkJson(REQUEST);
    assert.equal(result.decision, "DENY", `reply ${i}`);
    assert.ok(result.error, `reply ${i}`);
  }
  assert.equal(policy.checkJson(REQUEST).decision, "DENY");        // the engine returned a null pointer
});

test("buffers are released even when evaluation fails", async () => {
  const module = fakeModule({ replies: ["not json"] });
  const policy = (await load_(module)).compile("p");
  policy.checkJson(REQUEST);
  assert.ok(module.freed.length >= 2, "input and output buffers freed");
});

test("compile errors become CompileError and free the error buffer", async () => {
  const module = fakeModule({ compileError: { message: "unexpected token", line: 3, column: 9 } });
  const engine = await load_(module);
  assert.throws(() => engine.compile("p"), (error) => error instanceof CompileError && error.line === 3 && error.column === 9);
  assert.ok(module.freed.length >= 3);
});

test("a request that cannot be serialised is a DENY and never reaches the engine", async () => {
  const module = fakeModule({ replies: [{ decision: "ALLOW", reason: "", obligations: [] }] });
  const policy = (await load_(module)).compile("p");
  const circular = {};
  circular.self = circular;
  assert.equal(policy.checkJson(circular).decision, "DENY");
  assert.equal(policy.checkJson(undefined).decision, "DENY");
  assert.equal(policy.checkJson(REQUEST).decision, "ALLOW");        // the scripted reply was still unused
});

test("a freed policy denies, and freeing twice is harmless", async () => {
  const policy = (await load_(fakeModule({ replies: [{ decision: "ALLOW", reason: "", obligations: [] }] }))).compile("p");
  policy.free();
  policy.free();
  assert.equal(policy.checkJson(REQUEST).decision, "DENY");
  assert.equal(policy.policyVersion, 0);
});

test("engine.version reads the C library version", async () => {
  assert.equal((await load_(fakeModule())).version, "0.2.0-alpha.1");
});
