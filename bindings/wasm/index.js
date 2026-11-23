// JavaScript wrapper for the YOG WebAssembly module (yog/src/api/wasm.c).
//
// The wrapper fails closed: anything that is not an explicit ALLOW, REQUIRE_APPROVAL or DENY decision from the engine
// (an error object, malformed output, a JavaScript exception) comes back as { decision: "DENY", error }.
//
// Build the module first (see README.md); `dist/yog.js` is produced by Emscripten.

export class CompileError extends Error {
  constructor(message, line, column) {
    super(`${line}:${column}: ${message}`);
    this.name = "CompileError";
    this.line = line;
    this.column = column;
    this.detail = message;
  }
}

const DECISIONS = new Set(["ALLOW", "DENY", "REQUIRE_APPROVAL"]);

function denied(message) {
  return { decision: "DENY", reason: message, obligations: [], error: { message } };
}

export class Policy {
  #module;
  #handle;

  constructor(module, handle) {
    this.#module = module;
    this.#handle = handle;
  }

  /** Checks one request (an object, or a JSON string).  Never throws for a bad request: returns a DENY with `error`. */
  checkJson(request, { trace = false } = {}) {
    if (this.#handle === 0) return denied("the policy has been freed");
    let text;
    try {
      text = typeof request === "string" ? request : JSON.stringify(request);
      if (typeof text !== "string") return denied("the request is not JSON-serialisable");
    } catch (error) {
      return denied(`the request is not JSON-serialisable: ${error.message}`);
    }
    const m = this.#module;
    const bytes = m.lengthBytesUTF8(text);
    const input = m._malloc(bytes + 1);
    if (input === 0) return denied("out of memory");
    let outputPointer = 0;
    try {
      m.stringToUTF8(text, input, bytes + 1);
      outputPointer = m._yog_wasm_check_json(this.#handle, input, bytes, trace ? 1 : 0);
      if (outputPointer === 0) return denied("the engine returned no result");
      const parsed = JSON.parse(m.UTF8ToString(outputPointer));
      if (!parsed || !DECISIONS.has(parsed.decision) || parsed.error) {
        const message = parsed && parsed.error && parsed.error.message ? parsed.error.message : "the engine did not return a decision";
        return { ...denied(message), error: parsed && parsed.error ? parsed.error : { message } };
      }
      return parsed;
    } catch (error) {
      return denied(`evaluation failed: ${error.message}`);
    } finally {
      m._free(input);
      if (outputPointer !== 0) m._yog_wasm_free_string(outputPointer);
    }
  }

  /** The language version the policy declared with `version N` (1 when absent). */
  get policyVersion() {
    return this.#handle === 0 ? 0 : this.#module._yog_policy_version(this.#handle);
  }

  free() {
    if (this.#handle !== 0) {
      this.#module._yog_free(this.#handle);
      this.#handle = 0;
    }
  }
}

export class Engine {
  #module;

  constructor(module) {
    this.#module = module;
  }

  /** The version string of the C library inside the module. */
  get version() {
    return this.#module.UTF8ToString(this.#module._yog_version());
  }

  /** Compiles a policy.  Throws CompileError (with line and column) if it does not compile. */
  compile(source) {
    const m = this.#module;
    const bytes = m.lengthBytesUTF8(source);
    const input = m._malloc(bytes + 1);
    const errorSlot = m._malloc(4);
    if (input === 0 || errorSlot === 0) throw new Error("out of memory");
    try {
      m.stringToUTF8(source, input, bytes + 1);
      m.setValue(errorSlot, 0, "i32");
      const handle = m._yog_wasm_compile(input, bytes, errorSlot);
      if (handle === 0) {
        const pointer = m.getValue(errorSlot, "i32");
        let detail = { message: "the policy does not compile", line: 0, column: 0 };
        if (pointer !== 0) {
          try {
            detail = JSON.parse(m.UTF8ToString(pointer)).error ?? detail;
          } finally {
            m._yog_wasm_free_string(pointer);
          }
        }
        throw new CompileError(detail.message, detail.line ?? 0, detail.column ?? 0);
      }
      return new Policy(m, handle);
    } finally {
      m._free(input);
      m._free(errorSlot);
    }
  }
}

/** Loads the WebAssembly module and returns an Engine.  `factory` defaults to the Emscripten build in dist/. */
export async function load(factory) {
  const create = factory ?? (await import("./dist/yog.js")).default;
  return new Engine(await create());
}
