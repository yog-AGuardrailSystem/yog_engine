# YOG for WebAssembly (experimental)

This package wraps the C engine compiled to WebAssembly. It was written without an Emscripten toolchain on hand; the
`wasm` job in `.github/workflows/ci.yml` built it and ran `node --test bindings/wasm/test` successfully once (2026-11-23).
That job is still marked non-blocking, nothing is published to npm, and the module has had no use beyond those tests.

## Build

```sh
# with the Emscripten SDK active (or: docker run --rm -v "$PWD":/src -w /src emscripten/emsdk:3.1.64 ...)
emcmake cmake -S yog -B yog/build-wasm -DYOG_WASM=ON -DCMAKE_BUILD_TYPE=Release
cmake --build yog/build-wasm
mkdir -p bindings/wasm/dist
cp yog/build-wasm/yog.js yog/build-wasm/yog.wasm bindings/wasm/dist/
node --test bindings/wasm/test
```

## Use

```js
import { load } from "yog-engine-wasm";

const engine = await load();
const policy = engine.compile(`version 2
input arg(text, any)
allow act(U, R):
    arg("n", N)
    N < 5
`);
const result = policy.checkJson({ actor: "bot", action: "act", resource: "db", args: { n: 3 } });
// { decision: "ALLOW", reason: "...", obligations: [], matched_line: 3 }
policy.free();
```

`checkJson` never throws for a bad request: anything that is not an explicit decision from the engine comes back as
`{ decision: "DENY", error: {...} }`. Request values never pass through policy text, so they cannot inject policy.

## Limits and notes

* No threads, no filesystem: the module is a pure function of the policy and the request. Memory can grow (`ALLOW_MEMORY_GROWTH`).
* The engine's own limits (steps, depth, solutions, memory, a wall-clock backstop) apply; the wall clock uses `timespec_get`.
* Imports (`import "file"`) are expanded by the platform loader, not by this module: pass an already-expanded policy.
* Browser use is meant for demos and policy editors. A policy decision made in a browser is not enforcement.
