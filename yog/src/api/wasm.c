/*
 * wasm.c -- the WebAssembly entry points (built only with Emscripten; see yog/CMakeLists.txt, YOG_WASM).
 *
 * The public C ABI passes structs whose layout depends on the pointer width, which makes a hand-written JavaScript
 * mirror fragile.  These three functions take and return only integers, pointers and JSON text, so the JavaScript
 * wrapper (bindings/wasm) never has to know a struct layout.
 *
 * Fail closed: when a request cannot be evaluated the returned JSON has an "error" member and no "decision";
 * the wrapper turns that into a DENY.
 */
#ifdef __EMSCRIPTEN__

#include <emscripten.h>
#include <stdlib.h>
#include <string.h>

#include "api/yog.h"

/* Compiles a policy.  Returns the handle, or NULL with *error_json set to a malloc'd JSON error object. */
EMSCRIPTEN_KEEPALIVE Yog *yog_wasm_compile(const char *source, size_t length, char **error_json)
{
    YogError error;
    Yog *yog;
    memset(&error, 0, sizeof(error));
    yog = yog_compile(source, length, &error);
    if (yog == NULL && error_json != NULL) *error_json = yog_error_to_json(&error);
    return yog;
}

/* Checks one JSON request; always returns a malloc'd JSON text (a decision, or an error object). */
EMSCRIPTEN_KEEPALIVE char *yog_wasm_check_json(Yog *yog, const char *json, size_t length, int trace)
{
    YogResult result;
    YogError error;
    char *out;
    memset(&result, 0, sizeof(result));
    memset(&error, 0, sizeof(error));
    if (yog_check_json(yog, json, length, trace != 0, &result, &error)) {
        out = yog_result_to_json(yog, &result);
        yog_result_free(&result);
        return out;
    }
    yog_result_free(&result);
    return yog_error_to_json(&error);
}

EMSCRIPTEN_KEEPALIVE void yog_wasm_free_string(char *text)
{
    yog_string_free(text);
}

#endif /* __EMSCRIPTEN__ */
