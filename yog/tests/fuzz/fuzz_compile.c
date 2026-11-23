/*
 * fuzz_compile.c -- libFuzzer harness for the compiler and evaluator.
 *
 * Build (Clang):
 *   clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -I yog/src -I yog/include \
 *         yog/tests/fuzz/fuzz_compile.c \
 *         yog/src/lexer/lexer.c yog/src/parser/ast.c yog/src/parser/parser.c \
 *         yog/src/sema/symbol_table.c yog/src/sema/sema.c \
 *         yog/src/ir/ir_build.c yog/src/ir/ir_dump.c \
 *         yog/src/vm/unify.c yog/src/vm/engine.c yog/src/api/yog.c \
 *         -o fuzz_compile
 *   ./fuzz_compile -max_len=4096 -timeout=10
 *
 * The harness must never crash, hang, leak or return a partial result: any
 * such finding is a security bug, because policies are untrusted input.
 *
 * CMake can build this target with -DYOG_FUZZ=ON when the toolchain supports
 * -fsanitize=fuzzer.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "api/yog.h"

static const char JSON_POLICY[] =
    "version 2\n"
    "input arg(text, any)\n"
    "input env(text, any)\n"
    "input now(int)\n"
    "deny act(U, R):\n    arg(\"q\", V)\n    matches(V, \"(?i)drop|^(a+)+$\")\n"
    "require_approval act(U, R):\n    env(\"stage\", \"prod\")\n    obligation audit(R)\n"
    "allow act(U, R):\n    arg(\"p\", P)\n    under(P, \"/work\")\n    now(T)\n    T > 5\n    obligation seen(T)\n";

/* The first byte picks the target: odd = a JSON request against a fixed policy, even = a policy. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    YogError error;
    Yog *yog;
    FILE *sink;

    if (size > 1u << 20) return 0;
    if (size > 0 && (data[0] & 1u)) {
        static Yog *json_policy;
        YogResult result;
        if (json_policy == NULL) {
            json_policy = yog_compile(JSON_POLICY, sizeof(JSON_POLICY) - 1, &error);
            if (json_policy == NULL) abort();
        }
        if (yog_check_json(json_policy, (const char *)data + 1, size - 1, false, &result, &error)) {
            char *text = yog_result_to_json(json_policy, &result);
            yog_string_free(text);
        } else if (result.decision != YOG_DENY) {
            abort();                                   /* an error must never look like an allow */
        }
        yog_result_free(&result);
        return 0;
    }

    yog = yog_compile((const char *)data, size, &error);
    if (yog == NULL) return 0;

    sink = tmpfile();
    if (sink != NULL) {
        (void)yog_run_queries(yog, sink, false);
        fclose(sink);
    }

    {
        YogResult result;
        if (yog_check(yog, "alice", "can_delete", "db1", NULL, false, &result, &error))
            yog_result_free(&result);
    }
    {
        YogResult result;
        if (yog_check(yog, "alice", "can_delete", "db1",
                      "fact role(alice, admin)", false, &result, &error))
            yog_result_free(&result);
    }

    yog_free(yog);
    return 0;
}
