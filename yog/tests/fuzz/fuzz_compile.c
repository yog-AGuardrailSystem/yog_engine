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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    YogError error;
    Yog *yog;
    FILE *sink;

    if (size > 1u << 20) return 0;

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
