/*
 * test_util.h -- the tiny assertion helpers shared by the C test programs.
 *
 * No external framework: a test is a main() that calls TEST_CHECK and ends
 * with test_report().  A failed check prints file:line and the expression so
 * a red build points straight at the broken invariant.
 */
#ifndef YOG_TEST_UTIL_H
#define YOG_TEST_UTIL_H

#include <stdio.h>
#include <string.h>

#include "parser/parser.h"

static int test_checks = 0;
static int test_failures = 0;

#define TEST_CHECK(cond)                                                       \
    do {                                                                       \
        test_checks++;                                                         \
        if (!(cond)) {                                                         \
            test_failures++;                                                   \
            (void)fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                          #cond);                                              \
        }                                                                      \
    } while (0)

/* Parse `source`; returns NULL and prints the diagnostic on failure. */
static inline YogProgram *test_parse(const char *source)
{
    Lexer lexer;
    YogParseError error;
    YogProgram *program = NULL;
    YogParseStatus status;

    lexer_init(&lexer, source, strlen(source));
    status = yog_parse(&lexer, &program, &error);
    if (status != YOG_PARSE_OK) {
        (void)fprintf(stderr, "    parse error %s at %d:%d: %s\n",
                      yog_parse_status_name(status), error.line, error.column,
                      error.message);
        return NULL;
    }
    return program;
}

static inline int test_report(const char *name)
{
    if (test_failures == 0) {
        (void)printf("PASS: %s (%d checks)\n", name, test_checks);
        return 0;
    }
    (void)fprintf(stderr, "FAIL: %s (%d checks, %d failures)\n", name,
                  test_checks, test_failures);
    return 1;
}

#endif /* YOG_TEST_UTIL_H */
