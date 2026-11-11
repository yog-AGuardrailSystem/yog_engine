/*
 * test_api.c -- the public facade: ownership, diagnostics, and status codes.
 */
#include "../test_util.h"

#include <stdlib.h>

#include "api/yog.h"

static void test_compile_and_check(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(yog_module(yog) != NULL);

    TEST_CHECK(yog_check(yog, "alice", "can_delete", "db1", NULL, false,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    TEST_CHECK(strcmp(result.reason, "allow clause at line 2 matched") == 0);
    TEST_CHECK(result.trace == NULL);
    yog_result_free(&result);

    yog_free(yog);
}

static void test_trace_is_opt_in(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(yog_check(yog, "alice", "can_delete", "db1", NULL, true,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    TEST_CHECK(result.trace != NULL);
    TEST_CHECK(strstr(result.trace, "?- role(alice, admin)") != NULL);
    yog_result_free(&result);

    yog_free(yog);
}

static void test_compile_copies_the_source(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    char *mutable_source = malloc(sizeof(source));
    YogError error;
    Yog *yog;
    YogResult result;

    TEST_CHECK(mutable_source != NULL);
    if (mutable_source == NULL) return;
    memcpy(mutable_source, source, sizeof(source));

    yog = yog_compile(mutable_source, strlen(mutable_source), &error);
    memset(mutable_source, 'x', strlen(source));
    free(mutable_source);

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    /* The AST slices point into the compiler's own copy, so evaluation still
     * works after the caller's buffer is gone. */
    TEST_CHECK(yog_check(yog, "alice", "can_delete", "db1", NULL, false,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_syntax_error_is_reported(void)
{
    static const char source[] = "fact role(alice admin)\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);

    TEST_CHECK(yog == NULL);
    TEST_CHECK(error.message[0] != '\0');
    TEST_CHECK(error.line > 0);
}

static void test_semantic_error_is_reported(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule admin_of(User, Group):\n"
        "    role(Group, admin)\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);

    TEST_CHECK(yog == NULL);
    TEST_CHECK(strstr(error.message, "never bound by the body") != NULL);
    TEST_CHECK(error.line == 2);
}

static void test_unknown_action_denies(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(yog_check(yog, "alice", "can_read", "db1", NULL, false,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(strcmp(result.reason,
                      "no allow/deny clause defines action can_read/2") == 0);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_invalid_arguments(void)
{
    YogError error;
    YogResult result;

    TEST_CHECK(yog_compile(NULL, 0, &error) == NULL);
    TEST_CHECK(error.message[0] != '\0');
    TEST_CHECK(!yog_check(NULL, "a", "b", "c", NULL, false, &result, &error));
}

static void test_policy_from_file_shape(void)
{
    /* A policy with comments, blank lines and CRLF must compile too. */
    static const char source[] =
        "# a comment\r\n"
        "\r\n"
        "fact role(alice, admin)\r\n"
        "allow can_read(User, File):\r\n"
        "    role(User, admin)\r\n"
        "\r\n";
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(yog_check(yog, "alice", "can_read", "f1", NULL, false,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

int main(void)
{
    test_compile_and_check();
    test_trace_is_opt_in();
    test_compile_copies_the_source();
    test_syntax_error_is_reported();
    test_semantic_error_is_reported();
    test_unknown_action_denies();
    test_invalid_arguments();
    test_policy_from_file_shape();
    return test_report("test_api");
}
