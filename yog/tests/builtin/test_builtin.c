/*
 * test_builtin.c -- the pure built-in predicates: normal cases, edge cases and
 * hostile inputs (the matcher must stay linear and must never crash).
 */
#include "../test_util.h"

#include <string.h>
#include <time.h>

#include "builtin/builtin.h"

static YogBuiltinArg text(const char *s)
{
    YogBuiltinArg a;
    a.kind = YOG_ARG_TEXT;
    a.text = s;
    a.length = strlen(s);
    a.integer = 0;
    return a;
}

static YogBuiltinArg number(int64_t n)
{
    YogBuiltinArg a;
    a.kind = YOG_ARG_INTEGER;
    a.text = NULL;
    a.length = 0;
    a.integer = n;
    return a;
}

/* Returns 1 true, 0 false, -1 evaluation error. */
static int eval2(YogBuiltinId id, const char *a, const char *b)
{
    YogBuiltinArg args[2];
    bool result = false;
    char message[160];
    args[0] = text(a);
    args[1] = text(b);
    if (!yog_builtin_eval(id, args, 2, &result, message, sizeof(message))) return -1;
    return result ? 1 : 0;
}

static void test_lookup(void)
{
    TEST_CHECK(yog_builtin_find("matches", 7, 2) == YOG_BUILTIN_MATCHES);
    TEST_CHECK(yog_builtin_find("matches", 7, 3) == YOG_BUILTIN_NONE);
    TEST_CHECK(yog_builtin_find("in", 2, 2) == YOG_BUILTIN_IN);
    TEST_CHECK(yog_builtin_find("in", 2, 9) == YOG_BUILTIN_IN);   /* variadic */
    TEST_CHECK(yog_builtin_find("in", 2, 1) == YOG_BUILTIN_NONE);
    TEST_CHECK(yog_builtin_find("role", 4, 2) == YOG_BUILTIN_NONE);
    TEST_CHECK(strcmp(yog_builtin_name(YOG_BUILTIN_CIDR), "cidr") == 0);
}

static void test_in(void)
{
    YogBuiltinArg args[4];
    bool result = true;
    char message[64];

    args[0] = text("b"); args[1] = text("a"); args[2] = text("b"); args[3] = text("c");
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_IN, args, 4, &result, message, sizeof(message)) && result);
    args[0] = text("z");
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_IN, args, 4, &result, message, sizeof(message)) && !result);
    /* different kinds never compare equal, and that is not an error */
    args[0] = number(7); args[1] = text("7"); args[2] = number(8);
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_IN, args, 3, &result, message, sizeof(message)) && !result);
    args[2] = number(7);
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_IN, args, 3, &result, message, sizeof(message)) && result);
    TEST_CHECK(!yog_builtin_eval(YOG_BUILTIN_IN, args, 1, &result, message, sizeof(message)));
}

static void test_strings(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_STARTS_WITH, "/prod/db", "/prod") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_STARTS_WITH, "/prod", "/prod/db") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_STARTS_WITH, "abc", "") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_ENDS_WITH, "backup.sql", ".sql") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_ENDS_WITH, "sql", "backup.sql") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_CONTAINS, "rm -rf /", "-rf") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_CONTAINS, "ls", "-rf") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_CONTAINS, "ls", "") == 1);
}

static void test_wrong_kind_is_an_error(void)
{
    YogBuiltinArg args[2];
    bool result = false;
    char message[96];
    args[0] = number(1);
    args[1] = text("x");
    TEST_CHECK(!yog_builtin_eval(YOG_BUILTIN_CONTAINS, args, 2, &result, message, sizeof(message)));
    TEST_CHECK(strstr(message, "text") != NULL);
}

static void test_glob(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "report.csv", "*.csv") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "report.csv", "*.txt") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "a/b/c.log", "a/*/c.log") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "abc", "a?c") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "ac", "a?c") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "", "*") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "a*b", "a*b") == 1);     /* '*' in text */
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "xaxbx", "*a*b*") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, "xbxax", "*a*b*") == 0);
}

static void test_under(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod/db/data", "/prod") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod", "/prod") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod/", "/prod") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/production", "/prod") == 0);   /* not a string prefix */
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/staging/db", "/prod") == 0);
    /* traversal is normalised before comparing */
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/staging/../prod/db", "/prod") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod/../staging", "/prod") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/../prod/db", "/prod") == 1);   /* ".." at root stays */
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod/./db//x", "/prod/db") == 1);
    /* absolute and relative paths never match each other */
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "prod/db", "/prod") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/prod/db", "prod") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "../etc", "..") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/", "/") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, "/anything", "/") == 1);
}

static void test_cidr(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "10.1.2.3", "10.0.0.0/8") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "11.1.2.3", "10.0.0.0/8") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "192.168.1.77", "192.168.1.0/24") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "192.168.2.77", "192.168.1.0/24") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "1.2.3.4", "0.0.0.0/0") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "1.2.3.4", "1.2.3.4/32") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "1.2.3.5", "1.2.3.4/32") == 0);
    /* a malformed address is simply not inside the network */
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "10.0.0.256", "10.0.0.0/8") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "010.0.0.1", "10.0.0.0/8") == 0);   /* leading zero */
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "not-an-ip", "10.0.0.0/8") == 0);
    /* a malformed network in the policy is an error, so it fails closed */
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "10.0.0.1", "10.0.0.0") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "10.0.0.1", "10.0.0.0/33") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_CIDR, "10.0.0.1", "10.0.0.0/") == -1);
}

static void test_regex_basics(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "DROP TABLE users", "DROP TABLE") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "select 1", "DROP TABLE") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "^abc$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "xabc", "^abc$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abcx", "^abc$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "xabcx", "abc") == 1);        /* searched anywhere */
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "aaa", "^a*$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "", "^a*$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "", "a+") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "color", "^colou?r$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "colour", "^colou?r$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "colouur", "^colou?r$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "drop", "drop|truncate") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "truncate", "drop|truncate") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "delete", "drop|truncate") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abab", "^(ab)+$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "aba", "^(ab)+$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "id42", "^id[0-9]+$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "idx", "^id[0-9]+$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "ab12", "^[a-z]+\\d+$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "AB12", "^[^a-z]+$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "a.b", "^a\\.b$") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "axb", "^a\\.b$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "a b", "a\\sb") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "rm -rf /", "rm\\s+-rf") == 1);
}

static void test_regex_case_insensitive(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "DrOp TaBlE", "(?i)drop table") == 1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "DROP", "drop") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "XYZ", "(?i)^[a-z]+$") == 1);
}

static void test_regex_invalid_patterns_fail_closed(void)
{
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "(abc") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "abc)") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "[abc") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "*abc") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "a**") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "[z-a]") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "abc\\") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "abc", "[]") == -1);
}

static void test_regex_is_linear_on_hostile_patterns(void)
{
    /* (a+)+$ against "aaaa...b" takes exponential time in a backtracking
     * engine.  The NFA must answer immediately and correctly. */
    char subject[2049];
    clock_t start;
    double seconds;
    memset(subject, 'a', 2048);
    subject[2047] = 'b';
    subject[2048] = '\0';
    start = clock();
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, subject, "^(a+)+$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, subject, "(a|aa)+$") == 0);
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, subject, "^(a*)*b$") == 1);
    seconds = (double)(clock() - start) / (double)CLOCKS_PER_SEC;
    TEST_CHECK(seconds < 2.0);
}

static void test_size_limits(void)
{
    char big[5000];
    char pattern[300];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    memset(pattern, 'a', sizeof(pattern) - 1);
    pattern[sizeof(pattern) - 1] = '\0';
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, big, "a") == -1);       /* text too long */
    TEST_CHECK(eval2(YOG_BUILTIN_MATCHES, "a", pattern) == -1);   /* pattern too long */
    TEST_CHECK(eval2(YOG_BUILTIN_UNDER, big, "/") == -1);
    TEST_CHECK(eval2(YOG_BUILTIN_GLOB, big, "*") == -1);
}

static void test_embedded_zero_bytes(void)
{
    YogBuiltinArg args[2];
    bool result = false;
    char message[64];
    static const char subject[] = {'a', '\0', 'b'};
    args[0].kind = YOG_ARG_TEXT; args[0].text = subject; args[0].length = 3; args[0].integer = 0;
    args[1] = text("b");
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_CONTAINS, args, 2, &result, message, sizeof(message)) && result);
    args[1] = text("^a.b$");
    TEST_CHECK(yog_builtin_eval(YOG_BUILTIN_MATCHES, args, 2, &result, message, sizeof(message)) && result);
}

int main(void)
{
    test_lookup();
    test_in();
    test_strings();
    test_wrong_kind_is_an_error();
    test_glob();
    test_under();
    test_cidr();
    test_regex_basics();
    test_regex_case_insensitive();
    test_regex_invalid_patterns_fail_closed();
    test_regex_is_linear_on_hostile_patterns();
    test_size_limits();
    test_embedded_zero_bytes();
    return test_report("test_builtin");
}
