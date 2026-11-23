/*
 * test_v2.c -- language version 2 through the public API: input declarations,
 * booleans, require_approval, obligations, built-ins, the version pragma, and
 * the compile-time rules (C6..C9) that keep them safe.
 */
#include "../test_util.h"

#include <stdlib.h>
#include <string.h>

#include "api/yog.h"

/* ----------------------------------------------------------------- helpers */

static Yog *compile_ok(const char *source)
{
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    if (yog == NULL) (void)fprintf(stderr, "    unexpected compile error: %s (line %d)\n", error.message, error.line);
    return yog;
}

/* Compiles a policy that must be rejected and returns true when the error
 * message contains `needle`. */
static bool rejects(const char *source, const char *needle)
{
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);
    if (yog != NULL) {
        yog_free(yog);
        (void)fprintf(stderr, "    policy was accepted but should fail with \"%s\"\n", needle);
        return false;
    }
    if (strstr(error.message, needle) == NULL) {
        (void)fprintf(stderr, "    expected \"%s\" in \"%s\"\n", needle, error.message);
        return false;
    }
    return true;
}

static YogDecision decide(Yog *yog, const char *actor, const char *action, const char *resource,
                          const char *context, YogResult *out)
{
    YogError error;
    if (!yog_check(yog, actor, action, resource, context, false, out, &error)) {
        (void)fprintf(stderr, "    check failed: %s\n", error.message);
        return YOG_DENY;
    }
    return out->decision;
}

static bool obligation_is(const YogResult *result, size_t index, const char *name, size_t args)
{
    return index < result->obligation_count &&
           strcmp(result->obligations[index].name, name) == 0 &&
           result->obligations[index].arg_count == args;
}

/* ------------------------------------------------------------------- lattice */

static const char LATTICE[] =
    "input flag(text)\n"
    "allow act(U, R):\n    flag(\"allow\")\n"
    "require_approval act(U, R):\n    flag(\"approve\")\n"
    "deny act(U, R):\n    flag(\"deny\")\n";

static void test_precedence_lattice(void)
{
    /* every subset of {allow, approve, deny} matching, against the expected winner */
    static const struct { const char *ctx; YogDecision want; } cases[] = {
        { NULL,                                                   YOG_DENY },              /* default deny */
        { "fact flag(\"allow\")",                                 YOG_ALLOW },
        { "fact flag(\"approve\")",                               YOG_REQUIRE_APPROVAL },
        { "fact flag(\"deny\")",                                  YOG_DENY },
        { "fact flag(\"allow\"); fact flag(\"approve\")",         YOG_REQUIRE_APPROVAL },
        { "fact flag(\"allow\"); fact flag(\"deny\")",            YOG_DENY },
        { "fact flag(\"approve\"); fact flag(\"deny\")",          YOG_DENY },
        { "fact flag(\"allow\"); fact flag(\"approve\"); fact flag(\"deny\")", YOG_DENY },
    };
    Yog *yog = compile_ok(LATTICE);
    size_t i;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        YogResult result;
        TEST_CHECK(decide(yog, "u", "act", "r", cases[i].ctx, &result) == cases[i].want);
        yog_result_free(&result);
    }
    yog_free(yog);
}

static void test_reason_names_the_winning_clause(void)
{
    Yog *yog = compile_ok(LATTICE);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "r", "fact flag(\"approve\")", &result) == YOG_REQUIRE_APPROVAL);
    TEST_CHECK(strstr(result.reason, "require_approval clause at line 4") != NULL);
    TEST_CHECK(result.matched_line == 4);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "r", NULL, &result) == YOG_DENY);
    TEST_CHECK(result.matched_line == 0);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_decision_names(void)
{
    TEST_CHECK(strcmp(yog_decision_name(YOG_ALLOW), "ALLOW") == 0);
    TEST_CHECK(strcmp(yog_decision_name(YOG_DENY), "DENY") == 0);
    TEST_CHECK(strcmp(yog_decision_name(YOG_REQUIRE_APPROVAL), "REQUIRE_APPROVAL") == 0);
    TEST_CHECK(strcmp(yog_decision_name((YogDecision)99), "UNKNOWN") == 0);
}

/* --------------------------------------------------------------- obligations */

static void test_obligations_are_collected_in_order_and_deduplicated(void)
{
    static const char policy[] =
        "input role(text)\n"
        "allow act(U, R):\n    role(\"a\")\n    obligation audit(\"first\", U)\n    obligation tag(7)\n"
        "allow act(U, R):\n    role(\"a\")\n    obligation audit(\"first\", U)\n"      /* duplicate */
        "allow act(U, R):\n    role(\"b\")\n    obligation audit(\"second\", R)\n"
        "allow act(U, R):\n    role(\"a\")\n    obligation flagged(true)\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(decide(yog, "alice", "act", "doc", "fact role(\"a\")", &result) == YOG_ALLOW);
    TEST_CHECK(result.obligation_count == 3);
    TEST_CHECK(obligation_is(&result, 0, "audit", 2));
    TEST_CHECK(obligation_is(&result, 1, "tag", 1));
    TEST_CHECK(obligation_is(&result, 2, "flagged", 1));
    if (result.obligation_count == 3) {
        TEST_CHECK(result.obligations[0].args[0].kind == YOG_OBLIGATION_TEXT);
        TEST_CHECK(strcmp(result.obligations[0].args[0].text, "first") == 0);
        TEST_CHECK(strcmp(result.obligations[0].args[1].text, "alice") == 0);   /* bound variable */
        TEST_CHECK(result.obligations[1].args[0].kind == YOG_OBLIGATION_INTEGER);
        TEST_CHECK(result.obligations[1].args[0].integer == 7);
        TEST_CHECK(result.obligations[2].args[0].kind == YOG_OBLIGATION_BOOLEAN);
        TEST_CHECK(result.obligations[2].args[0].integer == 1);
    }
    yog_result_free(&result);

    /* only clauses that actually matched contribute */
    TEST_CHECK(decide(yog, "alice", "act", "doc", "fact role(\"b\")", &result) == YOG_ALLOW);
    TEST_CHECK(result.obligation_count == 1);
    TEST_CHECK(obligation_is(&result, 0, "audit", 2));
    if (result.obligation_count == 1) TEST_CHECK(strcmp(result.obligations[0].args[1].text, "doc") == 0);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_deny_carries_no_obligations(void)
{
    static const char policy[] =
        "input go(text)\n"
        "allow act(U, R):\n    go(\"x\")\n    obligation audit(\"allowed\")\n"
        "deny act(U, R):\n    go(\"x\")\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "r", "fact go(\"x\")", &result) == YOG_DENY);
    TEST_CHECK(result.obligation_count == 0 && result.obligations == NULL);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_obligations_come_only_from_the_winning_kind(void)
{
    static const char policy[] =
        "input go(text)\n"
        "allow act(U, R):\n    go(\"x\")\n    obligation from_allow(1)\n"
        "require_approval act(U, R):\n    go(\"x\")\n    obligation from_approval(2)\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "r", "fact go(\"x\")", &result) == YOG_REQUIRE_APPROVAL);
    TEST_CHECK(result.obligation_count == 1);
    TEST_CHECK(obligation_is(&result, 0, "from_approval", 1));
    yog_result_free(&result);
    yog_free(yog);
}

static void test_obligation_uses_variables_bound_in_the_body(void)
{
    static const char policy[] =
        "input owner(text, text)\n"
        "allow act(U, R):\n    obligation notify(Owner)\n    owner(R, Owner)\n";   /* bound later in the body */
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "doc", "fact owner(\"doc\", \"carol\")", &result) == YOG_ALLOW);
    TEST_CHECK(result.obligation_count == 1);
    if (result.obligation_count == 1) TEST_CHECK(strcmp(result.obligations[0].args[0].text, "carol") == 0);
    yog_result_free(&result);
    yog_free(yog);
}

/* ------------------------------------------------------------ compile rules */

static void test_obligation_placement_rules(void)
{
    TEST_CHECK(rejects("input p(text)\ndeny a(U, R):\n    p(U)\n    obligation x(1)\n",
                       "only allowed in allow and require_approval"));
    TEST_CHECK(rejects("fact p(a)\nrule r(X):\n    p(X)\n    obligation x(1)\n",
                       "only allowed in allow and require_approval"));
    TEST_CHECK(rejects("input p(text)\nallow a(U, R):\n    p(U)\n    obligation x(Unbound)\n",
                       "not bound by the clause body"));
    TEST_CHECK(rejects("input p(text)\nallow a(U, R):\n    p(U)\n    obligation x(_)\n",
                       "not bound by the clause body"));
}

static void test_input_declaration_rules(void)
{
    TEST_CHECK(rejects("input p(text)\ninput p(text)\n", "declared twice"));
    TEST_CHECK(rejects("input p(text)\nfact p(a)\n", "is an input"));
    TEST_CHECK(rejects("fact p(a)\ninput p(text)\n", "is an input"));
    TEST_CHECK(rejects("input p(string)\n", "unknown input type"));
    TEST_CHECK(rejects("input p(Text)\n", "unknown input type"));
    /* a typed constant in a rule body must match the declaration */
    TEST_CHECK(rejects("input p(int)\nrule r(X):\n    p(\"seven\")\n    p(X)\n", "must be int"));
    TEST_CHECK(rejects("input p(text)\nrule r(X):\n    p(7)\n    p(X)\n", "must be text"));
    TEST_CHECK(rejects("input p(bool)\nrule r(X):\n    p(1)\n    p(X)\n", "must be bool"));
    {
        Yog *yog = compile_ok("input p(any, int)\nrule r(X):\n    p(\"x\", 3)\n    p(true, X)\n");
        TEST_CHECK(yog != NULL);
        yog_free(yog);
    }
}

static void test_builtin_rules(void)
{
    TEST_CHECK(rejects("fact in(a, b)\n", "built-in predicate"));
    TEST_CHECK(rejects("fact contains(a, b)\n", "built-in predicate"));
    TEST_CHECK(rejects("input glob(text, text)\n", "built-in predicate"));
    /* arity decides: contains/3 is not a built-in, so it is an ordinary name */
    {
        Yog *yog = compile_ok("fact contains(a, b, c)\n");
        TEST_CHECK(yog != NULL);
        yog_free(yog);
    }
    TEST_CHECK(rejects("input p(text)\nallow a(U, R):\n    contains(X, \"y\")\n    p(X)\n", "not bound before built-in"));
    TEST_CHECK(rejects("input p(text)\nallow a(U, R):\n    contains(_, \"y\")\n", "not bound before built-in"));
}

static void test_version_rules(void)
{
    Yog *ok = compile_ok("version 2\nfact p(a)\n");
    TEST_CHECK(ok != NULL);
    if (ok != NULL) {
        TEST_CHECK(yog_policy_version(ok) == 2);
        yog_free(ok);
    }
    ok = compile_ok("fact p(a)\n");
    TEST_CHECK(ok != NULL);
    if (ok != NULL) {
        TEST_CHECK(yog_policy_version(ok) == 1);   /* absent means the original language */
        yog_free(ok);
    }
    ok = compile_ok("version 1\nfact p(a)\n");
    TEST_CHECK(ok != NULL && yog_policy_version(ok) == 1);
    yog_free(ok);
    TEST_CHECK(rejects("version 3\nfact p(a)\n", "language version 3"));
    TEST_CHECK(rejects("version 0\nfact p(a)\n", "language version 0"));
    TEST_CHECK(rejects("fact p(a)\nversion 2\n", "must be the first statement"));
    TEST_CHECK(rejects("version 2\nversion 2\n", "must be the first statement"));
    TEST_CHECK(rejects("version\n", "version number"));
    TEST_CHECK(rejects("version two\n", "version number"));
    TEST_CHECK(yog_policy_version(NULL) == 1);
}

static void test_boolean_rules(void)
{
    TEST_CHECK(rejects("input p(bool)\nallow a(U, R):\n    p(X)\n    X < true\n", "booleans can only be compared"));
    TEST_CHECK(rejects("input p(bool)\nallow a(U, R):\n    p(X)\n    false >= X\n", "booleans can only be compared"));
}

static void test_new_keywords_are_reserved(void)
{
    TEST_CHECK(rejects("fact input(a)\n", "Expected"));
    TEST_CHECK(rejects("fact version(a)\n", "Expected"));
    TEST_CHECK(rejects("fact obligation(a)\n", "Expected"));
    TEST_CHECK(rejects("fact p(true, a)\nfact true(a)\n", "Expected"));
}

/* ------------------------------------------------------------------ runtime */

static void test_booleans_flow_through_inputs(void)
{
    static const char policy[] =
        "input approved(text, bool)\n"
        "allow act(U, R):\n    approved(R, Flag)\n    Flag == true\n"
        "deny act(U, R):\n    approved(R, Flag)\n    Flag != true\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "d1", "fact approved(\"d1\", true)", &result) == YOG_ALLOW);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "d1", "fact approved(\"d1\", false)", &result) == YOG_DENY);
    TEST_CHECK(strstr(result.reason, "deny clause") != NULL);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_context_types_are_enforced(void)
{
    static const char policy[] =
        "input limit(text, int)\n"
        "allow act(U, R):\n    limit(R, N)\n    N > 5\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    YogError error;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "r", "fact limit(\"r\", 9)", &result) == YOG_ALLOW);
    yog_result_free(&result);
    /* a text where an int is declared is a malformed request: an error, never ALLOW */
    TEST_CHECK(!yog_check(yog, "u", "act", "r", "fact limit(\"r\", \"nine\")", false, &result, &error));
    TEST_CHECK(strstr(error.message, "argument 2 must be int") != NULL);
    TEST_CHECK(result.decision == YOG_DENY);
    yog_result_free(&result);
    TEST_CHECK(!yog_check(yog, "u", "act", "r", "fact limit(true, 9)", false, &result, &error));
    TEST_CHECK(strstr(error.message, "argument 1 must be text") != NULL);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_builtins_in_policies(void)
{
    static const char policy[] =
        "input call(text, text)\n"
        "input path(text)\n"
        "input ip(text)\n"
        "deny act(U, R):\n    call(R, Cmd)\n    matches(Cmd, \"(?i)rm\\\\s+-rf\")\n"
        "deny act(U, R):\n    path(P)\n    not under(P, \"/work\")\n"
        "deny act(U, R):\n    ip(A)\n    not cidr(A, \"10.0.0.0/8\")\n"
        "allow act(U, R):\n    call(R, Cmd)\n    in(Cmd, \"ls\", \"cat\", \"pwd\")\n"
        "allow act(U, R):\n    call(R, Cmd)\n    starts_with(Cmd, \"git \")\n    not contains(Cmd, \"push --force\")\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"ls\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"RM  -RF /\")", &result) == YOG_DENY);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"git status\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"git push --force\")", &result) == YOG_DENY);
    yog_result_free(&result);
    /* path traversal out of /work is caught because under() normalises first */
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"ls\"); fact path(\"/work/../etc/passwd\")", &result) == YOG_DENY);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"ls\"); fact path(\"/work/src/a.c\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"ls\"); fact ip(\"8.8.8.8\")", &result) == YOG_DENY);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "sh", "fact call(\"sh\", \"ls\"); fact ip(\"10.1.2.3\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_invalid_pattern_fails_closed(void)
{
    static const char policy[] =
        "input call(text)\n"
        "allow act(U, R):\n    call(C)\n    matches(C, \"(unclosed\")\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    YogError error;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(!yog_check(yog, "u", "act", "r", "fact call(\"x\")", false, &result, &error));
    TEST_CHECK(strstr(error.message, "invalid pattern") != NULL);
    TEST_CHECK(result.decision == YOG_DENY);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_builtin_with_wrong_kind_fails_closed(void)
{
    static const char policy[] =
        "input n(int)\n"
        "allow act(U, R):\n    n(X)\n    contains(X, \"1\")\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    YogError error;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(!yog_check(yog, "u", "act", "r", "fact n(5)", false, &result, &error));
    TEST_CHECK(strstr(error.message, "expects text") != NULL);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_context_separator_tolerates_spaces(void)
{
    static const char policy[] =
        "input a(text)\ninput b(text)\n"
        "allow act(U, R):\n    a(\"1\")\n    b(\"2\")\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "u", "act", "r", "fact a(\"1\"); fact b(\"2\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "u", "act", "r", "fact a(\"1\");\tfact b(\"2\")", &result) == YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_existing_policies_behave_as_before(void)
{
    static const char policy[] =
        "fact role(alice, admin)\n"
        "allow can_access(User, Resource):\n    role(User, admin)\n"
        "deny can_access(User, Resource):\n    role(User, banned)\n";
    Yog *yog = compile_ok(policy);
    YogResult result;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(decide(yog, "alice", "can_access", "db", NULL, &result) == YOG_ALLOW);
    TEST_CHECK(strstr(result.reason, "allow clause at line 2") != NULL);
    TEST_CHECK(result.obligation_count == 0);
    yog_result_free(&result);
    TEST_CHECK(decide(yog, "bob", "can_access", "db", NULL, &result) == YOG_DENY);
    yog_result_free(&result);
    yog_free(yog);
}

int main(void)
{
    test_precedence_lattice();
    test_reason_names_the_winning_clause();
    test_decision_names();
    test_obligations_are_collected_in_order_and_deduplicated();
    test_deny_carries_no_obligations();
    test_obligations_come_only_from_the_winning_kind();
    test_obligation_uses_variables_bound_in_the_body();
    test_obligation_placement_rules();
    test_input_declaration_rules();
    test_builtin_rules();
    test_version_rules();
    test_boolean_rules();
    test_new_keywords_are_reserved();
    test_booleans_flow_through_inputs();
    test_context_types_are_enforced();
    test_builtins_in_policies();
    test_invalid_pattern_fails_closed();
    test_builtin_with_wrong_kind_fails_closed();
    test_context_separator_tolerates_spaces();
    test_existing_policies_behave_as_before();
    return test_report("test_v2");
}
