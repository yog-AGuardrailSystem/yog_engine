/*
 * test_vm.c -- unification, backtracking, and the allow/deny contract.
 *
 * Unification is tested directly against the store, before any policy is
 * involved: when these primitives are wrong every higher-level failure is
 * hard to localise.
 */
#include "../test_util.h"

#include <stdlib.h>

#include "api/yog.h"
#include "vm/vm.h"

static YogValue text_value(const char *text)
{
    YogValue value;
    value.kind = YOG_VALUE_TEXT;
    value.text.text = text;
    value.text.length = strlen(text);
    value.integer = 0;
    return value;
}

static YogValue int_value(long long number)
{
    YogValue value;
    value.kind = YOG_VALUE_INTEGER;
    value.text.text = NULL;
    value.text.length = 0;
    value.integer = number;
    return value;
}

static void test_unification_primitive(void)
{
    YogValue values[3];
    YogModule module;
    YogValueSpace space;
    YogStore store;
    YogIRTerm x;
    YogIRTerm y;
    YogIRTerm admin;
    YogIRTerm user;
    YogIRTerm resolved;
    size_t base = 0;

    memset(&module, 0, sizeof(module));
    values[0] = text_value("admin");
    values[1] = text_value("user");
    values[2] = int_value(42);
    module.values = values;
    module.value_count = 3;

    space.module = &module;
    space.context = NULL;
    space.request = NULL;
    space.request_count = 0;

    yog_store_init(&store);
    TEST_CHECK(yog_store_push_frame(&store, 3, &base));

    x.kind = YOG_IR_VAR;
    x.index = base + 0;
    y.kind = YOG_IR_VAR;
    y.index = base + 1;
    admin.kind = YOG_IR_CONST;
    admin.index = 0;
    user.kind = YOG_IR_CONST;
    user.index = 1;

    /* unify(X, admin) -> X = admin */
    TEST_CHECK(yog_unify(&store, &space, x, admin));
    resolved = yog_store_resolve(&store, x);
    TEST_CHECK(resolved.kind == YOG_IR_CONST && resolved.index == 0);

    /* unify(admin, admin) -> success; unify(admin, user) -> failure */
    TEST_CHECK(yog_unify(&store, &space, admin, admin));
    TEST_CHECK(!yog_unify(&store, &space, admin, user));

    /* unify(X, X) -> success without binding */
    TEST_CHECK(yog_unify(&store, &space, x, x));

    /* unify(Y, X) follows the chain to the same constant */
    TEST_CHECK(yog_unify(&store, &space, y, x));
    resolved = yog_store_resolve(&store, y);
    TEST_CHECK(resolved.kind == YOG_IR_CONST && resolved.index == 0);

    /* Backtracking unbinds every cell created after the mark. */
    {
        YogIRTerm z;
        size_t mark = yog_store_mark(&store);
        z.kind = YOG_IR_VAR;
        z.index = base + 2;
        TEST_CHECK(yog_unify(&store, &space, z, user));
        resolved = yog_store_resolve(&store, z);
        TEST_CHECK(resolved.kind == YOG_IR_CONST && resolved.index == 1);
        TEST_CHECK(yog_store_reset(&store, mark));
        resolved = yog_store_resolve(&store, z);
        TEST_CHECK(resolved.kind == YOG_IR_VAR && resolved.index == base + 2);
    }

    yog_store_free(&store);
}

static Yog *compile_ok(const char *source)
{
    YogError error;
    Yog *yog = yog_compile(source, strlen(source), &error);

    if (yog == NULL)
        (void)fprintf(stderr, "    compile error %d:%d: %s\n", error.line,
                      error.column, error.message);
    return yog;
}

static void test_deny_overrides_allow(void)
{
    static const char source[] =
        "fact member(alice, team)\n"
        "fact banned(alice)\n"
        "allow read(User, Doc):\n"
        "    member(User, team)\n"
        "deny read(User, Doc):\n"
        "    banned(User)\n"
        "allow write(User, Doc):\n"
        "    member(User, team)\n";
    Yog *yog = compile_ok(source);
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    /* Matching deny beats matching allow. */
    TEST_CHECK(yog_check(yog, "alice", "read", "doc1", NULL, false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(strcmp(result.reason, "deny clause at line 5 matched") == 0);
    yog_result_free(&result);

    /* No allow clause matched -> default deny. */
    TEST_CHECK(yog_check(yog, "bob", "read", "doc1", NULL, false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(strcmp(result.reason, "default deny: no allow clause was satisfied") == 0);
    yog_result_free(&result);

    /* A matching allow with no deny -> ALLOW. */
    TEST_CHECK(yog_check(yog, "alice", "write", "doc1", NULL, false, &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    TEST_CHECK(strcmp(result.reason, "allow clause at line 7 matched") == 0);
    yog_result_free(&result);

    /* Unknown action is denied with the reference wording. */
    TEST_CHECK(yog_check(yog, "alice", "drop", "doc1", NULL, false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(strcmp(result.reason, "no allow/deny clause defines action drop/2") == 0);
    yog_result_free(&result);

    yog_free(yog);
}

static void test_request_context_facts(void)
{
    static const char source[] =
        "fact amount(dummy_account, 0)\n"
        "allow transfer(User, Acct):\n"
        "    amount(Acct, Amount)\n"
        "    Amount <= 5000\n";
    Yog *yog = compile_ok(source);
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(yog_check(yog, "finance_bot", "transfer", "acct_1",
                         "fact amount(acct_1, 4000)", false, &result, &error));
    TEST_CHECK(result.decision == YOG_ALLOW);
    yog_result_free(&result);

    TEST_CHECK(yog_check(yog, "finance_bot", "transfer", "acct_1",
                         "fact amount(acct_1, 9000)", false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    yog_result_free(&result);

    /* Context is per request; the compiled program is unchanged. */
    TEST_CHECK(yog_check(yog, "finance_bot", "transfer", "acct_1", NULL, false,
                         &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    yog_result_free(&result);

    yog_free(yog);
}

static void test_context_must_be_facts(void)
{
    static const char source[] =
        "fact member(alice, team)\n"
        "allow read(User, Doc):\n"
        "    member(User, team)\n";
    Yog *yog = compile_ok(source);
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(!yog_check(yog, "alice", "read", "doc1",
                          "rule bad(User):\n    member(User, team)", false,
                          &result, &error));
    TEST_CHECK(strstr(error.message, "may only contain fact statements") != NULL);
    yog_free(yog);
}

static void test_query_evaluation(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact role(bob, admin)\n"
        "fact role(carol, viewer)\n"
        "query role(alice, admin)\n"
        "query role(X, admin)\n"
        "query role(dave, admin)\n";
    Yog *yog = compile_ok(source);
    FILE *out;
    char buffer[8192];
    size_t read;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    out = tmpfile();
    TEST_CHECK(out != NULL);
    if (out == NULL) {
        yog_free(yog);
        return;
    }
    TEST_CHECK(yog_run_queries(yog, out, false));
    rewind(out);
    read = fread(buffer, 1, sizeof(buffer) - 1, out);
    buffer[read] = '\0';
    fclose(out);

    TEST_CHECK(strstr(buffer, "query role(alice, admin)\n  -> TRUE") != NULL);
    TEST_CHECK(strstr(buffer, "query role(dave, admin)\n  -> FALSE") != NULL);
    /* Backtracking enumerates every solution of the open query. */
    TEST_CHECK(strstr(buffer, "X=alice") != NULL);
    TEST_CHECK(strstr(buffer, "X=bob") != NULL);
    TEST_CHECK(strstr(buffer, "X=carol") == NULL);

    yog_free(yog);
}

static void test_evaluation_limits_are_configurable(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    Yog *yog = compile_ok(source);

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    /* The public facade does not expose limits yet; the symbols must exist so
     * embedders using the VM layer can tune them.  This is a compile-time
     * contract check rather than a runtime one. */
    TEST_CHECK(YOG_VM_MAX_DEPTH > 0);
    TEST_CHECK(YOG_VM_MAX_STEPS > 0);
    yog_free(yog);
}

int main(void)
{
    test_unification_primitive();
    test_deny_overrides_allow();
    test_request_context_facts();
    test_context_must_be_facts();
    test_query_evaluation();
    test_evaluation_limits_are_configurable();
    return test_report("test_vm");
}
