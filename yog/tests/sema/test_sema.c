/*
 * test_sema.c -- independent semantic tests (not a differential harness).
 *
 * Each case states the language rule it protects; the expected outcome is
 * taken from the frozen specification in docs/COMPILER.md, not from what
 * yog.py happens to do.
 */
#include "../test_util.h"

#include "sema/sema.h"

static bool check_source(const char *source, YogSymbolTable *symbols,
                         YogSemaError *error)
{
    YogProgram *program = test_parse(source);
    bool ok;

    if (program == NULL) return false;
    yog_symbol_table_init(symbols);
    ok = yog_sema_check(program, symbols, error);
    yog_program_free(program);
    return ok;
}

static void test_accepts_well_formed_policy(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact environment(db1, production)\n"
        "rule may_delete(User, DB):\n"
        "    role(User, admin)\n"
        "    environment(DB, production)\n"
        "allow can_delete(User, DB):\n"
        "    may_delete(User, DB)\n"
        "deny can_delete(User, DB):\n"
        "    banned(User)\n"
        "fact banned(mallory)\n"
        "query can_delete(alice, db1)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(check_source(source, &symbols, &error));
    TEST_CHECK(symbols.count == 5); /* role, environment, may_delete, can_delete, banned */

    {
        size_t index;
        YogText name;

        name.text = "role";
        name.length = 4;
        TEST_CHECK(yog_symbol_table_find(&symbols, name, 2, &index));
        TEST_CHECK(symbols.items[index].role == YOG_ROLE_FACT);

        name.text = "may_delete";
        name.length = 10;
        TEST_CHECK(yog_symbol_table_find(&symbols, name, 2, &index));
        TEST_CHECK(symbols.items[index].role == YOG_ROLE_RULE);

        name.text = "can_delete";
        name.length = 10;
        TEST_CHECK(yog_symbol_table_find(&symbols, name, 2, &index));
        TEST_CHECK(symbols.items[index].role == YOG_ROLE_DECISION);
    }
    yog_symbol_table_free(&symbols);
}

static void test_fact_must_be_ground(void)
{
    static const char source[] = "fact role(Who, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "facts must be ground") != NULL);
}

static void test_predicate_has_one_role(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule role(User, Group):\n"
        "    member(User, Group)\n"
        "fact member(alice, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "is both a fact and a rule head") != NULL);
}

static void test_rule_head_variable_must_be_bound(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule admin_of(User, Group):\n"
        "    role(Group, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "never bound by the body") != NULL);
}

static void test_negation_operand_must_be_bound_earlier(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact revoked(bob)\n"
        "rule clean(User):\n"
        "    not revoked(User)\n"
        "    role(User, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "not bound before `not`") != NULL);
}

static void test_comparison_operand_must_be_bound_earlier(void)
{
    static const char source[] =
        "fact amount(acct_1, 4000)\n"
        "rule small(Acct):\n"
        "    Amount <= 5000\n"
        "    amount(Acct, Amount)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "not bound before a comparison") != NULL);
}

static void test_body_predicate_must_be_defined(void)
{
    static const char source[] =
        "rule bad(User):\n"
        "    role(User, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "not defined by any fact or rule") != NULL);
}

static void test_decision_head_is_exempt_from_range_restriction(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    /* User and DB are inputs supplied by check(), so they need not be bound. */
    TEST_CHECK(check_source(source, &symbols, &error));
    yog_symbol_table_free(&symbols);
}

static void test_wildcard_in_rule_head_is_rejected(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule odd(_):\n"
        "    role(alice, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "wildcard") != NULL);
}

static void test_recursion_is_rejected(void)
{
    static const char source[] =
        "fact edge(a, b)\n"
        "rule path(X, Y):\n"
        "    edge(X, Y)\n"
        "rule path(X, Z):\n"
        "    path(X, Y)\n"
        "    edge(Y, Z)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    TEST_CHECK(!check_source(source, &symbols, &error));
    TEST_CHECK(strstr(error.message, "rule cycle") != NULL);
    TEST_CHECK(strstr(error.message, "path") != NULL);
}

static void test_duplicate_fact_is_allowed(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact role(alice, admin)\n"
        "allow can_read(User, File):\n"
        "    role(User, admin)\n";
    YogSymbolTable symbols;
    YogSemaError error;

    /* Repeating a fact is idempotent, not a role conflict. */
    TEST_CHECK(check_source(source, &symbols, &error));
    yog_symbol_table_free(&symbols);
}

int main(void)
{
    test_accepts_well_formed_policy();
    test_fact_must_be_ground();
    test_predicate_has_one_role();
    test_rule_head_variable_must_be_bound();
    test_negation_operand_must_be_bound_earlier();
    test_comparison_operand_must_be_bound_earlier();
    test_body_predicate_must_be_defined();
    test_decision_head_is_exempt_from_range_restriction();
    test_wildcard_in_rule_head_is_rejected();
    test_recursion_is_rejected();
    test_duplicate_fact_is_allowed();
    return test_report("test_sema");
}
