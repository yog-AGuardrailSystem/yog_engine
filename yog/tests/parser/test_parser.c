/*
 * test_parser.c -- AST shape and grammar conformance tests.
 *
 * The parser must accept exactly the language yog.py accepts.  The negative
 * cases below are part of that contract: zero-arity atoms, empty bodies, and
 * comparisons whose left operand is an identifier are syntax errors.
 */
#include "../test_util.h"

static void test_statement_shape(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule can_delete(User, DB):\n"
        "    role(User, admin)\n"
        "    environment(DB, development)\n"
        "    User != nobody\n"
        "    not revoked(User)\n"
        "allow can_read(User, File):\n"
        "    role(User, reader)\n"
        "query can_delete(alice, database_1)\n";
    YogProgram *program = test_parse(source);

    TEST_CHECK(program != NULL);
    if (program == NULL) return;

    TEST_CHECK(program->statement_count == 4);
    TEST_CHECK(program->statements[0].type == YOG_STATEMENT_FACT);
    TEST_CHECK(program->statements[1].type == YOG_STATEMENT_RULE);
    TEST_CHECK(program->statements[2].type == YOG_STATEMENT_ALLOW);
    TEST_CHECK(program->statements[3].type == YOG_STATEMENT_QUERY);

    TEST_CHECK(program->statements[1].as.clause.body.goal_count == 4);
    TEST_CHECK(program->statements[1].as.clause.body.goals[2].type == YOG_GOAL_COMPARISON);
    TEST_CHECK(program->statements[1].as.clause.body.goals[2].as.comparison.operator_type ==
               YOG_COMPARE_NE);
    TEST_CHECK(program->statements[1].as.clause.body.goals[3].type == YOG_GOAL_NEGATION);

    yog_program_free(program);
}

static void test_term_kinds(void)
{
    static const char source[] =
        "fact thing(Var, ident, \"quoted text\", 42, _)\n";
    YogProgram *program = test_parse(source);
    const YogAtom *atom;

    TEST_CHECK(program != NULL);
    if (program == NULL) return;

    atom = &program->statements[0].as.fact;
    TEST_CHECK(atom->term_count == 5);
    TEST_CHECK(atom->terms[0].type == YOG_TERM_VARIABLE);
    TEST_CHECK(atom->terms[1].type == YOG_TERM_IDENTIFIER);
    TEST_CHECK(atom->terms[2].type == YOG_TERM_STRING);
    TEST_CHECK(atom->terms[2].text.length == strlen("quoted text"));
    TEST_CHECK(memcmp(atom->terms[2].text.text, "quoted text",
                      atom->terms[2].text.length) == 0);
    TEST_CHECK(atom->terms[3].type == YOG_TERM_INTEGER);
    TEST_CHECK(atom->terms[3].integer_value == 42);
    TEST_CHECK(atom->terms[4].type == YOG_TERM_WILDCARD);

    yog_program_free(program);
}

static void assert_syntax_error(const char *source)
{
    Lexer lexer;
    YogParseError error;
    YogProgram *program = NULL;

    lexer_init(&lexer, source, strlen(source));
    TEST_CHECK(yog_parse(&lexer, &program, &error) != YOG_PARSE_OK);
    TEST_CHECK(program == NULL);
    TEST_CHECK(error.message[0] != '\0');
    TEST_CHECK(error.line > 0);
    if (program != NULL) yog_program_free(program);
}

static void test_rejects_zero_arity_atom(void)
{
    assert_syntax_error("fact role()\n");
}

static void test_rejects_empty_rule_body(void)
{
    assert_syntax_error("rule r(X):\n");
}

static void test_rejects_identifier_comparison_operand(void)
{
    /* `foo == bar` is not a comparison; the left operand must be a variable
     * or a literal, as in the reference grammar. */
    assert_syntax_error("fact role(alice, admin)\n"
                        "rule r(X):\n"
                        "    foo == bar\n");
}

static void test_rejects_tabs_and_bad_indentation(void)
{
    assert_syntax_error("fact role(alice, admin)\n"
                        "rule r(X):\n"
                        "\trole(X, admin)\n");
}

static void test_error_position(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "rule r(X):\n"
        "    role(X, admin)\n"
        "    @bad\n";
    Lexer lexer;
    YogParseError error;
    YogProgram *program = NULL;

    lexer_init(&lexer, source, strlen(source));
    TEST_CHECK(yog_parse(&lexer, &program, &error) != YOG_PARSE_OK);
    TEST_CHECK(program == NULL);
    TEST_CHECK(error.line == 4);
    TEST_CHECK(error.column == 5);
}

int main(void)
{
    test_statement_shape();
    test_term_kinds();
    test_rejects_zero_arity_atom();
    test_rejects_empty_rule_body();
    test_rejects_identifier_comparison_operand();
    test_rejects_tabs_and_bad_indentation();
    test_error_position();
    return test_report("test_parser");
}
