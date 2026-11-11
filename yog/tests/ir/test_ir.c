/*
 * test_ir.c -- clause-table construction and dump tests.
 */
#include "../test_util.h"

#include <stdlib.h>

#include "ir/ir.h"
#include "sema/sema.h"

static YogModule *build(const char *source)
{
    YogProgram *program = test_parse(source);
    YogSymbolTable symbols;
    YogSemaError sema_error;
    YogIRError ir_error;
    YogModule *module = NULL;

    if (program == NULL) return NULL;
    yog_symbol_table_init(&symbols);
    if (!yog_sema_check(program, &symbols, &sema_error)) {
        (void)fprintf(stderr, "    sema error %d:%d: %s\n", sema_error.line,
                      sema_error.column, sema_error.message);
        yog_program_free(program);
        return NULL;
    }
    if (!yog_ir_build(program, &symbols, source, &module, &ir_error)) {
        (void)fprintf(stderr, "    ir error %d:%d: %s\n", ir_error.line,
                      ir_error.column, ir_error.message);
    }
    yog_symbol_table_free(&symbols);
    yog_program_free(program);
    return module;
}

static void test_shape(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact role(bob, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n"
        "query can_delete(alice, db1)\n"
        "query can_delete(X, db1)\n";
    YogModule *module = build(source);

    TEST_CHECK(module != NULL);
    if (module == NULL) return;

    TEST_CHECK(module->predicate_count == 2);
    TEST_CHECK(module->clause_count == 3);
    TEST_CHECK(module->query_count == 2);
    TEST_CHECK(module->value_count == 4); /* alice, admin, db1, and the second query's X is a variable */

    TEST_CHECK(module->clauses[0].kind == YOG_CLAUSE_FACT);
    TEST_CHECK(module->clauses[1].kind == YOG_CLAUSE_FACT);
    TEST_CHECK(module->clauses[2].kind == YOG_CLAUSE_ALLOW);
    TEST_CHECK(module->clauses[2].goal_count == 1);
    TEST_CHECK(module->clauses[2].goals[0].kind == YOG_IR_CALL);

    TEST_CHECK(module->queries[0].predicate != SIZE_MAX);
    TEST_CHECK(module->queries[0].variable_count == 0);
    TEST_CHECK(module->queries[1].variable_count == 1);
    TEST_CHECK(module->queries[1].variables[0].length == 1);
    TEST_CHECK(memcmp(module->queries[1].variables[0].text, "X", 1) == 0);

    yog_ir_free(module);
}

static void test_wildcards_get_fresh_slots(void)
{
    static const char source[] =
        "fact domain(internal_addr, internal)\n"
        "fact sensitivity(internal_addr, low)\n"
        "allow can_read(User, Address):\n"
        "    domain(Address, _)\n"
        "    sensitivity(Address, _)\n";
    YogModule *module = build(source);

    TEST_CHECK(module != NULL);
    if (module == NULL) return;

    /* head: User=0, Address=1; then one fresh slot per wildcard. */
    TEST_CHECK(module->clauses[2].variable_count == 4);
    TEST_CHECK(module->clauses[2].goals[0].args[1].kind == YOG_IR_VAR);
    TEST_CHECK(module->clauses[2].goals[1].args[1].kind == YOG_IR_VAR);
    TEST_CHECK(module->clauses[2].goals[0].args[1].index !=
               module->clauses[2].goals[1].args[1].index);

    yog_ir_free(module);
}

static void test_constants_are_interned(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "fact role(bob, admin)\n"
        "allow can_read(User, File):\n"
        "    role(User, admin)\n";
    YogModule *module = build(source);

    TEST_CHECK(module != NULL);
    if (module == NULL) return;

    TEST_CHECK(module->value_count == 3); /* alice, admin, bob */
    yog_ir_free(module);
}

static void test_dump_is_line_oriented(void)
{
    static const char source[] =
        "fact role(alice, admin)\n"
        "allow can_delete(User, DB):\n"
        "    role(User, admin)\n"
        "query can_delete(alice, db1)\n";
    YogModule *module = build(source);
    FILE *out;
    char buffer[4096];
    size_t read;

    TEST_CHECK(module != NULL);
    if (module == NULL) return;

    out = tmpfile();
    TEST_CHECK(out != NULL);
    if (out == NULL) {
        yog_ir_free(module);
        return;
    }
    yog_ir_dump(module, out);
    rewind(out);
    read = fread(buffer, 1, sizeof(buffer) - 1, out);
    buffer[read] = '\0';
    fclose(out);

    TEST_CHECK(strstr(buffer, "predicates=2") != NULL);
    TEST_CHECK(strstr(buffer, "clauses=2") != NULL);
    TEST_CHECK(strstr(buffer, "clause[1]=allow can_delete/2") != NULL);
    TEST_CHECK(strstr(buffer, "goal[0]=call role/2") != NULL);
    TEST_CHECK(strstr(buffer, "queries=1") != NULL);

    yog_ir_free(module);
}

static void test_rejects_when_semantics_are_bad(void)
{
    static const char source[] =
        "fact role(Who, admin)\n";
    YogProgram *program = test_parse(source);
    YogSymbolTable symbols;
    YogSemaError sema_error;

    TEST_CHECK(program != NULL);
    if (program == NULL) return;
    yog_symbol_table_init(&symbols);
    TEST_CHECK(!yog_sema_check(program, &symbols, &sema_error));
    yog_program_free(program);
}

int main(void)
{
    test_shape();
    test_wildcards_get_fresh_slots();
    test_constants_are_interned();
    test_dump_is_line_oriented();
    test_rejects_when_semantics_are_bad();
    return test_report("test_ir");
}
