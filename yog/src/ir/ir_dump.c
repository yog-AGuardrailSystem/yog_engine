/*
 * ir_dump.c -- stable, human-readable dump of a compiled policy.
 *
 * Used by `yogc ir` when a policy misbehaves, and by snapshot tests.  The
 * output is intentionally line oriented so it can be diffed.
 */
#include "ir/ir.h"

#include <string.h>

static const char *clause_kind_name(YogClauseKind kind)
{
    switch (kind) {
    case YOG_CLAUSE_FACT: return "fact";
    case YOG_CLAUSE_RULE: return "rule";
    case YOG_CLAUSE_ALLOW: return "allow";
    case YOG_CLAUSE_DENY: return "deny";
    default: return "?";
    }
}

static const char *goal_kind_name(YogIRGoalKind kind)
{
    switch (kind) {
    case YOG_IR_CALL: return "call";
    case YOG_IR_NOT: return "not";
    case YOG_IR_COMPARE: return "compare";
    default: return "?";
    }
}

static const char *comparison_name(YogComparisonOperator op)
{
    switch (op) {
    case YOG_COMPARE_EQ: return "EQ";
    case YOG_COMPARE_NE: return "NE";
    case YOG_COMPARE_LT: return "LT";
    case YOG_COMPARE_LE: return "LE";
    case YOG_COMPARE_GT: return "GT";
    case YOG_COMPARE_GE: return "GE";
    default: return "?";
    }
}

static void dump_term(const YogModule *module, const YogIRTerm *term, FILE *out)
{
    if (term->kind == YOG_IR_VAR) {
        fprintf(out, "$%zu", term->index);
        return;
    }
    if (term->index >= module->value_count) {
        fprintf(out, "<bad const %zu>", term->index);
        return;
    }
    if (module->values[term->index].kind == YOG_VALUE_INTEGER) {
        fprintf(out, "%lld", (long long)module->values[term->index].integer);
    } else {
        fprintf(out, "\"%.*s\"", (int)module->values[term->index].text.length,
                module->values[term->index].text.text);
    }
}

static void dump_index_list(const size_t *items, size_t count, FILE *out)
{
    size_t i;
    if (count == 0) {
        fputs("none", out);
        return;
    }
    for (i = 0; i < count; ++i) fprintf(out, i == 0 ? "%zu" : ",%zu", items[i]);
}

void yog_ir_dump(const YogModule *module, FILE *out)
{
    size_t i;

    if (module == NULL || out == NULL) return;

    fprintf(out, "values=%zu\n", module->value_count);
    for (i = 0; i < module->value_count; ++i) {
        const YogValue *value = &module->values[i];
        if (value->kind == YOG_VALUE_INTEGER)
            fprintf(out, "value[%zu]=int:%lld\n", i, (long long)value->integer);
        else
            fprintf(out, "value[%zu]=text:\"%.*s\"\n", i, (int)value->text.length, value->text.text);
    }

    fprintf(out, "predicates=%zu\n", module->predicate_count);
    for (i = 0; i < module->predicate_count; ++i) {
        const YogIRPredicate *predicate = &module->predicates[i];
        fprintf(out, "predicate[%zu]=%s %.*s/%zu facts=",
                i, yog_role_name(predicate->role),
                (int)predicate->name.length, predicate->name.text, predicate->arity);
        dump_index_list(predicate->facts, predicate->fact_count, out);
        fputs(" rules=", out);
        dump_index_list(predicate->rules, predicate->rule_count, out);
        fputs(" decisions=", out);
        dump_index_list(predicate->decisions, predicate->decision_count, out);
        fputc('\n', out);
    }

    fprintf(out, "clauses=%zu\n", module->clause_count);
    for (i = 0; i < module->clause_count; ++i) {
        const YogIRClause *clause = &module->clauses[i];
        size_t g;
        const YogIRPredicate *predicate = &module->predicates[clause->predicate];
        fprintf(out, "clause[%zu]=%s %.*s/%zu vars=%zu line=%d\n",
                i, clause_kind_name(clause->kind),
                (int)predicate->name.length, predicate->name.text, clause->head_count,
                clause->variable_count, clause->line);
        fputs("  head:", out);
        if (clause->head_count == 0) fputs(" (none)", out);
        for (g = 0; g < clause->head_count; ++g) {
            fputc(' ', out);
            dump_term(module, &clause->head[g], out);
        }
        fputc('\n', out);
        for (g = 0; g < clause->goal_count; ++g) {
            const YogIRGoal *goal = &clause->goals[g];
            size_t a;
            fprintf(out, "  goal[%zu]=%s", g, goal_kind_name(goal->kind));
            if (goal->kind == YOG_IR_COMPARE) {
                fprintf(out, " %s", comparison_name(goal->comparison));
            } else {
                const YogIRPredicate *target = &module->predicates[goal->predicate];
                fprintf(out, " %.*s/%zu", (int)target->name.length, target->name.text, target->arity);
            }
            for (a = 0; a < goal->arg_count; ++a) {
                fputc(' ', out);
                dump_term(module, &goal->args[a], out);
            }
            fputc('\n', out);
        }
    }

    fprintf(out, "queries=%zu\n", module->query_count);
    for (i = 0; i < module->query_count; ++i) {
        const YogIRQuery *query = &module->queries[i];
        size_t a;
        fprintf(out, "query[%zu]=%.*s/%zu predicate=", i, (int)query->name.length,
                query->name.text, query->arity);
        if (query->predicate == SIZE_MAX) fputs("undefined", out);
        else fprintf(out, "%zu", query->predicate);
        fprintf(out, " vars=%zu line=%d\n", query->variable_count, query->line);
        for (a = 0; a < query->arg_count; ++a) {
            fputs("  arg[", out);
            fprintf(out, "%zu]=", a);
            dump_term(module, &query->args[a], out);
            fputc('\n', out);
        }
    }
}
