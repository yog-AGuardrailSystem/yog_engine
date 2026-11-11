/*
 * ir_build.c -- lowers a validated AST into the clause-table IR.
 *
 * The builder assumes yog_sema_check() has already accepted the program, but
 * it still defensive-checks every allocation and every limit so a malformed
 * policy can never produce a half-built module.
 */
#include "ir/ir.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------- utilities */

typedef struct {
    YogModule            *module;
    const YogSymbolTable *symbols;
    YogIRError           *error;
} BuildCtx;

static bool set_error(BuildCtx *ctx, int line, int column, const char *fmt, ...)
{
    va_list args;
    if (ctx->error != NULL) {
        ctx->error->line = line;
        ctx->error->column = column;
        va_start(args, fmt);
        (void)vsnprintf(ctx->error->message, sizeof(ctx->error->message), fmt, args);
        va_end(args);
    }
    return false;
}

static bool text_equal(YogText a, YogText b)
{
    return a.length == b.length && (a.length == 0 || memcmp(a.text, b.text, a.length) == 0);
}

/* Clause-local variable slots, in first-use order. */
typedef struct {
    YogText *names;
    size_t   count;
    size_t   capacity;
} VarSlots;

static void var_slots_free(VarSlots *slots)
{
    if (slots == NULL) return;
    free(slots->names);
    memset(slots, 0, sizeof(*slots));
}

static bool var_slots_find(const VarSlots *slots, YogText name, size_t *out)
{
    size_t i;
    for (i = 0; i < slots->count; ++i) {
        if (text_equal(slots->names[i], name)) {
            if (out != NULL) *out = i;
            return true;
        }
    }
    return false;
}

static bool var_slots_add(VarSlots *slots, YogText name, size_t *out)
{
    YogText *grown;
    size_t next;
    if (slots->count == slots->capacity) {
        next = slots->capacity == 0 ? 8 : slots->capacity * 2;
        if (next < slots->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(slots->names, next * sizeof(*grown));
        if (grown == NULL) return false;
        slots->names = grown;
        slots->capacity = next;
    }
    slots->names[slots->count] = name;
    if (out != NULL) *out = slots->count;
    slots->count++;
    return true;
}

/* Constant pool: identifiers and strings share a namespace (they unify in the
 * reference implementation); integers are a separate namespace. */
static bool intern_value(BuildCtx *ctx, YogValue value, size_t *out)
{
    YogModule *module = ctx->module;
    size_t i;
    for (i = 0; i < module->value_count; ++i) {
        const YogValue *candidate = &module->values[i];
        if (candidate->kind != value.kind) continue;
        if (value.kind == YOG_VALUE_INTEGER) {
            if (candidate->integer == value.integer) { *out = i; return true; }
        } else if (text_equal(candidate->text, value.text)) {
            *out = i;
            return true;
        }
    }
    if (module->value_count >= YOG_IR_MAX_VALUES)
        return set_error(ctx, 0, 0, "policy exceeds the constant limit (%u)", YOG_IR_MAX_VALUES);
    if (module->value_count == module->value_capacity) {
        size_t next = module->value_capacity == 0 ? 16 : module->value_capacity * 2;
        YogValue *grown;
        if (next > YOG_IR_MAX_VALUES) next = YOG_IR_MAX_VALUES;
        if (next <= module->value_capacity) return false;
        grown = realloc(module->values, next * sizeof(*grown));
        if (grown == NULL) return set_error(ctx, 0, 0, "out of memory growing the constant pool");
        module->values = grown;
        module->value_capacity = next;
    }
    module->values[module->value_count] = value;
    *out = module->value_count;
    module->value_count++;
    return true;
}

static bool intern_text(BuildCtx *ctx, YogText text, size_t *out)
{
    YogValue value;
    value.kind = YOG_VALUE_TEXT;
    value.text = text;
    value.integer = 0;
    return intern_value(ctx, value, out);
}

static bool intern_integer(BuildCtx *ctx, int64_t number, size_t *out)
{
    YogValue value;
    value.kind = YOG_VALUE_INTEGER;
    value.text.text = NULL;
    value.text.length = 0;
    value.integer = number;
    return intern_value(ctx, value, out);
}

/* Build one IR term.  Wildcards always allocate a fresh slot, which is how the
 * reference implements `_` (a variable unique to that occurrence). */
static bool build_term(BuildCtx *ctx, const YogTerm *term, VarSlots *slots, YogIRTerm *out)
{
    size_t slot;
    switch (term->type) {
    case YOG_TERM_VARIABLE:
        if (!var_slots_find(slots, term->text, &slot) && !var_slots_add(slots, term->text, &slot))
            return set_error(ctx, term->line, term->column, "out of memory allocating a variable");
        out->kind = YOG_IR_VAR;
        out->index = slot;
        return true;
    case YOG_TERM_WILDCARD:
        if (!var_slots_add(slots, term->text, &slot))
            return set_error(ctx, term->line, term->column, "out of memory allocating a wildcard");
        out->kind = YOG_IR_VAR;
        out->index = slot;
        return true;
    case YOG_TERM_IDENTIFIER:
    case YOG_TERM_STRING:
        out->kind = YOG_IR_CONST;
        return intern_text(ctx, term->text, &out->index);
    case YOG_TERM_INTEGER:
        out->kind = YOG_IR_CONST;
        return intern_integer(ctx, term->integer_value, &out->index);
    default:
        return set_error(ctx, term->line, term->column, "unsupported term");
    }
}

static bool build_term_array(BuildCtx *ctx, const YogTerm *terms, size_t count,
                             VarSlots *slots, YogIRTerm **out_terms)
{
    YogIRTerm *built;
    size_t i;
    if (count > YOG_IR_MAX_ARGS)
        return set_error(ctx, 0, 0, "atom exceeds the argument limit (%u)", YOG_IR_MAX_ARGS);
    built = count == 0 ? NULL : malloc(count * sizeof(*built));
    if (count > 0 && built == NULL)
        return set_error(ctx, 0, 0, "out of memory allocating atom arguments");
    for (i = 0; i < count; ++i) {
        if (!build_term(ctx, &terms[i], slots, &built[i])) {
            free(built);
            return false;
        }
    }
    *out_terms = built;
    return true;
}

/* -------------------------------------------------------------- predicates */

static size_t predicate_id(const YogSymbolTable *symbols, YogText name, size_t arity)
{
    size_t index;
    return yog_symbol_table_find(symbols, name, arity, &index) ? index : SIZE_MAX;
}

static bool push_clause_ref(BuildCtx *ctx, size_t **items, size_t *count, size_t *capacity,
                            size_t clause)
{
    size_t next;
    size_t *grown;
    if (*count == *capacity) {
        next = *capacity == 0 ? 8 : *capacity * 2;
        if (next < *capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(*items, next * sizeof(*grown));
        if (grown == NULL) return set_error(ctx, 0, 0, "out of memory growing a predicate");
        *items = grown;
        *capacity = next;
    }
    (*items)[(*count)++] = clause;
    return true;
}

/* ------------------------------------------------------------------ goals */

static bool build_goal(BuildCtx *ctx, const YogGoal *goal, VarSlots *slots, YogIRGoal *out)
{
    memset(out, 0, sizeof(*out));
    out->line = goal->line;
    out->column = goal->column;

    if (goal->type == YOG_GOAL_COMPARISON) {
        out->kind = YOG_IR_COMPARE;
        out->comparison = goal->as.comparison.operator_type;
        out->arg_count = 2;
        out->args = malloc(2 * sizeof(*out->args));
        if (out->args == NULL)
            return set_error(ctx, goal->line, goal->column, "out of memory allocating a comparison");
        if (!build_term(ctx, &goal->as.comparison.left, slots, &out->args[0]) ||
            !build_term(ctx, &goal->as.comparison.right, slots, &out->args[1])) {
            free(out->args);
            out->args = NULL;
            out->arg_count = 0;
            return false;
        }
        return true;
    }

    out->kind = goal->type == YOG_GOAL_NEGATION ? YOG_IR_NOT : YOG_IR_CALL;
    out->predicate = predicate_id(ctx->symbols, goal->as.atom.predicate, goal->as.atom.term_count);
    if (out->predicate == SIZE_MAX)
        return set_error(ctx, goal->line, goal->column,
                         "%.*s/%zu is not defined by any fact or rule",
                         (int)goal->as.atom.predicate.length, goal->as.atom.predicate.text,
                         goal->as.atom.term_count);
    out->arg_count = goal->as.atom.term_count;
    if (!build_term_array(ctx, goal->as.atom.terms, goal->as.atom.term_count, slots, &out->args))
        return false;
    return true;
}

/* ------------------------------------------------------------------ module */

static void free_module_contents(YogModule *module)
{
    size_t i;
    if (module == NULL) return;
    for (i = 0; i < module->predicate_count; ++i) {
        free(module->predicates[i].facts);
        free(module->predicates[i].rules);
        free(module->predicates[i].decisions);
    }
    for (i = 0; i < module->clause_count; ++i) {
        size_t g;
        free(module->clauses[i].head);
        for (g = 0; g < module->clauses[i].goal_count; ++g) free(module->clauses[i].goals[g].args);
        free(module->clauses[i].goals);
    }
    for (i = 0; i < module->query_count; ++i) {
        free(module->queries[i].args);
        free(module->queries[i].variables);
    }
    free(module->values);
    free(module->predicates);
    free(module->clauses);
    free(module->queries);
    memset(module, 0, sizeof(*module));
}

void yog_ir_free(YogModule *module)
{
    if (module == NULL) return;
    free_module_contents(module);
    free(module);
}

static bool ensure_clause_capacity(BuildCtx *ctx)
{
    YogModule *module = ctx->module;
    if (module->clause_count >= YOG_IR_MAX_CLAUSES)
        return set_error(ctx, 0, 0, "policy exceeds the clause limit (%u)", YOG_IR_MAX_CLAUSES);
    if (module->clause_count == module->clause_capacity) {
        size_t next = module->clause_capacity == 0 ? 16 : module->clause_capacity * 2;
        YogIRClause *grown;
        if (next > YOG_IR_MAX_CLAUSES) next = YOG_IR_MAX_CLAUSES;
        if (next <= module->clause_capacity) return false;
        grown = realloc(module->clauses, next * sizeof(*grown));
        if (grown == NULL) return set_error(ctx, 0, 0, "out of memory growing the clause table");
        module->clauses = grown;
        module->clause_capacity = next;
    }
    return true;
}

static bool build_statement(BuildCtx *ctx, const YogStatement *statement)
{
    YogModule *module = ctx->module;
    YogIRClause *clause;
    const YogAtom *head;
    const YogBody *body;
    VarSlots slots;
    size_t clause_index;
    size_t i;
    YogIRPredicate *predicate;

    if (!ensure_clause_capacity(ctx)) return false;

    clause_index = module->clause_count;
    clause = &module->clauses[module->clause_count];
    memset(clause, 0, sizeof(*clause));
    memset(&slots, 0, sizeof(slots));

    switch (statement->type) {
    case YOG_STATEMENT_FACT:
        clause->kind = YOG_CLAUSE_FACT;
        head = &statement->as.fact;
        body = NULL;
        break;
    case YOG_STATEMENT_RULE:
        clause->kind = YOG_CLAUSE_RULE;
        head = &statement->as.clause.head;
        body = &statement->as.clause.body;
        break;
    case YOG_STATEMENT_ALLOW:
        clause->kind = YOG_CLAUSE_ALLOW;
        head = &statement->as.clause.head;
        body = &statement->as.clause.body;
        break;
    case YOG_STATEMENT_DENY:
        clause->kind = YOG_CLAUSE_DENY;
        head = &statement->as.clause.head;
        body = &statement->as.clause.body;
        break;
    default:
        return set_error(ctx, statement->line, statement->column, "unsupported statement");
    }

    clause->predicate = predicate_id(ctx->symbols, head->predicate, head->term_count);
    if (clause->predicate == SIZE_MAX)
        return set_error(ctx, statement->line, statement->column,
                         "predicate %.*s/%zu is missing from the symbol table",
                         (int)head->predicate.length, head->predicate.text, head->term_count);
    clause->line = statement->line;
    clause->column = statement->column;
    clause->variable_base = module->variable_count;

    if (!build_term_array(ctx, head->terms, head->term_count, &slots, &clause->head))
        goto fail;
    clause->head_count = head->term_count;

    if (body != NULL) {
        if (body->goal_count > YOG_IR_MAX_GOALS) {
            (void)set_error(ctx, statement->line, statement->column,
                            "clause exceeds the goal limit (%u)", YOG_IR_MAX_GOALS);
            goto fail;
        }
        clause->goals = body->goal_count == 0 ? NULL : calloc(body->goal_count, sizeof(*clause->goals));
        if (body->goal_count > 0 && clause->goals == NULL) {
            (void)set_error(ctx, statement->line, statement->column, "out of memory allocating clause goals");
            goto fail;
        }
        clause->goal_count = body->goal_count;
        for (i = 0; i < body->goal_count; ++i) {
            if (!build_goal(ctx, &body->goals[i], &slots, &clause->goals[i])) goto fail;
        }
    }

    clause->variable_count = slots.count;
    module->variable_count += slots.count;

    predicate = &module->predicates[clause->predicate];
    if (clause->kind == YOG_CLAUSE_FACT) {
        if (!push_clause_ref(ctx, &predicate->facts, &predicate->fact_count,
                             &predicate->fact_capacity, clause_index))
            goto fail;
    } else if (clause->kind == YOG_CLAUSE_RULE) {
        if (!push_clause_ref(ctx, &predicate->rules, &predicate->rule_count,
                             &predicate->rule_capacity, clause_index))
            goto fail;
    } else {
        if (!push_clause_ref(ctx, &predicate->decisions, &predicate->decision_count,
                             &predicate->decision_capacity, clause_index))
            goto fail;
    }

    var_slots_free(&slots);
    module->clause_count++;
    return true;

fail:
    free(clause->head);
    if (clause->goals != NULL) {
        for (i = 0; i < clause->goal_count; ++i) free(clause->goals[i].args);
        free(clause->goals);
    }
    memset(clause, 0, sizeof(*clause));
    var_slots_free(&slots);
    return false;
}

static bool build_query(BuildCtx *ctx, const YogStatement *statement)
{
    YogModule *module = ctx->module;
    YogIRQuery *query;
    VarSlots slots;
    const YogAtom *atom = &statement->as.query;
    size_t i;

    if (module->query_count >= YOG_IR_MAX_QUERIES)
        return set_error(ctx, statement->line, statement->column,
                         "policy exceeds the query limit (%u)", YOG_IR_MAX_QUERIES);
    if (module->query_count == module->query_capacity) {
        size_t next = module->query_capacity == 0 ? 8 : module->query_capacity * 2;
        YogIRQuery *grown;
        if (next > YOG_IR_MAX_QUERIES) next = YOG_IR_MAX_QUERIES;
        if (next <= module->query_capacity) return false;
        grown = realloc(module->queries, next * sizeof(*grown));
        if (grown == NULL) return set_error(ctx, 0, 0, "out of memory growing the query table");
        module->queries = grown;
        module->query_capacity = next;
    }

    query = &module->queries[module->query_count];
    memset(query, 0, sizeof(*query));
    memset(&slots, 0, sizeof(slots));
    query->name = atom->predicate;
    query->arity = atom->term_count;
    query->predicate = predicate_id(ctx->symbols, atom->predicate, atom->term_count);
    query->line = atom->line;
    query->column = atom->column;

    if (!build_term_array(ctx, atom->terms, atom->term_count, &slots, &query->args))
        return false;
    query->arg_count = atom->term_count;
    query->variable_count = slots.count;
    if (slots.count > 0) {
        query->variables = malloc(slots.count * sizeof(*query->variables));
        if (query->variables == NULL) {
            free(query->args);
            query->args = NULL;
            var_slots_free(&slots);
            return set_error(ctx, atom->line, atom->column, "out of memory allocating query variables");
        }
        for (i = 0; i < slots.count; ++i) query->variables[i] = slots.names[i];
    }
    var_slots_free(&slots);
    module->variable_count += query->variable_count;
    module->query_count++;
    return true;
}

bool yog_ir_build(const YogProgram *program, const YogSymbolTable *symbols,
                  const char *source, YogModule **out_module, YogIRError *error)
{
    BuildCtx ctx;
    YogModule *module;
    size_t i;

    if (out_module != NULL) *out_module = NULL;
    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (program == NULL || symbols == NULL || out_module == NULL)
        return false;

    module = calloc(1, sizeof(*module));
    if (module == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory allocating the module");
        return false;
    }
    module->source = source;
    ctx.module = module;
    ctx.symbols = symbols;
    ctx.error = error;

    if (symbols->count > YOG_IR_MAX_PREDICATES) {
        (void)set_error(&ctx, 0, 0, "policy exceeds the predicate limit (%u)", YOG_IR_MAX_PREDICATES);
        yog_ir_free(module);
        return false;
    }

    module->predicates = symbols->count == 0 ? NULL : calloc(symbols->count, sizeof(*module->predicates));
    if (symbols->count > 0 && module->predicates == NULL) {
        (void)set_error(&ctx, 0, 0, "out of memory allocating the predicate table");
        yog_ir_free(module);
        return false;
    }
    for (i = 0; i < symbols->count; ++i) {
        module->predicates[i].name = symbols->items[i].name;
        module->predicates[i].arity = symbols->items[i].arity;
        module->predicates[i].role = symbols->items[i].role;
    }
    module->predicate_count = symbols->count;

    for (i = 0; i < program->statement_count; ++i) {
        const YogStatement *statement = &program->statements[i];
        bool ok;
        if (statement->type == YOG_STATEMENT_QUERY) ok = build_query(&ctx, statement);
        else ok = build_statement(&ctx, statement);
        if (!ok) {
            yog_ir_free(module);
            return false;
        }
    }

    *out_module = module;
    return true;
}
