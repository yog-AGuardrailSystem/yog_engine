/*
 * ir_build.c -- lowers a validated AST into the clause-table IR.
 *
 * The builder assumes yog_sema_check() has already accepted the program, but
 * it still defensive-checks every allocation and every limit so a malformed
 * policy can never produce a half-built module.
 */
#include "ir/ir.h"

#include "builtin/builtin.h"

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
        if (value.kind == YOG_VALUE_INTEGER || value.kind == YOG_VALUE_BOOLEAN) {
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

static bool intern_boolean(BuildCtx *ctx, bool flag, size_t *out)
{
    YogValue value;
    value.kind = YOG_VALUE_BOOLEAN;
    value.text.text = NULL;
    value.text.length = 0;
    value.integer = flag ? 1 : 0;
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
    case YOG_TERM_BOOLEAN:
        out->kind = YOG_IR_CONST;
        return intern_boolean(ctx, term->integer_value != 0, &out->index);
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

    if (goal->type == YOG_GOAL_OBLIGATION) {
        out->kind = YOG_IR_OBLIGATION;
        out->name = goal->as.atom.predicate;
        out->predicate = SIZE_MAX;
        out->arg_count = goal->as.atom.term_count;
        return build_term_array(ctx, goal->as.atom.terms, goal->as.atom.term_count, slots, &out->args);
    }

    out->kind = goal->type == YOG_GOAL_NEGATION ? YOG_IR_NOT : YOG_IR_CALL;
    out->builtin = (int)yog_builtin_find(goal->as.atom.predicate.text, goal->as.atom.predicate.length,
                                         goal->as.atom.term_count);
    if (out->builtin != 0) {
        out->predicate = SIZE_MAX;
        out->arg_count = goal->as.atom.term_count;
        return build_term_array(ctx, goal->as.atom.terms, goal->as.atom.term_count, slots, &out->args);
    }
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

/* ------------------------------------------------------------ first-argument fact index */

#define YOG_FACT_INDEX_MIN_FACTS 16u

struct YogFactIndex {
    size_t *positions;     /* fact positions grouped by bucket, ascending within a bucket */
    size_t *starts;        /* bucket_count + 1 offsets into positions */
    size_t  bucket_count;  /* a power of two */
};

uint64_t yog_value_hash(const YogValue *value)
{
    uint64_t h = 14695981039346656037ull;
    size_t i;
    h = (h ^ (uint64_t)value->kind) * 1099511628211ull;
    if (value->kind == YOG_VALUE_TEXT) {
        for (i = 0; i < value->text.length; ++i)
            h = (h ^ (uint64_t)(unsigned char)value->text.text[i]) * 1099511628211ull;
    } else {
        uint64_t bits = (uint64_t)value->integer;
        for (i = 0; i < 8; ++i) {
            h = (h ^ (bits & 0xFFu)) * 1099511628211ull;
            bits >>= 8;
        }
    }
    return h ^ (h >> 29);
}

const size_t *yog_fact_index_candidates(const YogIRPredicate *predicate, uint64_t hash, size_t *count)
{
    const YogFactIndex *index = predicate->fact_index;
    size_t bucket = (size_t)(hash & (uint64_t)(index->bucket_count - 1u));
    *count = index->starts[bucket + 1u] - index->starts[bucket];
    return index->positions + index->starts[bucket];
}

/* Builds the index for one predicate; on any failure leaves fact_index NULL and the engine scans instead. */
static void build_fact_index(const YogModule *module, YogIRPredicate *predicate)
{
    YogFactIndex *index;
    uint64_t *hashes;
    size_t bucket_count = 16u, i;
    if (predicate->arity == 0 || predicate->fact_count < YOG_FACT_INDEX_MIN_FACTS) return;
    while (bucket_count < predicate->fact_count) bucket_count <<= 1;
    index = calloc(1, sizeof(*index));
    hashes = malloc(predicate->fact_count * sizeof(*hashes));
    if (index == NULL || hashes == NULL) goto fail;
    index->bucket_count = bucket_count;
    index->starts = calloc(bucket_count + 1u, sizeof(*index->starts));
    index->positions = malloc(predicate->fact_count * sizeof(*index->positions));
    if (index->starts == NULL || index->positions == NULL) goto fail;
    for (i = 0; i < predicate->fact_count; ++i) {
        const YogIRClause *clause = &module->clauses[predicate->facts[i]];
        if (clause->head_count == 0 || clause->head[0].kind != YOG_IR_CONST ||
            clause->head[0].index >= module->value_count)
            goto fail;                      /* not the ground fact we expect: do not index */
        hashes[i] = yog_value_hash(&module->values[clause->head[0].index]);
        index->starts[(size_t)(hashes[i] & (uint64_t)(bucket_count - 1u)) + 1u]++;
    }
    for (i = 0; i < bucket_count; ++i) index->starts[i + 1u] += index->starts[i];
    {
        size_t *fill = malloc(bucket_count * sizeof(*fill));
        if (fill == NULL) goto fail;
        memcpy(fill, index->starts, bucket_count * sizeof(*fill));
        for (i = 0; i < predicate->fact_count; ++i)
            index->positions[fill[(size_t)(hashes[i] & (uint64_t)(bucket_count - 1u))]++] = i;
        free(fill);
    }
    free(hashes);
    predicate->fact_index = index;
    return;
fail:
    if (index != NULL) {
        free(index->positions);
        free(index->starts);
        free(index);
    }
    free(hashes);
}

static void free_module_contents(YogModule *module)
{
    size_t i;
    if (module == NULL) return;
    for (i = 0; i < module->predicate_count; ++i) {
        free(module->predicates[i].facts);
        if (module->predicates[i].fact_index != NULL) {
            free(module->predicates[i].fact_index->positions);
            free(module->predicates[i].fact_index->starts);
            free(module->predicates[i].fact_index);
        }
        free(module->predicates[i].rules);
        free(module->predicates[i].decisions);
        free(module->predicates[i].arg_types);
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
    case YOG_STATEMENT_REQUIRE_APPROVAL:
        clause->kind = YOG_CLAUSE_APPROVAL;
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
    module->language_version = 1;
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
        if (statement->type == YOG_STATEMENT_VERSION) {
            module->language_version = (int)statement->as.fact.terms[0].integer_value;
            continue;
        }
        if (statement->type == YOG_STATEMENT_INPUT) {
            const YogAtom *atom = &statement->as.fact;
            size_t id = predicate_id(symbols, atom->predicate, atom->term_count);
            size_t t;
            if (id == SIZE_MAX || module->predicates[id].arg_types != NULL) continue;
            module->predicates[id].arg_types = calloc(atom->term_count, 1);
            if (module->predicates[id].arg_types == NULL) {
                (void)set_error(&ctx, statement->line, statement->column, "out of memory recording input types");
                yog_ir_free(module);
                return false;
            }
            for (t = 0; t < atom->term_count; ++t) {
                const YogText type = atom->terms[t].text;
                unsigned char code = YOG_TYPE_ANY;
                if (type.length == 4 && memcmp(type.text, "text", 4) == 0) code = YOG_TYPE_TEXT;
                else if (type.length == 3 && memcmp(type.text, "int", 3) == 0) code = YOG_TYPE_INT;
                else if (type.length == 4 && memcmp(type.text, "bool", 4) == 0) code = YOG_TYPE_BOOL;
                module->predicates[id].arg_types[t] = code;
            }
            continue;
        }
        if (statement->type == YOG_STATEMENT_QUERY) ok = build_query(&ctx, statement);
        else ok = build_statement(&ctx, statement);
        if (!ok) {
            yog_ir_free(module);
            return false;
        }
    }

    for (i = 0; i < module->predicate_count; ++i) build_fact_index(module, &module->predicates[i]);

    *out_module = module;
    return true;
}
