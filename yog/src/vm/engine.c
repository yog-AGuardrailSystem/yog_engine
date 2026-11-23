/*
 * engine.c -- backward-chaining solver and the allow/deny contract.
 *
 * Search model
 *   - depth-first over clauses, facts first, then rules, then decisions;
 *   - each clause activation gets a fresh frame of cells in the store;
 *   - the trail is reset when an activation is abandoned.
 *
 * Because the semantic analyser rejects recursion (C5), a clause can never be
 * re-entered while its own frame is live, so frames do not need to be copied.
 *
 * Logical evaluation (solve_atom / solve_goals) knows nothing about allow and
 * deny; yog_engine_check() is the only place that applies the policy-combining
 * algorithm (deny > allow > default deny).
 */
#include "vm/vm.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "builtin/builtin.h"

typedef bool (*YogYield)(void *user, YogEngine *engine);

typedef struct {
    size_t                  predicate;
    const YogIRClause      *clause;   /* owned by the context module */
} ContextMatch;

struct YogEngine {
    const YogModule     *module;
    YogStore             store;
    YogValueSpace        space;

    size_t               max_steps;
    int                  max_depth;
    size_t               max_solutions;
    size_t               max_millis;
    size_t               max_memory;
    size_t               steps;
    size_t               solutions;
    struct timespec      started;
    bool                 clock_ok;

    bool                 failed;
    YogEvalError         error;

    bool                 trace_enabled;
    char                *trace;
    size_t               trace_length;
    size_t               trace_capacity;

    ContextMatch        *matches;
    size_t               match_count;
    size_t               match_capacity;
};

/* ------------------------------------------------------------------ errors */

static bool fail(YogEngine *engine, int line, int column, const char *fmt, ...)
{
    va_list args;
    if (engine->failed) return false;
    engine->failed = true;
    engine->error.line = line;
    engine->error.column = column;
    va_start(args, fmt);
    (void)vsnprintf(engine->error.message, sizeof(engine->error.message), fmt, args);
    va_end(args);
    return false;
}

static void tracef(YogEngine *engine, const char *fmt, ...)
{
    va_list args;
    int written;
    size_t available;

    if (!engine->trace_enabled) return;
    available = engine->trace_capacity - engine->trace_length;
    if (available < 64) {
        size_t next = engine->trace_capacity == 0 ? 512 : engine->trace_capacity * 2;
        char *grown;
        if (next > 1u << 20) return;
        grown = realloc(engine->trace, next);
        if (grown == NULL) return;
        engine->trace = grown;
        engine->trace_capacity = next;
        available = engine->trace_capacity - engine->trace_length;
    }
    va_start(args, fmt);
    written = vsnprintf(engine->trace + engine->trace_length, available, fmt, args);
    va_end(args);
    if (written < 0) return;
    engine->trace_length += (size_t)written;
    if (engine->trace_length >= engine->trace_capacity) engine->trace_length = engine->trace_capacity - 1;
}

/* --------------------------------------------------------------- budgets */

/* Steps between wall-clock reads; reading the clock on every step would cost
 * more than the work it guards. */
#define YOG_CLOCK_INTERVAL 1024u

static size_t elapsed_millis(const YogEngine *engine)
{
    struct timespec now;
    long long ms;
    if (!engine->clock_ok || timespec_get(&now, TIME_UTC) != TIME_UTC) return 0;
    ms = (long long)(now.tv_sec - engine->started.tv_sec) * 1000LL +
         (long long)(now.tv_nsec - engine->started.tv_nsec) / 1000000LL;
    return ms < 0 ? 0 : (size_t)ms;
}

/* Bytes currently held by the evaluator for one request. */
static size_t engine_memory(const YogEngine *engine)
{
    return engine->store.cell_capacity * sizeof(YogIRTerm) +
           engine->store.trail_capacity * sizeof(size_t) +
           engine->match_capacity * sizeof(ContextMatch) +
           engine->trace_capacity;
}

/* Called once per clause attempt.  Every limit fails closed: the caller sees an
 * evaluation error, never a partial answer. */
static bool within_budget(YogEngine *engine, int line, int column)
{
    engine->steps++;
    if (engine->steps > engine->max_steps)
        return fail(engine, line, column, "evaluation step limit exceeded");
    if (engine_memory(engine) > engine->max_memory)
        return fail(engine, line, column, "evaluation memory limit exceeded (%zu bytes)",
                    engine->max_memory);
    if (engine->steps % YOG_CLOCK_INTERVAL == 0 && elapsed_millis(engine) > engine->max_millis)
        return fail(engine, line, column, "evaluation time limit exceeded (%zu ms)",
                    engine->max_millis);
    return true;
}

/* ------------------------------------------------------------------ values */

static void format_value(const YogEngine *engine, YogIRTerm term, char *buffer, size_t size)
{
    YogIRTerm resolved = yog_store_resolve(&engine->store, term);
    if (resolved.kind == YOG_IR_VAR) {
        (void)snprintf(buffer, size, "_");
        return;
    }
    {
        const YogValue *value = yog_value_at(&engine->space, resolved.index);
        if (value == NULL) {
            (void)snprintf(buffer, size, "<bad>");
        } else if (value->kind == YOG_VALUE_INTEGER) {
            (void)snprintf(buffer, size, "%lld", (long long)value->integer);
        } else if (value->kind == YOG_VALUE_BOOLEAN) {
            (void)snprintf(buffer, size, "%s", value->integer != 0 ? "true" : "false");
        } else {
            (void)snprintf(buffer, size, "%.*s", (int)value->text.length, value->text.text);
        }
    }
}

static void format_goal(const YogEngine *engine, const YogIRPredicate *predicate,
                        const YogIRTerm *args, size_t arg_count, size_t base,
                        char *buffer, size_t size)
{
    size_t used = 0;
    size_t i;
    int written;

    written = snprintf(buffer, size, "%.*s(", (int)predicate->name.length, predicate->name.text);
    if (written < 0) return;
    used = (size_t)written < size ? (size_t)written : size - 1;
    for (i = 0; i < arg_count && used + 1 < size; ++i) {
        char term_text[160];
        YogIRTerm absolute = args[i];
        if (absolute.kind == YOG_IR_VAR) absolute.index += base;
        format_value(engine, absolute, term_text, sizeof(term_text));
        written = snprintf(buffer + used, size - used, "%s%s", i == 0 ? "" : ", ", term_text);
        if (written < 0) return;
        used += (size_t)written;
        if (used >= size) { used = size - 1; break; }
    }
    (void)snprintf(buffer + used, size - used, ")");
}

static size_t find_predicate(const YogModule *module, const char *name, size_t length, size_t arity)
{
    size_t i;
    for (i = 0; i < module->predicate_count; ++i) {
        const YogIRPredicate *predicate = &module->predicates[i];
        if (predicate->arity == arity &&
            predicate->name.length == length &&
            (length == 0 || memcmp(predicate->name.text, name, length) == 0))
            return i;
    }
    return SIZE_MAX;
}

/* ------------------------------------------------------------------ solver */

static bool solve_atom(YogEngine *engine, size_t predicate,
                       const YogIRTerm *args, size_t arg_count, size_t args_base,
                       YogYield yield, void *user, int depth);
static bool solve_goals(YogEngine *engine, const YogIRClause *clause,
                        size_t frame, size_t index, YogYield yield, void *user,
                        int depth);

static YogIRTerm to_absolute(YogIRTerm term, size_t frame)
{
    if (term.kind == YOG_IR_VAR) {
        YogIRTerm absolute;
        absolute.kind = YOG_IR_VAR;
        absolute.index = frame + term.index;
        return absolute;
    }
    return term;
}

static bool unify_head(YogEngine *engine, const YogIRClause *clause, size_t frame,
                       const YogIRTerm *args, size_t arg_count, size_t args_base,
                       const YogModule *term_module)
{
    size_t base_offset;
    size_t i;

    if (clause->head_count != arg_count) return false;
    base_offset = term_module == NULL ? 0 : engine->module->value_count;

    for (i = 0; i < arg_count; ++i) {
        YogIRTerm head = to_absolute(clause->head[i], frame);
        YogIRTerm goal = args[i];
        if (head.kind == YOG_IR_CONST && term_module != NULL) head.index += base_offset;
        if (goal.kind == YOG_IR_VAR) goal.index += args_base;
        if (!yog_unify(&engine->store, &engine->space, head, goal)) return false;
    }
    return true;
}

/* Try one clause/fact; returns true to keep searching, false when the search
 * was stopped by the consumer or by an evaluation error. */
static bool try_clause(YogEngine *engine, const YogIRClause *clause,
                       const YogModule *term_module,
                       const YogIRTerm *args, size_t arg_count, size_t args_base,
                       YogYield yield, void *user, int depth)
{
    size_t mark = yog_store_mark(&engine->store);
    size_t frame = engine->store.cell_count;
    bool keep_searching = true;

    if (!within_budget(engine, clause->line, clause->column)) return false;

    if (engine->trace_enabled && clause->predicate < engine->module->predicate_count) {
        const YogIRPredicate *predicate = &engine->module->predicates[clause->predicate];
        tracef(engine, "try %s %.*s/%zu (line %d)\n",
               clause->kind == YOG_CLAUSE_FACT ? "fact" :
               clause->kind == YOG_CLAUSE_RULE ? "rule" : "decision",
               (int)predicate->name.length, predicate->name.text, predicate->arity, clause->line);
    }

    if (!yog_store_push_frame(&engine->store, clause->variable_count, &frame))
        return fail(engine, clause->line, clause->column, "out of memory growing the substitution store");

    if (unify_head(engine, clause, frame, args, arg_count, args_base, term_module)) {
        if (clause->goal_count == 0) {
            keep_searching = yield(user, engine);
        } else {
            keep_searching = solve_goals(engine, clause, frame, 0, yield, user, depth);
        }
    }

    (void)yog_store_reset(&engine->store, mark);
    engine->store.cell_count = frame;
    return keep_searching;
}

static bool solve_atom(YogEngine *engine, size_t predicate,
                       const YogIRTerm *args, size_t arg_count, size_t args_base,
                       YogYield yield, void *user, int depth)
{
    const YogIRPredicate *symbol;
    size_t i;

    if (engine->failed) return false;
    if (depth > engine->max_depth)
        return fail(engine, 0, 0, "evaluation depth limit exceeded (%d)", engine->max_depth);
    if (predicate >= engine->module->predicate_count) return true; /* undefined: no solutions */

    symbol = &engine->module->predicates[predicate];
    if (engine->trace_enabled) {
        char text[512];
        format_goal(engine, symbol, args, arg_count, args_base, text, sizeof(text));
        tracef(engine, "?- %s\n", text);
    }

    for (i = 0; i < symbol->fact_count; ++i) {
        const YogIRClause *clause = &engine->module->clauses[symbol->facts[i]];
        if (!try_clause(engine, clause, NULL, args, arg_count, args_base, yield, user, depth + 1))
            return false;
    }

    /* Request context facts behave exactly like facts appended to the program. */
    for (i = 0; i < engine->match_count; ++i) {
        if (engine->matches[i].predicate != predicate) continue;
        {
            const YogIRClause *clause = engine->matches[i].clause;
            if (!try_clause(engine, clause, engine->space.context, args, arg_count,
                            args_base, yield, user, depth + 1))
                return false;
        }
    }

    for (i = 0; i < symbol->rule_count; ++i) {
        const YogIRClause *clause = &engine->module->clauses[symbol->rules[i]];
        if (!try_clause(engine, clause, NULL, args, arg_count, args_base, yield, user, depth + 1))
            return false;
    }
    for (i = 0; i < symbol->decision_count; ++i) {
        const YogIRClause *clause = &engine->module->clauses[symbol->decisions[i]];
        if (!try_clause(engine, clause, NULL, args, arg_count, args_base, yield, user, depth + 1))
            return false;
    }
    return true;
}

typedef struct {
    YogEngine         *engine;
    const YogIRClause *clause;
    size_t             frame;
    size_t             next;
    YogYield           yield;
    void              *user;
    int                depth;
} ConjCtx;

static bool continue_after(void *user, YogEngine *engine)
{
    ConjCtx *ctx = user;
    return solve_goals(engine, ctx->clause, ctx->frame, ctx->next, ctx->yield, ctx->user, ctx->depth);
}

typedef struct {
    bool found;
} NegCtx;

static bool negation_yield(void *user, YogEngine *engine)
{
    (void)engine;
    ((NegCtx *)user)->found = true;
    return false; /* stop at the first proof */
}

/* Returns 1 when the built-in holds, 0 when it does not, -1 on error. */
static int eval_builtin_goal(YogEngine *engine, size_t frame, const YogIRGoal *goal)
{
    YogBuiltinArg args[YOG_IR_MAX_ARGS];
    char message[160];
    bool result = false;
    size_t i;

    if (!within_budget(engine, goal->line, goal->column)) return -1;
    if (goal->arg_count > YOG_IR_MAX_ARGS) {
        (void)fail(engine, goal->line, goal->column, "built-in has too many arguments");
        return -1;
    }
    for (i = 0; i < goal->arg_count; ++i) {
        YogIRTerm term = yog_store_resolve(&engine->store, to_absolute(goal->args[i], frame));
        const YogValue *value;
        if (term.kind == YOG_IR_VAR) {
            (void)fail(engine, goal->line, goal->column, "built-in argument is not bound");
            return -1;
        }
        value = yog_value_at(&engine->space, term.index);
        if (value == NULL) {
            (void)fail(engine, goal->line, goal->column, "built-in refers to an invalid constant");
            return -1;
        }
        args[i].text = NULL;
        args[i].length = 0;
        args[i].integer = 0;
        if (value->kind == YOG_VALUE_INTEGER) {
            args[i].kind = YOG_ARG_INTEGER;
            args[i].integer = value->integer;
        } else if (value->kind == YOG_VALUE_BOOLEAN) {
            args[i].kind = YOG_ARG_BOOLEAN;
            args[i].integer = value->integer;
        } else {
            args[i].kind = YOG_ARG_TEXT;
            args[i].text = value->text.text;
            args[i].length = value->text.length;
        }
    }
    if (!yog_builtin_eval((YogBuiltinId)goal->builtin, args, goal->arg_count, &result,
                          message, sizeof(message))) {
        (void)fail(engine, goal->line, goal->column, "%s", message);
        return -1;
    }
    return result ? 1 : 0;
}

/* Returns 1 when the comparison holds, 0 when it does not, -1 on error. */
static int eval_comparison(YogEngine *engine, size_t frame, const YogIRGoal *goal)
{
    YogIRTerm left = to_absolute(goal->args[0], frame);
    YogIRTerm right = to_absolute(goal->args[1], frame);
    const YogValue *a;
    const YogValue *b;
    bool equal;
    int order = 0;

    left = yog_store_resolve(&engine->store, left);
    right = yog_store_resolve(&engine->store, right);
    if (left.kind == YOG_IR_VAR || right.kind == YOG_IR_VAR) {
        (void)fail(engine, goal->line, goal->column, "comparison with an unbound variable");
        return -1;
    }
    a = yog_value_at(&engine->space, left.index);
    b = yog_value_at(&engine->space, right.index);
    if (a == NULL || b == NULL) {
        (void)fail(engine, goal->line, goal->column, "comparison refers to an invalid constant");
        return -1;
    }

    if (a->kind == YOG_VALUE_INTEGER && b->kind == YOG_VALUE_INTEGER) {
        equal = a->integer == b->integer;
        order = a->integer < b->integer ? -1 : (a->integer > b->integer ? 1 : 0);
    } else if (a->kind == YOG_VALUE_TEXT && b->kind == YOG_VALUE_TEXT) {
        size_t shared = a->text.length < b->text.length ? a->text.length : b->text.length;
        int cmp = shared == 0 ? 0 : memcmp(a->text.text, b->text.text, shared);
        equal = a->text.length == b->text.length && (shared == 0 || cmp == 0);
        order = cmp != 0 ? (cmp < 0 ? -1 : 1) : (a->text.length < b->text.length ? -1 :
                                                (a->text.length > b->text.length ? 1 : 0));
    } else if (a->kind == YOG_VALUE_BOOLEAN && b->kind == YOG_VALUE_BOOLEAN) {
        if (goal->comparison != YOG_COMPARE_EQ && goal->comparison != YOG_COMPARE_NE) {
            (void)fail(engine, goal->line, goal->column, "booleans can only be compared with == and !=");
            return -1;
        }
        equal = a->integer == b->integer;
    } else if ((a->kind == YOG_VALUE_TEXT && b->kind == YOG_VALUE_INTEGER) ||
               (a->kind == YOG_VALUE_INTEGER && b->kind == YOG_VALUE_TEXT)) {
        (void)fail(engine, goal->line, goal->column,
                   "cannot compare a string with an integer");
        return -1;
    } else {
        (void)fail(engine, goal->line, goal->column, "cannot compare values of different types");
        return -1;
    }

    switch (goal->comparison) {
    case YOG_COMPARE_EQ: return equal ? 1 : 0;
    case YOG_COMPARE_NE: return equal ? 0 : 1;
    case YOG_COMPARE_LT: return order < 0 ? 1 : 0;
    case YOG_COMPARE_LE: return order <= 0 ? 1 : 0;
    case YOG_COMPARE_GT: return order > 0 ? 1 : 0;
    case YOG_COMPARE_GE: return order >= 0 ? 1 : 0;
    default: return 0;
    }
}

static bool solve_goals(YogEngine *engine, const YogIRClause *clause,
                        size_t frame, size_t index, YogYield yield, void *user,
                        int depth)
{
    const YogIRGoal *goal;

    if (engine->failed) return false;
    if (index >= clause->goal_count) return yield(user, engine);
    if (depth > engine->max_depth)
        return fail(engine, clause->line, clause->column, "evaluation depth limit exceeded (%d)", engine->max_depth);

    goal = &clause->goals[index];

    /* An obligation never filters solutions; it is read when the clause wins. */
    if (goal->kind == YOG_IR_OBLIGATION)
        return solve_goals(engine, clause, frame, index + 1, yield, user, depth);

    if (goal->builtin != 0) {
        int outcome = eval_builtin_goal(engine, frame, goal);
        if (outcome < 0) return false;
        if (goal->kind == YOG_IR_NOT) outcome = !outcome;
        if (!outcome) return true;
        return solve_goals(engine, clause, frame, index + 1, yield, user, depth);
    }

    if (goal->kind == YOG_IR_CALL) {
        ConjCtx ctx;
        ctx.engine = engine;
        ctx.clause = clause;
        ctx.frame = frame;
        ctx.next = index + 1;
        ctx.yield = yield;
        ctx.user = user;
        ctx.depth = depth + 1;
        return solve_atom(engine, goal->predicate, goal->args, goal->arg_count,
                          frame, continue_after, &ctx, depth + 1);
    }

    if (goal->kind == YOG_IR_NOT) {
        size_t mark = yog_store_mark(&engine->store);
        NegCtx neg;
        neg.found = false;
        (void)solve_atom(engine, goal->predicate, goal->args, goal->arg_count,
                         frame, negation_yield, &neg, depth + 1);
        if (engine->failed) return false;
        if (!yog_store_reset(&engine->store, mark))
            return fail(engine, goal->line, goal->column, "failed to undo bindings after `not`");
        if (neg.found) return true; /* negation failed: clause has no solution here */
        return solve_goals(engine, clause, frame, index + 1, yield, user, depth);
    }

    {
        int result = eval_comparison(engine, frame, goal);
        if (result < 0) return false;
        if (result == 0) return true;
        return solve_goals(engine, clause, frame, index + 1, yield, user, depth);
    }
}

/* ------------------------------------------------------------ engine setup */

YogEngine *yog_engine_create(const YogModule *module, YogEvalError *error)
{
    YogEngine *engine;
    if (module == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "no module to evaluate");
        return NULL;
    }
    engine = calloc(1, sizeof(*engine));
    if (engine == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory creating the engine");
        return NULL;
    }
    yog_store_init(&engine->store);
    engine->module = module;
    engine->space.module = module;
    engine->max_steps = YOG_VM_MAX_STEPS;
    engine->max_depth = YOG_VM_MAX_DEPTH;
    engine->max_solutions = YOG_VM_MAX_SOLUTIONS;
    engine->max_millis = YOG_VM_MAX_MILLIS;
    engine->max_memory = YOG_VM_MAX_MEMORY;
    return engine;
}

void yog_engine_free(YogEngine *engine)
{
    if (engine == NULL) return;
    yog_store_free(&engine->store);
    free(engine->trace);
    free(engine->matches);
    free(engine);
}

void yog_engine_set_limits(YogEngine *engine, YogEngineLimits limits)
{
    if (engine == NULL) return;
    if (limits.max_steps > 0) engine->max_steps = limits.max_steps;
    if (limits.max_depth > 0) engine->max_depth = limits.max_depth;
    if (limits.max_solutions > 0) engine->max_solutions = limits.max_solutions;
    if (limits.max_millis > 0) engine->max_millis = limits.max_millis;
    if (limits.max_memory > 0) engine->max_memory = limits.max_memory;
}

static void engine_reset(YogEngine *engine, const YogModule *context, bool trace_enabled)
{
    engine->store.trail_count = 0;
    engine->store.cell_count = 0;
    engine->steps = 0;
    engine->solutions = 0;
    engine->clock_ok = timespec_get(&engine->started, TIME_UTC) == TIME_UTC;
    engine->failed = false;
    engine->error.line = 0;
    engine->error.column = 0;
    engine->error.message[0] = '\0';
    engine->trace_enabled = trace_enabled;
    engine->trace_length = 0;
    if (engine->trace != NULL) engine->trace[0] = '\0';
    engine->space.context = context;
    engine->match_count = 0;
}

/* A context fact for an `input` predicate must have the declared argument
 * types.  Returns false and fills `error` on a mismatch: a malformed request is
 * an evaluation error, which callers treat as DENY. */
static bool check_input_types(const YogEngine *engine, const YogModule *context,
                              const YogIRClause *clause, const YogIRPredicate *predicate,
                              YogEvalError *error)
{
    size_t a;
    if (predicate->role != YOG_ROLE_INPUT || predicate->arg_types == NULL) return true;
    for (a = 0; a < clause->head_count && a < predicate->arity; ++a) {
        const YogIRTerm term = clause->head[a];
        const YogValue *value;
        unsigned char wanted = predicate->arg_types[a];
        bool fits;
        if (term.kind != YOG_IR_CONST || term.index >= context->value_count) continue;
        value = &context->values[term.index];
        fits = wanted == YOG_TYPE_ANY ||
               (wanted == YOG_TYPE_TEXT && value->kind == YOG_VALUE_TEXT) ||
               (wanted == YOG_TYPE_INT && value->kind == YOG_VALUE_INTEGER) ||
               (wanted == YOG_TYPE_BOOL && value->kind == YOG_VALUE_BOOLEAN);
        if (!fits) {
            if (error != NULL) {
                error->line = clause->line;
                error->column = clause->column;
                (void)snprintf(error->message, sizeof(error->message),
                               "context fact %.*s/%zu: argument %zu must be %s",
                               (int)predicate->name.length, predicate->name.text, predicate->arity,
                               a + 1,
                               wanted == YOG_TYPE_TEXT ? "text" : (wanted == YOG_TYPE_INT ? "int" : "bool"));
            }
            return false;
        }
    }
    (void)engine;
    return true;
}

static bool build_matches(YogEngine *engine, const YogModule *context, YogEvalError *error)
{
    size_t i;
    if (context == NULL) return true;
    for (i = 0; i < context->clause_count; ++i) {
        const YogIRClause *clause = &context->clauses[i];
        const YogIRPredicate *predicate;
        size_t id;
        if (clause->kind != YOG_CLAUSE_FACT) continue;
        if (clause->predicate >= context->predicate_count) continue;
        predicate = &context->predicates[clause->predicate];
        id = find_predicate(engine->module, predicate->name.text, predicate->name.length, predicate->arity);
        if (id == SIZE_MAX) continue; /* a context fact for an unknown predicate is ignored */
        if (!check_input_types(engine, context, clause, &engine->module->predicates[id], error))
            return false;
        if (engine->match_count == engine->match_capacity) {
            size_t next = engine->match_capacity == 0 ? 8 : engine->match_capacity * 2;
            ContextMatch *grown;
            if (next < engine->match_capacity || next > SIZE_MAX / sizeof(*grown)) return false;
            grown = realloc(engine->matches, next * sizeof(*grown));
            if (grown == NULL) return false;
            engine->matches = grown;
            engine->match_capacity = next;
        }
        engine->matches[engine->match_count].predicate = id;
        engine->matches[engine->match_count].clause = clause;
        engine->match_count++;
    }
    return true;
}

static char *duplicate(const char *text)
{
    size_t length;
    char *copy;
    if (text == NULL) return NULL;
    length = strlen(text);
    copy = malloc(length + 1);
    if (copy == NULL) return NULL;
    memcpy(copy, text, length + 1);
    return copy;
}

static bool finish_result(YogEngine *engine, YogVerdict decision, const char *reason,
                          YogEngineResult *result, YogEvalError *error)
{
    result->decision = decision;
    result->reason = duplicate(reason);
    result->trace = (engine->trace_enabled && engine->trace_length > 0) ? duplicate(engine->trace) : NULL;
    if (result->reason == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory building the result");
        return false;
    }
    return true;
}

/* Frees everything a result owns; safe to call twice. */
void yog_engine_result_free(YogEngineResult *result)
{
    size_t i;
    if (result == NULL) return;
    for (i = 0; i < result->obligation_count; ++i) {
        size_t a;
        for (a = 0; a < result->obligations[i].arg_count; ++a) free(result->obligations[i].args[a].text);
        free(result->obligations[i].args);
        free(result->obligations[i].name);
    }
    free(result->obligations);
    free(result->reason);
    free(result->trace);
    result->obligations = NULL;
    result->obligation_count = 0;
    result->reason = NULL;
    result->trace = NULL;
}

/* ------------------------------------------------------------- obligations */

typedef struct {
    YogEngine         *engine;
    const YogIRClause *clause;
    size_t             frame;
    bool               collect;
    bool               found;
    YogEngineResult   *result;
    size_t            *capacity;
} DecisionCtx;

static bool arg_from_term(YogEngine *engine, YogIRTerm term, size_t frame,
                          const YogIRGoal *goal, YogEngineArg *out)
{
    YogIRTerm resolved = yog_store_resolve(&engine->store, to_absolute(term, frame));
    const YogValue *value;
    memset(out, 0, sizeof(*out));
    if (resolved.kind == YOG_IR_VAR)
        return fail(engine, goal->line, goal->column, "obligation argument is not bound");
    value = yog_value_at(&engine->space, resolved.index);
    if (value == NULL)
        return fail(engine, goal->line, goal->column, "obligation refers to an invalid constant");
    if (value->kind == YOG_VALUE_INTEGER) {
        out->kind = 1;
        out->integer = value->integer;
    } else if (value->kind == YOG_VALUE_BOOLEAN) {
        out->kind = 2;
        out->integer = value->integer;
    } else {
        out->kind = 0;
        out->text = malloc(value->text.length + 1);
        if (out->text == NULL)
            return fail(engine, goal->line, goal->column, "out of memory recording an obligation");
        if (value->text.length > 0) memcpy(out->text, value->text.text, value->text.length);
        out->text[value->text.length] = '\0';
    }
    return true;
}

static bool obligation_equal(const YogEngineObligation *a, const YogEngineObligation *b)
{
    size_t i;
    if (a->arg_count != b->arg_count || strcmp(a->name, b->name) != 0) return false;
    for (i = 0; i < a->arg_count; ++i) {
        if (a->args[i].kind != b->args[i].kind) return false;
        if (a->args[i].kind == 0) {
            if (strcmp(a->args[i].text, b->args[i].text) != 0) return false;
        } else if (a->args[i].integer != b->args[i].integer) {
            return false;
        }
    }
    return true;
}

static void obligation_release(YogEngineObligation *o)
{
    size_t a;
    for (a = 0; a < o->arg_count; ++a) free(o->args[a].text);
    free(o->args);
    free(o->name);
    memset(o, 0, sizeof(*o));
}

/* Reads one obligation goal while the clause's bindings are still live.  A
 * duplicate of an obligation already collected is dropped, so the result is a
 * deterministic, deduplicated list in clause order. */
static bool record_obligation(DecisionCtx *ctx, const YogIRGoal *goal)
{
    YogEngine *engine = ctx->engine;
    YogEngineResult *result = ctx->result;
    YogEngineObligation fresh;
    size_t a;

    memset(&fresh, 0, sizeof(fresh));
    fresh.name = malloc(goal->name.length + 1);
    if (fresh.name == NULL)
        return fail(engine, goal->line, goal->column, "out of memory recording an obligation");
    if (goal->name.length > 0) memcpy(fresh.name, goal->name.text, goal->name.length);
    fresh.name[goal->name.length] = '\0';
    fresh.args = goal->arg_count == 0 ? NULL : calloc(goal->arg_count, sizeof(*fresh.args));
    if (goal->arg_count > 0 && fresh.args == NULL) {
        obligation_release(&fresh);
        return fail(engine, goal->line, goal->column, "out of memory recording an obligation");
    }
    fresh.arg_count = goal->arg_count;
    for (a = 0; a < goal->arg_count; ++a) {
        if (!arg_from_term(engine, goal->args[a], ctx->frame, goal, &fresh.args[a])) {
            fresh.arg_count = a;
            obligation_release(&fresh);
            return false;
        }
    }
    for (a = 0; a < result->obligation_count; ++a) {
        if (obligation_equal(&result->obligations[a], &fresh)) {
            obligation_release(&fresh);
            return true;
        }
    }
    if (result->obligation_count >= YOG_VM_MAX_OBLIGATIONS) {
        obligation_release(&fresh);
        return fail(engine, goal->line, goal->column, "obligation limit exceeded (%u)",
                    (unsigned)YOG_VM_MAX_OBLIGATIONS);
    }
    if (result->obligation_count == *ctx->capacity) {
        size_t next = *ctx->capacity == 0 ? 4 : *ctx->capacity * 2;
        YogEngineObligation *grown = realloc(result->obligations, next * sizeof(*grown));
        if (grown == NULL) {
            obligation_release(&fresh);
            return fail(engine, goal->line, goal->column, "out of memory recording an obligation");
        }
        result->obligations = grown;
        *ctx->capacity = next;
    }
    result->obligations[result->obligation_count++] = fresh;
    return true;
}

static bool decision_yield(void *user, YogEngine *engine)
{
    DecisionCtx *ctx = user;
    size_t g;
    (void)engine;
    ctx->found = true;
    if (ctx->collect) {
        for (g = 0; g < ctx->clause->goal_count; ++g) {
            const YogIRGoal *goal = &ctx->clause->goals[g];
            if (goal->kind != YOG_IR_OBLIGATION) continue;
            if (!record_obligation(ctx, goal)) return false;
        }
    }
    return false; /* the first solution of a clause is enough */
}

static bool clause_has_obligations(const YogIRClause *clause)
{
    size_t g;
    for (g = 0; g < clause->goal_count; ++g)
        if (clause->goals[g].kind == YOG_IR_OBLIGATION) return true;
    return false;
}

static bool clause_matches(YogEngine *engine, const YogIRClause *clause, size_t frame,
                           const YogIRTerm *args, bool collect, YogEngineResult *result,
                           size_t *capacity)
{
    DecisionCtx ctx;
    ctx.engine = engine;
    ctx.clause = clause;
    ctx.frame = frame;
    ctx.collect = collect;
    ctx.found = false;
    ctx.result = result;
    ctx.capacity = capacity;
    if (!unify_head(engine, clause, frame, args, clause->head_count, 0, NULL)) return false;
    if (clause->goal_count == 0) {
        (void)decision_yield(&ctx, engine);
        return ctx.found && !engine->failed;
    }
    (void)solve_goals(engine, clause, frame, 0, decision_yield, &ctx, 1);
    return ctx.found && !engine->failed;
}

/* ---------------------------------------------------------------- check() */

bool yog_engine_check(YogEngine *engine, const char *actor, const char *action,
                      const char *resource, const YogModule *context,
                      bool want_trace, YogEngineResult *result, YogEvalError *error)
{
    static const YogClauseKind passes[3] = { YOG_CLAUSE_DENY, YOG_CLAUSE_APPROVAL, YOG_CLAUSE_ALLOW };
    YogValue request[2];
    YogIRTerm goal[2];
    size_t predicate_id;
    size_t base;
    size_t kind_pass;
    size_t capacity = 0;
    char reason[256];

    if (engine == NULL || result == NULL) return false;
    memset(result, 0, sizeof(*result));
    if (engine->module == NULL || actor == NULL || action == NULL || resource == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "check() received a null argument");
        return false;
    }

    engine_reset(engine, context, want_trace);
    if (!build_matches(engine, context, error)) {
        if (error != NULL && error->message[0] == '\0')
            (void)snprintf(error->message, sizeof(error->message), "out of memory preparing context facts");
        return false;
    }

    request[0].kind = YOG_VALUE_TEXT;
    request[0].text.text = actor;
    request[0].text.length = strlen(actor);
    request[0].integer = 0;
    request[1].kind = YOG_VALUE_TEXT;
    request[1].text.text = resource;
    request[1].text.length = strlen(resource);
    request[1].integer = 0;
    engine->space.request = request;
    engine->space.request_count = 2;

    base = engine->module->value_count + (context == NULL ? 0 : context->value_count);
    goal[0].kind = YOG_IR_CONST;
    goal[0].index = base;
    goal[1].kind = YOG_IR_CONST;
    goal[1].index = base + 1;

    predicate_id = find_predicate(engine->module, action, strlen(action), 2);
    if (predicate_id == SIZE_MAX || engine->module->predicates[predicate_id].role != YOG_ROLE_DECISION) {
        (void)snprintf(reason, sizeof(reason),
                       "no allow/deny clause defines action %s/2", action);
        return finish_result(engine, YOG_VERDICT_DENY, reason, result, error);
    }

    /* Precedence: deny > require_approval > allow > default deny.  Obligations
     * come only from the winning kind, in clause order, without duplicates. */
    for (kind_pass = 0; kind_pass < 3; ++kind_pass) {
        const YogIRPredicate *predicate = &engine->module->predicates[predicate_id];
        YogClauseKind wanted = passes[kind_pass];
        int first_line = 0;
        size_t i;
        for (i = 0; i < predicate->decision_count; ++i) {
            const YogIRClause *clause = &engine->module->clauses[predicate->decisions[i]];
            size_t mark;
            size_t frame;
            bool matched;

            if (clause->kind != wanted) continue;
            /* After the first match, later clauses only matter for their obligations. */
            if (first_line != 0 && !clause_has_obligations(clause)) continue;

            mark = yog_store_mark(&engine->store);
            frame = 0;
            if (!yog_store_push_frame(&engine->store, clause->variable_count, &frame)) {
                (void)fail(engine, clause->line, clause->column, "out of memory evaluating a decision clause");
                if (error != NULL) *error = engine->error;
                yog_engine_result_free(result);
                return false;
            }
            matched = clause_matches(engine, clause, frame, goal, wanted != YOG_CLAUSE_DENY,
                                     result, &capacity);
            (void)yog_store_reset(&engine->store, mark);
            engine->store.cell_count = frame;

            if (engine->failed) {
                if (error != NULL) *error = engine->error;
                yog_engine_result_free(result);
                return false;
            }
            if (matched) {
                if (first_line == 0) first_line = clause->line;
                if (wanted == YOG_CLAUSE_DENY) break;
            }
        }
        if (first_line != 0) {
            const char *kind_name = wanted == YOG_CLAUSE_DENY ? "deny" :
                                    (wanted == YOG_CLAUSE_APPROVAL ? "require_approval" : "allow");
            const char *verdict_name = wanted == YOG_CLAUSE_DENY ? "DENY" :
                                       (wanted == YOG_CLAUSE_APPROVAL ? "REQUIRE_APPROVAL" : "ALLOW");
            YogVerdict verdict = wanted == YOG_CLAUSE_DENY ? YOG_VERDICT_DENY :
                                 (wanted == YOG_CLAUSE_APPROVAL ? YOG_VERDICT_REQUIRE_APPROVAL : YOG_VERDICT_ALLOW);
            (void)snprintf(reason, sizeof(reason), "%s clause at line %d matched", kind_name, first_line);
            tracef(engine, "-> %s (%s)\n", verdict_name, reason);
            result->matched_line = first_line;
            if (!finish_result(engine, verdict, reason, result, error)) {
                yog_engine_result_free(result);
                return false;
            }
            return true;
        }
    }

    (void)snprintf(reason, sizeof(reason), "default deny: no allow clause was satisfied");
    tracef(engine, "-> DENY (%s)\n", reason);
    return finish_result(engine, YOG_VERDICT_DENY, reason, result, error);
}

/* ---------------------------------------------------------- run_queries() */

typedef struct {
    YogEngine     *engine;
    const YogIRQuery *query;
    size_t         frame;
    FILE          *out;
    bool           any;
} QueryCtx;

static bool collect_solution(void *user, YogEngine *engine)
{
    QueryCtx *ctx = user;
    size_t i;
    bool printed = false;

    engine->solutions++;
    if (engine->solutions > engine->max_solutions)
        return fail(engine, ctx->query->line, ctx->query->column,
                    "solution limit exceeded (%zu)", engine->max_solutions);

    if (!ctx->any) {
        fprintf(ctx->out, "  -> TRUE\n");
        ctx->any = true;
    }
    for (i = 0; i < ctx->query->variable_count; ++i) {
        YogIRTerm term;
        YogIRTerm resolved;
        char text[160];
        term.kind = YOG_IR_VAR;
        term.index = ctx->frame + i;
        resolved = yog_store_resolve(&engine->store, term);
        if (resolved.kind == YOG_IR_VAR) continue;
        format_value(engine, resolved, text, sizeof(text));
        fprintf(ctx->out, "%s%.*s=%s", printed ? ", " : "     ",
                (int)ctx->query->variables[i].length, ctx->query->variables[i].text, text);
        printed = true;
    }
    if (printed) fputc('\n', ctx->out);
    return true; /* enumerate every solution */
}

bool yog_engine_run_queries(YogEngine *engine, const YogModule *context,
                            FILE *out, bool want_trace, YogEvalError *error)
{
    size_t i;

    if (engine == NULL || out == NULL) return false;
    engine_reset(engine, context, want_trace);
    if (!build_matches(engine, context, error)) {
        if (error != NULL && error->message[0] == '\0')
            (void)snprintf(error->message, sizeof(error->message), "out of memory preparing context facts");
        return false;
    }

    for (i = 0; i < engine->module->query_count; ++i) {
        const YogIRQuery *query = &engine->module->queries[i];
        YogIRTerm *absolute = NULL;
        size_t frame = 0;
        size_t mark = yog_store_mark(&engine->store);
        size_t a;
        QueryCtx ctx;

        fprintf(out, "query %.*s(", (int)query->name.length, query->name.text);
        for (a = 0; a < query->arg_count; ++a) {
            char text[160];
            YogIRTerm term = query->args[a];
            if (term.kind == YOG_IR_VAR) {
                (void)snprintf(text, sizeof(text), "%.*s",
                               (int)query->variables[term.index].length,
                               query->variables[term.index].text);
            } else {
                const YogValue *value = yog_value_at(&engine->space, term.index);
                if (value != NULL && value->kind == YOG_VALUE_INTEGER)
                    (void)snprintf(text, sizeof(text), "%lld", (long long)value->integer);
                else if (value != NULL)
                    (void)snprintf(text, sizeof(text), "%.*s", (int)value->text.length, value->text.text);
                else
                    (void)snprintf(text, sizeof(text), "?");
            }
            fprintf(out, "%s%s", a == 0 ? "" : ", ", text);
        }
        fputs(")\n", out);

        if (!yog_store_push_frame(&engine->store, query->variable_count, &frame)) {
            if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory evaluating a query");
            return false;
        }
        absolute = query->arg_count == 0 ? NULL : malloc(query->arg_count * sizeof(*absolute));
        if (query->arg_count > 0 && absolute == NULL) {
            free(absolute);
            (void)yog_store_reset(&engine->store, mark);
            engine->store.cell_count = frame;
            if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory evaluating a query");
            return false;
        }
        for (a = 0; a < query->arg_count; ++a) {
            absolute[a] = query->args[a];
            if (absolute[a].kind == YOG_IR_VAR) absolute[a].index += frame;
        }

        ctx.engine = engine;
        ctx.query = query;
        ctx.frame = frame;
        ctx.out = out;
        ctx.any = false;

        (void)solve_atom(engine, query->predicate, absolute, query->arg_count, 0,
                         collect_solution, &ctx, 0);
        free(absolute);
        (void)yog_store_reset(&engine->store, mark);
        engine->store.cell_count = frame;

        if (engine->failed) {
            if (error != NULL) *error = engine->error;
            return false;
        }
        if (!ctx.any) fputs("  -> FALSE\n", out);
        if (want_trace && engine->trace_length > 0) {
            const char *line = engine->trace;
            while (*line) {
                const char *nl = strchr(line, '\n');
                size_t length = nl == NULL ? strlen(line) : (size_t)(nl - line);
                fprintf(out, "> %.*s\n", (int)length, line);
                line += length + (nl == NULL ? 0 : 1);
            }
            engine->trace_length = 0;
            if (engine->trace != NULL) engine->trace[0] = '\0';
        }
        fputc('\n', out);
    }
    return true;
}
