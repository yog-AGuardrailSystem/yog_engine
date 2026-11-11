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
    size_t               steps;

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

    engine->steps++;
    if (engine->steps > engine->max_steps)
        return fail(engine, clause->line, clause->column, "evaluation step limit exceeded");

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
    } else {
        (void)fail(engine, goal->line, goal->column,
                   "cannot compare a string with an integer");
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

void yog_engine_set_limits(YogEngine *engine, size_t max_steps, int max_depth)
{
    if (engine == NULL) return;
    if (max_steps > 0) engine->max_steps = max_steps;
    if (max_depth > 0) engine->max_depth = max_depth;
}

static void engine_reset(YogEngine *engine, const YogModule *context, bool trace_enabled)
{
    engine->store.trail_count = 0;
    engine->store.cell_count = 0;
    engine->steps = 0;
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

static bool build_matches(YogEngine *engine, const YogModule *context)
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

typedef struct {
    bool found;
} StopCtx;

static bool stop_on_solution(void *user, YogEngine *engine)
{
    (void)engine;
    ((StopCtx *)user)->found = true;
    return false;
}

static bool body_has_solution(YogEngine *engine, const YogIRClause *clause, size_t frame,
                              size_t args_base, const YogIRTerm *args)
{
    StopCtx stop;
    stop.found = false;
    if (!unify_head(engine, clause, frame, args, clause->head_count, args_base, NULL)) return false;
    if (clause->goal_count == 0) {
        stop.found = true;
        return true;
    }
    (void)solve_goals(engine, clause, frame, 0, stop_on_solution, &stop, 1);
    return stop.found;
}

void yog_engine_result_free(YogEngineResult *result)
{
    if (result == NULL) return;
    free(result->reason);
    free(result->trace);
    result->reason = NULL;
    result->trace = NULL;
}

/* ---------------------------------------------------------------- check() */

bool yog_engine_check(YogEngine *engine, const char *actor, const char *action,
                      const char *resource, const YogModule *context,
                      bool want_trace, YogEngineResult *result, YogEvalError *error)
{
    YogValue request[2];
    YogIRTerm goal[2];
    size_t predicate_id;
    size_t base;
    size_t kind_pass;
    char reason[256];

    if (engine == NULL || result == NULL) return false;
    memset(result, 0, sizeof(*result));
    if (engine->module == NULL || actor == NULL || action == NULL || resource == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "check() received a null argument");
        return false;
    }

    engine_reset(engine, context, want_trace);
    if (!build_matches(engine, context)) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory preparing context facts");
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

    for (kind_pass = 0; kind_pass < 2; ++kind_pass) {
        const YogIRPredicate *predicate = &engine->module->predicates[predicate_id];
        YogClauseKind wanted = kind_pass == 0 ? YOG_CLAUSE_DENY : YOG_CLAUSE_ALLOW;
        size_t i;
        for (i = 0; i < predicate->decision_count; ++i) {
            const YogIRClause *clause = &engine->module->clauses[predicate->decisions[i]];
            size_t mark;
            size_t frame;
            bool matched;

            if (clause->kind != wanted) continue;

            mark = yog_store_mark(&engine->store);
            frame = 0;
            if (!yog_store_push_frame(&engine->store, clause->variable_count, &frame)) {
                (void)fail(engine, clause->line, clause->column, "out of memory evaluating a decision clause");
                (void)error;
                return false;
            }
            matched = body_has_solution(engine, clause, frame, 0, goal);
            (void)yog_store_reset(&engine->store, mark);
            engine->store.cell_count = frame;

            if (engine->failed) {
                if (error != NULL) *error = engine->error;
                return false;
            }
            if (matched) {
                (void)snprintf(reason, sizeof(reason), "%s clause at line %d matched",
                               wanted == YOG_CLAUSE_DENY ? "deny" : "allow", clause->line);
                tracef(engine, "-> %s (%s)\n", wanted == YOG_CLAUSE_DENY ? "DENY" : "ALLOW", reason);
                return finish_result(engine, wanted == YOG_CLAUSE_DENY ? YOG_VERDICT_DENY : YOG_VERDICT_ALLOW,
                                     reason, result, error);
            }
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
    if (!build_matches(engine, context)) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory preparing context facts");
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
