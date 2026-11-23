/*
 * vm.h -- evaluation: values, substitutions, unification, and the engine.
 *
 * The VM answers logical questions only ("does this goal have a solution,
 * and with which bindings?").  Deciding ALLOW/DENY lives in the engine's
 * check() layer, on top of the solver -- the same separation the Python
 * reference has between ask() and check().
 */
#ifndef YOG_VM_H
#define YOG_VM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "ir/ir.h"

#define YOG_VM_UNBOUND       ((size_t)-1)
#define YOG_VM_MAX_DEPTH     256
#define YOG_VM_MAX_STEPS     1000000u
#define YOG_VM_MAX_SOLUTIONS 100000u
/* Distinct obligations one decision may return. */
#define YOG_VM_MAX_OBLIGATIONS 256u
/* Wall-clock backstop for one check or one query run.  The step budget is the
 * primary, deterministic bound; this only catches pathological slowness. */
#define YOG_VM_MAX_MILLIS    10000u
/* Bytes the evaluator may hold for substitutions, the trail, context matches
 * and the trace buffer during one check. */
#define YOG_VM_MAX_MEMORY    ((size_t)64u * 1024u * 1024u)

/* Every field: zero (or, for max_depth, non-positive) keeps the default. */
typedef struct {
    size_t max_steps;
    int    max_depth;
    size_t max_solutions;
    size_t max_millis;
    size_t max_memory;
} YogEngineLimits;

/* ------------------------------------------------------------ value space */

/* Values can come from three places: the compiled module, an optional
 * per-request context module, and request strings supplied by the caller. */
typedef struct {
    const YogModule *module;
    const YogModule *context;
    const YogValue  *request;
    size_t           request_count;
} YogValueSpace;

const YogValue *yog_value_at(const YogValueSpace *space, size_t index);

/* ---------------------------------------------------------- substitutions */

typedef struct {
    YogIRTerm *cells;
    size_t     cell_count;
    size_t     cell_capacity;
    size_t    *trail;
    size_t     trail_count;
    size_t     trail_capacity;
} YogStore;

void   yog_store_init(YogStore *store);
void   yog_store_free(YogStore *store);
size_t yog_store_mark(const YogStore *store);
bool   yog_store_reset(YogStore *store, size_t mark);
bool   yog_store_push_frame(YogStore *store, size_t count, size_t *out_base);

/* Follow variable-to-variable bindings until a constant or an unbound cell. */
YogIRTerm yog_store_resolve(const YogStore *store, YogIRTerm term);
bool      yog_unify(YogStore *store, const YogValueSpace *space,
                    YogIRTerm left, YogIRTerm right);

/* ---------------------------------------------------------------- engine */

typedef struct {
    int  line;
    int  column;
    char message[192];
} YogEvalError;

/* Kept distinct from the public YogDecision so the VM layer does not have to
 * include the API header (and vice versa). */
typedef enum {
    YOG_VERDICT_ALLOW = 0,
    YOG_VERDICT_DENY = 1,
    YOG_VERDICT_REQUIRE_APPROVAL = 2
} YogVerdict;

/* Obligation argument kinds match YogObligationArgKind in the public API. */
typedef struct {
    int      kind;      /* 0 text, 1 integer, 2 boolean */
    char    *text;      /* text arguments only (NUL-terminated copy) */
    int64_t  integer;   /* integers, and 0/1 for booleans */
} YogEngineArg;

typedef struct {
    char         *name;
    YogEngineArg *args;
    size_t        arg_count;
} YogEngineObligation;


typedef struct {
    YogVerdict           decision;
    char                *reason;
    char                *trace;
    int                  matched_line;      /* line of the first clause that decided */
    YogEngineObligation *obligations;       /* ALLOW / REQUIRE_APPROVAL only */
    size_t               obligation_count;
} YogEngineResult;

typedef struct YogEngine YogEngine;

YogEngine *yog_engine_create(const YogModule *module, YogEvalError *error);
void       yog_engine_free(YogEngine *engine);
void       yog_engine_set_limits(YogEngine *engine, YogEngineLimits limits);

/* Runs the deny/allow precedence contract.  `context` is an optional module
 * containing ground facts injected for this one request.
 * `want_trace` fills result->trace with a line-oriented trace. */
bool yog_engine_check(YogEngine *engine, const char *actor, const char *action,
                      const char *resource, const YogModule *context,
                      bool want_trace, YogEngineResult *result, YogEvalError *error);

/* Evaluates every `query` in the module, printing in the reference format. */
bool yog_engine_run_queries(YogEngine *engine, const YogModule *context,
                            FILE *out, bool want_trace, YogEvalError *error);

void yog_engine_result_free(YogEngineResult *result);

#endif /* YOG_VM_H */
