/*
 * yog.h -- public C API of the YOG policy engine.
 *
 * This is the only header embedders should include.  It exposes the compiler
 * facade (compile/free), the authorization query (check), query execution for
 * tests and the CLI, and the diagnostic/result types.  The lexer, parser,
 * semantic analyser, IR and VM are implementation details.
 *
 * Ownership
 *   - yog_compile() copies the source; the caller may free its buffer
 *     immediately.  The returned Yog owns everything it needs.
 *   - YogResult strings are owned by the result and released with
 *     yog_result_free().
 *   - YogError is caller-owned storage; its message is NUL-terminated.
 */
#ifndef YOG_API_H
#define YOG_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/*
 * Shared-library visibility.  A static build sees no decoration; the shared
 * target defines YOG_SHARED_EXPORTS so Windows gets dllexport and consumers
 * that define YOG_SHARED get dllimport.  On GCC/Clang the default visibility
 * is used and YOG_SHARED_EXPORTS is only documentation.
 */
#if defined(_WIN32)
#  if defined(YOG_SHARED_EXPORTS)
#    define YOG_API __declspec(dllexport)
#  elif defined(YOG_SHARED)
#    define YOG_API __declspec(dllimport)
#  else
#    define YOG_API
#  endif
#elif defined(YOG_SHARED_EXPORTS)
#  define YOG_API __attribute__((visibility("default")))
#else
#  define YOG_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct YogModule YogModule;

typedef struct {
    int  line;
    int  column;
    char message[192];
} YogError;

typedef struct Yog Yog;

typedef enum {
    YOG_ALLOW = 0,
    YOG_DENY = 1
} YogDecision;

typedef struct {
    YogDecision decision;
    char       *reason;
    char       *trace;   /* NULL unless trace output was requested */
} YogResult;

/* Evaluation budgets.  A zero field keeps the built-in default; non-positive
 * max_depth also uses the default. Policies are untrusted input, so these caps
 * bound the work a single request may do. */
typedef struct {
    size_t max_steps;   /* default YOG_VM_MAX_STEPS (1,000,000) */
    int    max_depth;   /* default YOG_VM_MAX_DEPTH (256) */
} YogLimits;

/* Compile a policy.  Returns NULL on error and fills `error`. */
YOG_API Yog *yog_compile(const char *source, size_t length, YogError *error);

YOG_API void yog_free(Yog *yog);

/* Read-only view of the compiled module, for `yogc ir` and tooling. */
YOG_API const YogModule *yog_module(const Yog *yog);

/*
 * Set the evaluation budgets used by subsequent checks.  Call this during
 * setup, before sharing the Yog across threads: mutating the limits while a
 * check is running is a data race.
 */
YOG_API void yog_set_limits(Yog *yog, YogLimits limits);

/* Read back the effective limits. */
YOG_API YogLimits yog_get_limits(const Yog *yog);

/*
 * Apply the policy-combining contract to one request:
 *   deny > allow > default deny.
 *
 * `context` is an optional string of ground facts separated by ';'
 * (for example "fact amount(acct_1, 9000)").  It is parsed per request and
 * never modifies the compiled program.
 *
 * A Yog is immutable after compilation and every check builds its own
 * evaluator, so concurrent yog_check() calls on the same Yog are safe once
 * yog_set_limits() has finished.  Each call's context is isolated: facts from
 * one request can never be observed by another.
 *
 * Returns false only on an evaluation/IO error; a denied request still
 * returns true with result->decision == YOG_DENY.  On false the decision is
 * fail-closed: callers must treat it as DENY.
 */
YOG_API bool yog_check(Yog *yog, const char *actor, const char *action, const char *resource,
                       const char *context, bool trace, YogResult *result, YogError *error);

/* Evaluate every `query` in the policy, printing in the reference format. */
YOG_API bool yog_run_queries(Yog *yog, FILE *out, bool trace);

YOG_API void yog_result_free(YogResult *result);

#ifdef __cplusplus
}
#endif
#endif /* YOG_API_H */
