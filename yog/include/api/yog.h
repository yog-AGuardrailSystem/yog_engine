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

/* Library version.  Keep in sync with project(VERSION) in CMakeLists.txt and
 * the Python/Rust package manifests (tests/test_versions.py checks this). */
#define YOG_VERSION_MAJOR 0
#define YOG_VERSION_MINOR 2
#define YOG_VERSION_PATCH 0
#define YOG_VERSION_PRERELEASE "alpha.1"
#define YOG_VERSION_STRING "0.2.0-alpha.1"

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

/* Outcomes.  Precedence when several clauses match: deny > require_approval >
 * allow > default deny.  Callers must treat anything other than YOG_ALLOW as
 * "do not run the action now"; YOG_REQUIRE_APPROVAL means a human or another
 * authority must approve this exact request first. */
typedef enum {
    YOG_ALLOW = 0,
    YOG_DENY = 1,
    YOG_REQUIRE_APPROVAL = 2
} YogDecision;

/* An obligation is data the policy attaches to an ALLOW or REQUIRE_APPROVAL
 * decision (for example "audit this call").  YOG never performs it: the
 * enforcement point (gateway, agent runtime) must. */
typedef enum {
    YOG_OBLIGATION_TEXT = 0,
    YOG_OBLIGATION_INTEGER = 1,
    YOG_OBLIGATION_BOOLEAN = 2
} YogObligationArgKind;

typedef struct {
    YogObligationArgKind kind;
    char                *text;     /* TEXT only */
    long long            integer;  /* INTEGER value, or 0/1 for BOOLEAN */
} YogObligationArg;

typedef struct {
    char             *name;
    YogObligationArg *args;
    size_t            arg_count;
} YogObligation;

typedef struct {
    YogDecision    decision;
    char          *reason;
    char          *trace;   /* NULL unless trace output was requested */
    int            matched_line;      /* line of the first clause that decided; 0 for default deny */
    YogObligation *obligations;       /* NULL when there are none */
    size_t         obligation_count;
} YogResult;

/* Evaluation budgets.  A zero field keeps the built-in default; non-positive
 * max_depth also uses the default. Policies are untrusted input, so these caps
 * bound the work a single request may do.  Exceeding any of them is an
 * evaluation error, which callers must treat as DENY.
 *
 * Always zero-initialise this struct (YogLimits l = {0};) before setting the
 * fields you care about, so new fields added later keep their defaults. */
typedef struct {
    size_t max_steps;     /* clause attempts; default 1,000,000 */
    int    max_depth;     /* goal nesting;   default 256 */
    size_t max_solutions; /* solutions enumerated per query; default 100,000 */
    size_t max_millis;    /* wall-clock backstop per check; default 10,000 ms */
    size_t max_memory;    /* evaluator bytes per check; default 64 MiB */
} YogLimits;

/* "ALLOW", "DENY" or "REQUIRE_APPROVAL" ("UNKNOWN" for any other value). */
YOG_API const char *yog_decision_name(YogDecision decision);

/* Version of the loaded library, e.g. "0.2.0-alpha.1".  Compare with
 * YOG_VERSION_STRING to detect a header/library mismatch. */
YOG_API const char *yog_version(void);

/* Compile a policy.  Returns NULL on error and fills `error`. */
YOG_API Yog *yog_compile(const char *source, size_t length, YogError *error);

YOG_API void yog_free(Yog *yog);

/* Language version the policy declared with `version N` (1 when absent). */
YOG_API int yog_policy_version(const Yog *yog);

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
 *   deny > require_approval > allow > default deny.
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
