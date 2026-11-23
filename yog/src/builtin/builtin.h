/*
 * builtin.h -- built-in predicates available to every policy.
 *
 * Built-ins are pure functions of their arguments.  They never read a clock,
 * the file system or the network, never allocate unboundedly, and never loop
 * unboundedly, so a policy that uses them stays deterministic and fail-closed.
 *
 *   in(X, V1, V2, ...)       X equals one of the listed values
 *   matches(Text, Pattern)   linear-time regular expression, searched anywhere
 *   glob(Text, Pattern)      whole-string match, '*' any run, '?' any one char
 *   under(Path, Prefix)      normalised path is Prefix or lies below it
 *   starts_with(Text, S)     byte prefix
 *   ends_with(Text, S)       byte suffix
 *   contains(Text, S)        byte substring
 *   cidr(Ip, Network)        IPv4 address inside a.b.c.d/n
 *
 * The same table drives the semantic analyser (name/arity checks), the IR
 * builder and the evaluator, so the three can never disagree.
 */
#ifndef YOG_BUILTIN_H
#define YOG_BUILTIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    YOG_BUILTIN_NONE = 0,
    YOG_BUILTIN_IN,
    YOG_BUILTIN_MATCHES,
    YOG_BUILTIN_GLOB,
    YOG_BUILTIN_UNDER,
    YOG_BUILTIN_STARTS_WITH,
    YOG_BUILTIN_ENDS_WITH,
    YOG_BUILTIN_CONTAINS,
    YOG_BUILTIN_CIDR
} YogBuiltinId;

typedef enum { YOG_ARG_TEXT = 0, YOG_ARG_INTEGER = 1, YOG_ARG_BOOLEAN = 2 } YogArgKind;

typedef struct {
    YogArgKind  kind;
    const char *text;     /* TEXT: not NUL-terminated */
    size_t      length;
    int64_t     integer;  /* INTEGER value, or 0/1 for BOOLEAN */
} YogBuiltinArg;

/* Limits that keep every built-in bounded (also documented in docs/SPEC.md). */
#define YOG_BUILTIN_MAX_PATTERN 256u
#define YOG_BUILTIN_MAX_TEXT    4096u

/* Returns YOG_BUILTIN_NONE when name/arity is not a built-in. */
YogBuiltinId yog_builtin_find(const char *name, size_t length, size_t arity);
const char  *yog_builtin_name(YogBuiltinId id);

/*
 * Evaluates one built-in.  Returns true and sets *result on success.  Returns
 * false and fills `message` on an evaluation error (wrong argument kind, an
 * invalid pattern, input over a size limit); callers must treat that as DENY.
 */
bool yog_builtin_eval(YogBuiltinId id, const YogBuiltinArg *args, size_t count,
                      bool *result, char *message, size_t message_size);

#endif /* YOG_BUILTIN_H */
