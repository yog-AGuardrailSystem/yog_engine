/*
 * yog_internal.h -- helpers shared by the API translation units
 * (yog.c, request.c).  Not part of the public ABI.
 */
#ifndef YOG_INTERNAL_H
#define YOG_INTERNAL_H

#include "api/yog.h"
#include "ir/ir.h"

/*
 * Checks one request against an already-built context module (the per-request
 * facts).  `context` may be NULL and is not consumed.  Same contract as
 * yog_check(): false means an evaluation error and the result is DENY.
 */
bool yog_check_with_context_module(Yog *yog, const char *actor, const char *action,
                                   const char *resource, const YogModule *context,
                                   bool trace, YogResult *result, YogError *error);

#endif /* YOG_INTERNAL_H */
