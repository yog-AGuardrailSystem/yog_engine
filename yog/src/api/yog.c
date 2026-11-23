/*
 * yog.c -- the compiler facade.
 *
 * Pipeline: source -> lexer -> parser -> semantic analyser -> IR -> engine.
 *
 * This file is the only place that knows all the stages.  Each stage keeps
 * its own ownership rules, and this facade is responsible for unwinding them
 * on every failure path (a compile error must never leak a partial AST, IR or
 * engine).
 */
#include "api/yog.h"
#include "api/yog_internal.h"

#include <stdlib.h>
#include <string.h>

#include "ir/ir.h"
#include "lexer/lexer.h"
#include "parser/parser.h"
#include "sema/sema.h"
#include "vm/vm.h"

struct Yog {
    char        *source;
    size_t       source_length;
    YogProgram  *program;
    YogModule   *module;

    /* Configuration only.  The evaluator is created per request so that the
     * immutable module can be shared between threads without locking. */
    YogLimits    limits;
};

static YogLimits default_limits(void);

static char *copy_text(const char *text, size_t length)
{
    char *copy = malloc(length + 1);
    if (copy == NULL) return NULL;
    if (length > 0) memcpy(copy, text, length);
    copy[length] = '\0';
    return copy;
}

static bool fail(YogError *error, int line, int column, const char *fmt, const char *detail)
{
    if (error != NULL) {
        error->line = line;
        error->column = column;
        if (detail != NULL) (void)snprintf(error->message, sizeof(error->message), fmt, detail);
        else (void)snprintf(error->message, sizeof(error->message), "%s", fmt);
    }
    return false;
}

static bool parse_source(const char *source, size_t length, YogProgram **out_program,
                         YogError *error)
{
    Lexer lexer;
    YogParseError parse_error;
    YogParseStatus status;

    lexer_init(&lexer, source, length);
    status = yog_parse(&lexer, out_program, &parse_error);
    if (status != YOG_PARSE_OK) {
        (void)fail(error, parse_error.line, parse_error.column, "%s", parse_error.message);
        return false;
    }
    return true;
}

Yog *yog_compile(const char *source, size_t length, YogError *error)
{
    Yog *yog;
    YogSemaError sema_error;
    YogIRError ir_error;
    YogSymbolTable symbols;

    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (source == NULL) {
        (void)fail(error, 0, 0, "source must not be NULL", NULL);
        return NULL;
    }

    yog = calloc(1, sizeof(*yog));
    if (yog == NULL) {
        (void)fail(error, 0, 0, "out of memory allocating the compiler", NULL);
        return NULL;
    }
    yog->source = copy_text(source, length);
    yog->source_length = length;
    if (yog->source == NULL) {
        (void)fail(error, 0, 0, "out of memory copying the source", NULL);
        yog_free(yog);
        return NULL;
    }

    if (!parse_source(yog->source, yog->source_length, &yog->program, error)) {
        yog_free(yog);
        return NULL;
    }

    yog_symbol_table_init(&symbols);
    if (!yog_sema_check(yog->program, &symbols, &sema_error)) {
        (void)fail(error, sema_error.line, sema_error.column, "%s", sema_error.message);
        yog_symbol_table_free(&symbols);
        yog_free(yog);
        return NULL;
    }

    if (!yog_ir_build(yog->program, &symbols, yog->source, &yog->module, &ir_error)) {
        (void)fail(error, ir_error.line, ir_error.column, "%s", ir_error.message);
        yog_symbol_table_free(&symbols);
        yog_free(yog);
        return NULL;
    }
    yog_symbol_table_free(&symbols);

    yog->limits = default_limits();
    return yog;
}

void yog_free(Yog *yog)
{
    if (yog == NULL) return;
    yog_ir_free(yog->module);
    yog_program_free(yog->program);
    free(yog->source);
    free(yog);
}

const YogModule *yog_module(const Yog *yog)
{
    return yog == NULL ? NULL : yog->module;
}

static YogLimits default_limits(void)
{
    YogLimits limits;
    limits.max_steps = YOG_VM_MAX_STEPS;
    limits.max_depth = YOG_VM_MAX_DEPTH;
    limits.max_solutions = YOG_VM_MAX_SOLUTIONS;
    limits.max_millis = YOG_VM_MAX_MILLIS;
    limits.max_memory = YOG_VM_MAX_MEMORY;
    return limits;
}

void yog_set_limits(Yog *yog, YogLimits limits)
{
    YogLimits defaults = default_limits();
    if (yog == NULL) return;
    yog->limits.max_steps = limits.max_steps == 0 ? defaults.max_steps : limits.max_steps;
    yog->limits.max_depth = limits.max_depth <= 0 ? defaults.max_depth : limits.max_depth;
    yog->limits.max_solutions = limits.max_solutions == 0 ? defaults.max_solutions : limits.max_solutions;
    yog->limits.max_millis = limits.max_millis == 0 ? defaults.max_millis : limits.max_millis;
    yog->limits.max_memory = limits.max_memory == 0 ? defaults.max_memory : limits.max_memory;
}

const char *yog_version(void)
{
    return YOG_VERSION_STRING;
}

const char *yog_decision_name(YogDecision decision)
{
    switch (decision) {
    case YOG_ALLOW: return "ALLOW";
    case YOG_DENY: return "DENY";
    case YOG_REQUIRE_APPROVAL: return "REQUIRE_APPROVAL";
    default: return "UNKNOWN";
    }
}

int yog_policy_version(const Yog *yog)
{
    return (yog == NULL || yog->module == NULL) ? 1 : yog->module->language_version;
}

YogLimits yog_get_limits(const Yog *yog)
{
    return yog == NULL ? default_limits() : yog->limits;
}

static void apply_limits(YogEngine *engine, const YogLimits *limits)
{
    YogEngineLimits engine_limits;
    engine_limits.max_steps = limits->max_steps;
    engine_limits.max_depth = limits->max_depth;
    engine_limits.max_solutions = limits->max_solutions;
    engine_limits.max_millis = limits->max_millis;
    engine_limits.max_memory = limits->max_memory;
    yog_engine_set_limits(engine, engine_limits);
}

/* Parse the optional per-request context ("fact a(b); fact c(d)"). */
static YogModule *compile_context(const char *text, char **owned_source, YogError *error)
{
    char *normalized;
    size_t length;
    size_t i;
    YogProgram *program = NULL;
    YogSymbolTable symbols;
    YogSemaError sema_error;
    YogIRError ir_error;
    YogModule *module = NULL;

    *owned_source = NULL;
    length = strlen(text);
    normalized = copy_text(text, length);
    if (normalized == NULL) {
        (void)fail(error, 0, 0, "out of memory copying the request context", NULL);
        return NULL;
    }
    /* ';' separates facts.  Blank out the spaces that usually follow it as well,
     * otherwise "fact a(b); fact c(d)" would read the second fact as indented. */
    for (i = 0; i < length; ++i) {
        if (normalized[i] != ';') continue;
        normalized[i] = '\n';
        while (i + 1 < length && (normalized[i + 1] == ' ' || normalized[i + 1] == '\t'))
            normalized[++i] = '\n';
    }

    /* The first statement may arrive with leading whitespace (for example the
     * space after a '|' in `yogc batch`).  Strip only that prefix: indentation
     * inside the string is left intact so that a non-fact statement is still
     * parsed and rejected by the fact-only check below. */
    {
        size_t start = 0;
        while (start < length && (normalized[start] == ' ' || normalized[start] == '\t'))
            start++;
        if (start > 0) {
            memmove(normalized, normalized + start, length - start + 1);
            length -= start;
        }
    }
    *owned_source = normalized;

    if (!parse_source(normalized, length, &program, error)) return NULL;

    for (i = 0; i < program->statement_count; ++i) {
        if (program->statements[i].type != YOG_STATEMENT_FACT) {
            (void)fail(error, program->statements[i].line, program->statements[i].column,
                       "request context may only contain fact statements", NULL);
            yog_program_free(program);
            return NULL;
        }
    }

    yog_symbol_table_init(&symbols);
    if (!yog_sema_check(program, &symbols, &sema_error)) {
        (void)fail(error, sema_error.line, sema_error.column, "%s", sema_error.message);
        yog_symbol_table_free(&symbols);
        yog_program_free(program);
        return NULL;
    }
    if (!yog_ir_build(program, &symbols, normalized, &module, &ir_error)) {
        (void)fail(error, ir_error.line, ir_error.column, "%s", ir_error.message);
        module = NULL;
    }
    yog_symbol_table_free(&symbols);
    yog_program_free(program);
    return module;
}

/* Deep-copies the engine's obligations into the public result. */
static bool copy_obligations(const YogEngineResult *from, YogResult *to)
{
    size_t i;
    to->obligations = NULL;
    to->obligation_count = 0;
    if (from->obligation_count == 0) return true;
    to->obligations = calloc(from->obligation_count, sizeof(*to->obligations));
    if (to->obligations == NULL) return false;
    for (i = 0; i < from->obligation_count; ++i) {
        const YogEngineObligation *src = &from->obligations[i];
        YogObligation *dst = &to->obligations[i];
        size_t a;
        to->obligation_count = i + 1;
        dst->name = copy_text(src->name, strlen(src->name));
        if (dst->name == NULL) return false;
        dst->args = src->arg_count == 0 ? NULL : calloc(src->arg_count, sizeof(*dst->args));
        if (src->arg_count > 0 && dst->args == NULL) return false;
        dst->arg_count = src->arg_count;
        for (a = 0; a < src->arg_count; ++a) {
            dst->args[a].kind = (YogObligationArgKind)src->args[a].kind;
            dst->args[a].integer = (long long)src->args[a].integer;
            if (src->args[a].kind == 0) {
                dst->args[a].text = copy_text(src->args[a].text, strlen(src->args[a].text));
                if (dst->args[a].text == NULL) return false;
            }
        }
    }
    return true;
}

bool yog_check(Yog *yog, const char *actor, const char *action, const char *resource,
               const char *context, bool trace, YogResult *result, YogError *error)
{
    YogModule *context_module = NULL;
    char *context_source = NULL;
    bool ok;

    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        /* Fail closed even if the caller ignores the false return value. */
        result->decision = YOG_DENY;
    }
    if (yog == NULL || result == NULL) {
        return fail(error, 0, 0, "yog_check() received a null argument", NULL);
    }

    if (context != NULL && context[0] != '\0') {
        context_module = compile_context(context, &context_source, error);
        if (context_module == NULL) {
            free(context_source);
            return false;
        }
    }

    ok = yog_check_with_context_module(yog, actor, action, resource, context_module, trace,
                                       result, error);
    yog_ir_free(context_module);
    free(context_source);
    return ok;
}

bool yog_check_with_context_module(Yog *yog, const char *actor, const char *action,
                                   const char *resource, const YogModule *context_module,
                                   bool trace, YogResult *result, YogError *error)
{
    YogEngine *engine = NULL;
    YogEngineResult engine_result;
    YogEvalError eval_error;
    bool ok;

    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->decision = YOG_DENY;
    }
    if (yog == NULL || result == NULL || actor == NULL || action == NULL || resource == NULL)
        return fail(error, 0, 0, "yog_check() received a null argument", NULL);

    memset(&engine_result, 0, sizeof(engine_result));
    memset(&eval_error, 0, sizeof(eval_error));
    engine = yog_engine_create(yog->module, &eval_error);
    if (engine == NULL) {
        (void)fail(error, 0, 0, "%s", eval_error.message);
        return false;
    }
    apply_limits(engine, &yog->limits);

    ok = yog_engine_check(engine, actor, action, resource, context_module,
                          trace, &engine_result, &eval_error);
    yog_engine_free(engine);

    if (!ok) {
        (void)fail(error, eval_error.line, eval_error.column, "%s", eval_error.message);
        yog_engine_result_free(&engine_result);
        return false;
    }

    /* Map verdicts explicitly: an unknown verdict is an error, never a silent DENY
     * or, worse, a silent ALLOW. */
    switch (engine_result.decision) {
    case YOG_VERDICT_ALLOW: result->decision = YOG_ALLOW; break;
    case YOG_VERDICT_DENY: result->decision = YOG_DENY; break;
    case YOG_VERDICT_REQUIRE_APPROVAL: result->decision = YOG_REQUIRE_APPROVAL; break;
    default:
        yog_engine_result_free(&engine_result);
        return fail(error, 0, 0, "internal error: unknown evaluation verdict", NULL);
    }
    if (!copy_obligations(&engine_result, result)) {
        yog_engine_result_free(&engine_result);
        result->decision = YOG_DENY;
        return fail(error, 0, 0, "out of memory copying obligations", NULL);
    }
    result->matched_line = engine_result.matched_line;
    result->reason = engine_result.reason;
    result->trace = engine_result.trace;
    engine_result.reason = NULL;
    engine_result.trace = NULL;
    yog_engine_result_free(&engine_result);
    return true;
}

bool yog_run_queries(Yog *yog, FILE *out, bool trace)
{
    YogEvalError eval_error;
    YogEngine *engine;
    bool ok;

    if (yog == NULL || out == NULL) return false;
    engine = yog_engine_create(yog->module, &eval_error);
    if (engine == NULL) return false;
    apply_limits(engine, &yog->limits);
    ok = yog_engine_run_queries(engine, NULL, out, trace, &eval_error);
    yog_engine_free(engine);
    return ok;
}

void yog_result_free(YogResult *result)
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
