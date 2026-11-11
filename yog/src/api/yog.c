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
    YogEngine   *engine;
};

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
    YogEvalError eval_error;

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

    yog->engine = yog_engine_create(yog->module, &eval_error);
    if (yog->engine == NULL) {
        (void)fail(error, 0, 0, "%s", eval_error.message);
        yog_free(yog);
        return NULL;
    }
    return yog;
}

void yog_free(Yog *yog)
{
    if (yog == NULL) return;
    yog_engine_free(yog->engine);
    yog_ir_free(yog->module);
    yog_program_free(yog->program);
    free(yog->source);
    free(yog);
}

const YogModule *yog_module(const Yog *yog)
{
    return yog == NULL ? NULL : yog->module;
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
    for (i = 0; i < length; ++i)
        if (normalized[i] == ';') normalized[i] = '\n';
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

bool yog_check(Yog *yog, const char *actor, const char *action, const char *resource,
               const char *context, bool trace, YogResult *result, YogError *error)
{
    YogModule *context_module = NULL;
    char *context_source = NULL;
    YogEngineResult engine_result;
    YogEvalError eval_error;
    bool ok;

    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (yog == NULL || result == NULL) {
        return fail(error, 0, 0, "yog_check() received a null argument", NULL);
    }
    memset(result, 0, sizeof(*result));

    if (context != NULL && context[0] != '\0') {
        context_module = compile_context(context, &context_source, error);
        if (context_module == NULL) {
            free(context_source);
            return false;
        }
    }

    memset(&engine_result, 0, sizeof(engine_result));
    ok = yog_engine_check(yog->engine, actor, action, resource, context_module,
                          trace, &engine_result, &eval_error);
    yog_ir_free(context_module);
    free(context_source);

    if (!ok) {
        (void)fail(error, eval_error.line, eval_error.column, "%s", eval_error.message);
        return false;
    }

    result->decision = engine_result.decision == YOG_VERDICT_ALLOW ? YOG_ALLOW : YOG_DENY;
    result->reason = engine_result.reason;
    result->trace = engine_result.trace;
    return true;
}

bool yog_run_queries(Yog *yog, FILE *out, bool trace)
{
    YogEvalError eval_error;
    if (yog == NULL || out == NULL) return false;
    return yog_engine_run_queries(yog->engine, NULL, out, trace, &eval_error);
}

void yog_result_free(YogResult *result)
{
    if (result == NULL) return;
    free(result->reason);
    free(result->trace);
    result->reason = NULL;
    result->trace = NULL;
}
