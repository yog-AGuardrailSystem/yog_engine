/*
 * request.c -- JSON requests and JSON results.
 *
 * A JSON request is turned into typed facts WITHOUT going through the text
 * context syntax.  Request values are attacker-influenced (tool arguments,
 * file paths, SQL), so they must never be spliced into policy text: a value
 * containing a quote or a semicolon could otherwise forge extra facts.  Here a
 * value is only ever a typed constant in the AST.
 *
 * Flattening rules (see docs/INTERFACES.md):
 *   "args":  {k: v}   ->  arg("k", v)          nested objects use dotted keys "a.b"
 *   "env":   {k: v}   ->  env("k", v)          arrays give one fact per element
 *   "state": {"version": n, "values": {k: v}}  ->  state_version(n), state("k", v)
 *   "now":   n        ->  now(n)
 *   "facts": [{"predicate": p, "args": [..]}]  ->  p(..)
 * A policy reads these facts by declaring matching `input` predicates.
 */
#include "api/yog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api/json.h"
#include "api/yog_internal.h"
#include "ir/ir.h"
#include "parser/ast.h"
#include "sema/sema.h"

#define MAX_FACTS      4096u
#define MAX_FACT_ARGS  16u
#define MAX_KEY_DEPTH  8u

typedef struct {
    YogProgram *program;
    char      **pool;          /* strings whose slices the AST points into */
    size_t      pool_count;
    size_t      pool_capacity;
    char        message[192];
} Builder;

static bool builder_fail(Builder *b, const char *fmt, const char *detail)
{
    if (b->message[0] == '\0') {
        if (detail != NULL) (void)snprintf(b->message, sizeof(b->message), fmt, detail);
        else (void)snprintf(b->message, sizeof(b->message), "%s", fmt);
    }
    return false;
}

static char *pool_copy(Builder *b, const char *text, size_t length)
{
    char *copy;
    if (b->pool_count == b->pool_capacity) {
        size_t next = b->pool_capacity == 0 ? 16 : b->pool_capacity * 2;
        char **grown = realloc(b->pool, next * sizeof(*grown));
        if (grown == NULL) { (void)builder_fail(b, "out of memory", NULL); return NULL; }
        b->pool = grown;
        b->pool_capacity = next;
    }
    copy = malloc(length + 1);
    if (copy == NULL) { (void)builder_fail(b, "out of memory", NULL); return NULL; }
    if (length > 0) memcpy(copy, text, length);
    copy[length] = '\0';
    b->pool[b->pool_count++] = copy;
    return copy;
}

static bool is_scalar(const YogJson *v)
{
    return v->kind == YOG_JSON_STRING || v->kind == YOG_JSON_INT || v->kind == YOG_JSON_BOOL;
}

static bool scalar_term(Builder *b, const YogJson *v, const char *where, int line, YogTerm *out)
{
    memset(out, 0, sizeof(*out));
    out->line = line;
    out->column = 1;
    switch (v->kind) {
    case YOG_JSON_STRING:
        out->type = YOG_TERM_STRING;
        out->text.text = v->string;
        out->text.length = v->string_length;
        return true;
    case YOG_JSON_INT:
        out->type = YOG_TERM_INTEGER;
        out->integer_value = v->integer;
        return true;
    case YOG_JSON_BOOL:
        out->type = YOG_TERM_BOOLEAN;
        out->integer_value = v->boolean ? 1 : 0;
        return true;
    case YOG_JSON_FLOAT:
        return builder_fail(b, "%s: numbers with a fraction or exponent are not supported (use an integer or a string)", where);
    case YOG_JSON_NULL:
        return builder_fail(b, "%s: null is not supported (omit the field)", where);
    default:
        return builder_fail(b, "%s: expected a string, integer or boolean", where);
    }
}

static bool add_fact(Builder *b, const char *predicate, const YogTerm *terms, size_t count)
{
    YogStatement statement;
    YogText name;
    if (b->program->statement_count >= MAX_FACTS)
        return builder_fail(b, "request has more than %s facts", "4096");
    memset(&statement, 0, sizeof(statement));
    statement.type = YOG_STATEMENT_FACT;
    statement.line = (int)b->program->statement_count + 1;
    statement.column = 1;
    name.text = predicate;
    name.length = strlen(predicate);
    if (!yog_atom_init(&statement.as.fact, name, terms, count, statement.line, 1))
        return builder_fail(b, "out of memory", NULL);
    if (!yog_program_append_statement(b->program, &statement)) {
        yog_statement_free(&statement);
        return builder_fail(b, "out of memory", NULL);
    }
    return true;
}

/* predicate("key", value) */
static bool add_pair(Builder *b, const char *predicate, const char *key, size_t key_length,
                     const YogJson *value, const char *where)
{
    YogTerm terms[2];
    int line = (int)b->program->statement_count + 1;
    memset(terms, 0, sizeof(terms));
    terms[0].type = YOG_TERM_STRING;
    terms[0].text.text = key;
    terms[0].text.length = key_length;
    terms[0].line = line;
    terms[0].column = 1;
    if (!scalar_term(b, value, where, line, &terms[1])) return false;
    return add_fact(b, predicate, terms, 2);
}

static bool flatten_object(Builder *b, const char *predicate, const char *prefix,
                           const YogJson *object, unsigned depth, const char *where)
{
    size_t i, prefix_length = prefix == NULL ? 0 : strlen(prefix);
    if (depth > MAX_KEY_DEPTH) return builder_fail(b, "%s: objects are nested too deeply", where);
    for (i = 0; i < object->count; ++i) {
        const YogJson *value = &object->items[i];
        const char *key = object->keys[i];
        size_t key_length = strlen(key);
        char *path;
        if (prefix_length == 0) {
            path = pool_copy(b, key, key_length);
        } else {
            char *joined = malloc(prefix_length + 1 + key_length + 1);
            if (joined == NULL) { (void)builder_fail(b, "out of memory", NULL); return false; }
            memcpy(joined, prefix, prefix_length);
            joined[prefix_length] = '.';
            memcpy(joined + prefix_length + 1, key, key_length);
            joined[prefix_length + 1 + key_length] = '\0';
            path = pool_copy(b, joined, prefix_length + 1 + key_length);
            free(joined);
        }
        if (path == NULL) return false;
        if (value->kind == YOG_JSON_OBJECT) {
            if (!flatten_object(b, predicate, path, value, depth + 1, where)) return false;
        } else if (value->kind == YOG_JSON_ARRAY) {
            size_t k;
            for (k = 0; k < value->count; ++k) {
                if (!is_scalar(&value->items[k]) && value->items[k].kind != YOG_JSON_FLOAT &&
                    value->items[k].kind != YOG_JSON_NULL)
                    return builder_fail(b, "%s: arrays may only contain strings, integers or booleans", where);
                if (!add_pair(b, predicate, path, strlen(path), &value->items[k], where)) return false;
            }
        } else if (!add_pair(b, predicate, path, strlen(path), value, where)) {
            return false;
        }
    }
    return true;
}

static bool is_identifier(const char *s)
{
    size_t i;
    if (s == NULL || s[0] < 'a' || s[0] > 'z') return false;
    for (i = 1; s[i] != '\0'; ++i) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return i <= 64;
}

static bool add_generic_facts(Builder *b, const YogJson *facts)
{
    size_t i;
    if (facts->kind != YOG_JSON_ARRAY) return builder_fail(b, "\"facts\" must be an array", NULL);
    for (i = 0; i < facts->count; ++i) {
        const YogJson *entry = &facts->items[i];
        const YogJson *predicate = yog_json_member(entry, "predicate");
        const YogJson *args = yog_json_member(entry, "args");
        YogTerm terms[MAX_FACT_ARGS];
        size_t a, field;
        if (entry->kind != YOG_JSON_OBJECT || predicate == NULL || predicate->kind != YOG_JSON_STRING ||
            args == NULL || args->kind != YOG_JSON_ARRAY)
            return builder_fail(b, "each fact needs a \"predicate\" string and an \"args\" array", NULL);
        for (field = 0; field < entry->count; ++field)
            if (strcmp(entry->keys[field], "predicate") != 0 && strcmp(entry->keys[field], "args") != 0)
                return builder_fail(b, "unknown field \"%s\" in a fact", entry->keys[field]);
        if (!is_identifier(predicate->string))
            return builder_fail(b, "invalid predicate name \"%s\"", predicate->string);
        if (args->count == 0 || args->count > MAX_FACT_ARGS)
            return builder_fail(b, "a fact needs between 1 and %s arguments", "16");
        {
            char *name = pool_copy(b, predicate->string, predicate->string_length);
            if (name == NULL) return false;
            for (a = 0; a < args->count; ++a)
                if (!scalar_term(b, &args->items[a], "facts", (int)b->program->statement_count + 1, &terms[a]))
                    return false;
            if (!add_fact(b, name, terms, args->count)) return false;
        }
    }
    return true;
}

static bool add_integer_fact(Builder *b, const char *predicate, const YogJson *value, const char *where)
{
    YogTerm term;
    if (value->kind != YOG_JSON_INT) return builder_fail(b, "%s must be an integer", where);
    if (!scalar_term(b, value, where, (int)b->program->statement_count + 1, &term)) return false;
    return add_fact(b, predicate, &term, 1);
}

static const char *string_field(Builder *b, const YogJson *root, const char *name)
{
    const YogJson *v = yog_json_member(root, name);
    if (v == NULL || v->kind != YOG_JSON_STRING) {
        (void)builder_fail(b, "request needs a string field \"%s\"", name);
        return NULL;
    }
    return v->string;
}

static bool build_facts(Builder *b, const YogJson *root)
{
    size_t i;
    const YogJson *v;
    for (i = 0; i < root->count; ++i) {
        const char *key = root->keys[i];
        if (strcmp(key, "actor") && strcmp(key, "action") && strcmp(key, "resource") && strcmp(key, "args") &&
            strcmp(key, "env") && strcmp(key, "state") && strcmp(key, "now") && strcmp(key, "facts") &&
            strcmp(key, "request_id"))
            return builder_fail(b, "unknown request field \"%s\"", key);
    }
    if ((v = yog_json_member(root, "args")) != NULL) {
        if (v->kind != YOG_JSON_OBJECT) return builder_fail(b, "\"args\" must be an object", NULL);
        if (!flatten_object(b, "arg", NULL, v, 0, "args")) return false;
    }
    if ((v = yog_json_member(root, "env")) != NULL) {
        if (v->kind != YOG_JSON_OBJECT) return builder_fail(b, "\"env\" must be an object", NULL);
        if (!flatten_object(b, "env", NULL, v, 0, "env")) return false;
    }
    if ((v = yog_json_member(root, "state")) != NULL) {
        const YogJson *version = yog_json_member(v, "version");
        const YogJson *values = yog_json_member(v, "values");
        size_t k;
        if (v->kind != YOG_JSON_OBJECT) return builder_fail(b, "\"state\" must be an object", NULL);
        for (k = 0; k < v->count; ++k)
            if (strcmp(v->keys[k], "version") != 0 && strcmp(v->keys[k], "values") != 0)
                return builder_fail(b, "unknown field \"%s\" in state", v->keys[k]);
        if (version != NULL && !add_integer_fact(b, "state_version", version, "state.version")) return false;
        if (values != NULL) {
            if (values->kind != YOG_JSON_OBJECT) return builder_fail(b, "\"state.values\" must be an object", NULL);
            if (!flatten_object(b, "state", NULL, values, 0, "state.values")) return false;
        }
    }
    if ((v = yog_json_member(root, "now")) != NULL && !add_integer_fact(b, "now", v, "\"now\"")) return false;
    if ((v = yog_json_member(root, "facts")) != NULL && !add_generic_facts(b, v)) return false;
    if ((v = yog_json_member(root, "request_id")) != NULL && v->kind != YOG_JSON_STRING)
        return builder_fail(b, "\"request_id\" must be a string", NULL);
    return true;
}

static void builder_free(Builder *b)
{
    size_t i;
    yog_program_free(b->program);
    for (i = 0; i < b->pool_count; ++i) free(b->pool[i]);
    free(b->pool);
    memset(b, 0, sizeof(*b));
}

bool yog_check_json(Yog *yog, const char *json, size_t length, bool trace,
                    YogResult *result, YogError *error)
{
    char message[192];
    YogJson *root = NULL;
    Builder builder;
    YogSymbolTable symbols;
    YogSemaError sema_error;
    YogIRError ir_error;
    YogModule *context = NULL;
    const char *actor, *action, *resource;
    bool ok = false;

    if (error != NULL) { error->line = 0; error->column = 0; error->message[0] = '\0'; }
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->decision = YOG_DENY;       /* fail closed even if the caller ignores the return value */
    }
    if (yog == NULL || result == NULL || json == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "yog_check_json() received a null argument");
        return false;
    }

    root = yog_json_parse(json, length, message, sizeof(message));
    if (root == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "%s", message);
        return false;
    }
    memset(&builder, 0, sizeof(builder));
    builder.program = calloc(1, sizeof(*builder.program));
    if (builder.program == NULL) {
        if (error != NULL) (void)snprintf(error->message, sizeof(error->message), "out of memory");
        yog_json_free(root);
        return false;
    }
    if (root->kind != YOG_JSON_OBJECT) {
        (void)builder_fail(&builder, "request must be a JSON object", NULL);
        goto done;
    }
    actor = string_field(&builder, root, "actor");
    action = actor == NULL ? NULL : string_field(&builder, root, "action");
    resource = action == NULL ? NULL : string_field(&builder, root, "resource");
    if (resource == NULL || !build_facts(&builder, root)) goto done;

    yog_symbol_table_init(&symbols);
    if (!yog_sema_check(builder.program, &symbols, &sema_error)) {
        (void)snprintf(builder.message, sizeof(builder.message), "request facts: %s", sema_error.message);
        goto done;
    }
    if (!yog_ir_build(builder.program, &symbols, "", &context, &ir_error)) {
        (void)snprintf(builder.message, sizeof(builder.message), "request facts: %s", ir_error.message);
        yog_symbol_table_free(&symbols);
        goto done;
    }
    yog_symbol_table_free(&symbols);

    ok = yog_check_with_context_module(yog, actor, action, resource, context, trace, result, error);
    yog_ir_free(context);
    builder_free(&builder);
    yog_json_free(root);
    return ok;

done:
    if (error != NULL && builder.message[0] != '\0')
        (void)snprintf(error->message, sizeof(error->message), "%s", builder.message);
    builder_free(&builder);
    yog_json_free(root);
    return false;
}

/* ------------------------------------------------------------- JSON results */

typedef struct {
    char  *data;
    size_t length;
    size_t capacity;
    bool   failed;
} Sb;

static void sb_append(Sb *sb, const char *text, size_t length)
{
    if (sb->failed) return;
    if (sb->length + length + 1 > sb->capacity) {
        size_t next = sb->capacity == 0 ? 256 : sb->capacity;
        char *grown;
        while (next < sb->length + length + 1) next *= 2;
        grown = realloc(sb->data, next);
        if (grown == NULL) { sb->failed = true; return; }
        sb->data = grown;
        sb->capacity = next;
    }
    memcpy(sb->data + sb->length, text, length);
    sb->length += length;
    sb->data[sb->length] = '\0';
}

static void sb_text(Sb *sb, const char *text) { sb_append(sb, text, strlen(text)); }

static void sb_json_string(Sb *sb, const char *text)
{
    const unsigned char *p = (const unsigned char *)(text == NULL ? "" : text);
    sb_text(sb, "\"");
    while (*p) {
        char buffer[8];
        if (*p == '"') { sb_text(sb, "\\\""); p++; }
        else if (*p == '\\') { sb_text(sb, "\\\\"); p++; }
        else if (*p == '\n') { sb_text(sb, "\\n"); p++; }
        else if (*p == '\r') { sb_text(sb, "\\r"); p++; }
        else if (*p == '\t') { sb_text(sb, "\\t"); p++; }
        else if (*p < 0x20) { (void)snprintf(buffer, sizeof(buffer), "\\u%04x", *p); sb_text(sb, buffer); p++; }
        else if (*p < 0x80) { sb_append(sb, (const char *)p, 1); p++; }
        else {
            size_t n = yog_utf8_sequence_length(p, strlen((const char *)p));
            if (n == 0) { sb_text(sb, "\\ufffd"); p++; }     /* never emit invalid UTF-8 */
            else { sb_append(sb, (const char *)p, n); p += n; }
        }
    }
    sb_text(sb, "\"");
}

char *yog_result_to_json(const Yog *yog, const YogResult *result)
{
    Sb sb;
    size_t i;
    char number[48];
    if (result == NULL) return NULL;
    memset(&sb, 0, sizeof(sb));
    sb_text(&sb, "{\"decision\":");
    sb_json_string(&sb, yog_decision_name(result->decision));
    sb_text(&sb, ",\"reason\":");
    sb_json_string(&sb, result->reason);
    (void)snprintf(number, sizeof(number), ",\"matched_line\":%d", result->matched_line);
    sb_text(&sb, number);
    if (yog != NULL) {
        (void)snprintf(number, sizeof(number), ",\"policy_version\":%d", yog_policy_version(yog));
        sb_text(&sb, number);
    }
    sb_text(&sb, ",\"obligations\":[");
    for (i = 0; i < result->obligation_count; ++i) {
        const YogObligation *o = &result->obligations[i];
        size_t a;
        if (i > 0) sb_text(&sb, ",");
        sb_text(&sb, "{\"name\":");
        sb_json_string(&sb, o->name);
        sb_text(&sb, ",\"args\":[");
        for (a = 0; a < o->arg_count; ++a) {
            if (a > 0) sb_text(&sb, ",");
            if (o->args[a].kind == YOG_OBLIGATION_INTEGER) {
                (void)snprintf(number, sizeof(number), "%lld", o->args[a].integer);
                sb_text(&sb, number);
            } else if (o->args[a].kind == YOG_OBLIGATION_BOOLEAN) {
                sb_text(&sb, o->args[a].integer != 0 ? "true" : "false");
            } else {
                sb_json_string(&sb, o->args[a].text);
            }
        }
        sb_text(&sb, "]}");
    }
    sb_text(&sb, "]");
    if (result->trace != NULL) {
        sb_text(&sb, ",\"trace\":");
        sb_json_string(&sb, result->trace);
    }
    sb_text(&sb, "}");
    if (sb.failed) { free(sb.data); return NULL; }
    return sb.data;
}

char *yog_error_to_json(const YogError *error)
{
    Sb sb;
    char number[48];
    memset(&sb, 0, sizeof(sb));
    sb_text(&sb, "{\"error\":{\"message\":");
    sb_json_string(&sb, error == NULL ? "unknown error" : error->message);
    if (error != NULL) {
        (void)snprintf(number, sizeof(number), ",\"line\":%d,\"column\":%d", error->line, error->column);
        sb_text(&sb, number);
    }
    sb_text(&sb, "}}");
    if (sb.failed) { free(sb.data); return NULL; }
    return sb.data;
}

void yog_string_free(char *text)
{
    free(text);
}
