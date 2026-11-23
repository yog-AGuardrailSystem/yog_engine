/*
 * json.c -- strict JSON reader (see json.h).
 */
#include "api/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const unsigned char *p;
    size_t               length;
    size_t               pos;
    size_t               nodes;
    char                *message;
    size_t               message_size;
    bool                 failed;
} Reader;

static void *fail(Reader *r, const char *what)
{
    if (!r->failed) {
        r->failed = true;
        if (r->message != NULL && r->message_size > 0)
            (void)snprintf(r->message, r->message_size, "json: %s at offset %zu", what, r->pos);
    }
    return NULL;
}

static void skip_space(Reader *r)
{
    while (r->pos < r->length &&
           (r->p[r->pos] == ' ' || r->p[r->pos] == '\t' || r->p[r->pos] == '\n' || r->p[r->pos] == '\r'))
        r->pos++;
}

/* Frees a value's owned memory without freeing the struct itself. */
static void release(YogJson *value)
{
    size_t i;
    if (value == NULL) return;
    for (i = 0; i < value->count; ++i) {
        release(&value->items[i]);
        if (value->keys != NULL) free(value->keys[i]);
    }
    free(value->items);
    free(value->keys);
    free(value->string);
    memset(value, 0, sizeof(*value));
}

/* Public free: the root is heap allocated by yog_json_parse. */
void yog_json_free(YogJson *root)
{
    if (root == NULL) return;
    release(root);
    free(root);
}

static bool append_item(Reader *r, YogJson *container, size_t *capacity, const YogJson *item, char *key)
{
    if (container->count == *capacity) {
        size_t next = *capacity == 0 ? 4 : *capacity * 2;
        YogJson *grown = realloc(container->items, next * sizeof(*grown));
        if (grown == NULL) { fail(r, "out of memory"); return false; }
        container->items = grown;
        if (container->kind == YOG_JSON_OBJECT) {
            char **keys = realloc(container->keys, next * sizeof(*keys));
            if (keys == NULL) { fail(r, "out of memory"); return false; }
            container->keys = keys;
        }
        *capacity = next;
    }
    container->items[container->count] = *item;
    if (container->kind == YOG_JSON_OBJECT) container->keys[container->count] = key;
    container->count++;
    return true;
}

/* ------------------------------------------------------------------ strings */

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool read_hex4(Reader *r, unsigned *out)
{
    unsigned value = 0;
    int i;
    if (r->pos + 4 > r->length) { fail(r, "truncated \\u escape"); return false; }
    for (i = 0; i < 4; ++i) {
        int d = hex_digit(r->p[r->pos + (size_t)i]);
        if (d < 0) { fail(r, "bad \\u escape"); return false; }
        value = value * 16u + (unsigned)d;
    }
    r->pos += 4;
    *out = value;
    return true;
}

static size_t encode_utf8(unsigned cp, unsigned char *out)
{
    if (cp < 0x80u) { out[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800u) {
        out[0] = (unsigned char)(0xC0u | (cp >> 6));
        out[1] = (unsigned char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (unsigned char)(0xE0u | (cp >> 12));
        out[1] = (unsigned char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (unsigned char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    out[0] = (unsigned char)(0xF0u | (cp >> 18));
    out[1] = (unsigned char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (unsigned char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (unsigned char)(0x80u | (cp & 0x3Fu));
    return 4;
}

/* Validates one multi-byte UTF-8 sequence starting at p[0] (p[0] >= 0x80). */
size_t yog_utf8_sequence_length(const unsigned char *p, size_t available)
{
    unsigned char c = p[0];
    if (c >= 0xC2 && c <= 0xDF) {
        return available >= 2 && (p[1] & 0xC0) == 0x80 ? 2 : 0;
    }
    if (c >= 0xE0 && c <= 0xEF) {
        if (available < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return 0;
        if (c == 0xE0 && p[1] < 0xA0) return 0;          /* overlong */
        if (c == 0xED && p[1] >= 0xA0) return 0;         /* surrogate */
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (available < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return 0;
        if (c == 0xF0 && p[1] < 0x90) return 0;          /* overlong */
        if (c == 0xF4 && p[1] >= 0x90) return 0;         /* above U+10FFFF */
        return 4;
    }
    return 0;
}

/* Reads a string whose opening quote has been consumed. */
static char *read_string(Reader *r, size_t *out_length)
{
    size_t capacity = 16, used = 0;
    unsigned char *buffer = malloc(capacity);
    if (buffer == NULL) return fail(r, "out of memory");

    for (;;) {
        unsigned char c;
        if (r->pos >= r->length) { free(buffer); return fail(r, "unterminated string"); }
        c = r->p[r->pos];
        if (c == '"') { r->pos++; break; }
        if (c < 0x20) { free(buffer); return fail(r, "control character in string"); }

        if (used + 8 >= capacity) {
            size_t next = capacity * 2;
            unsigned char *grown = realloc(buffer, next);
            if (grown == NULL) { free(buffer); return fail(r, "out of memory"); }
            buffer = grown;
            capacity = next;
        }
        if (used >= YOG_JSON_MAX_STRING) { free(buffer); return fail(r, "string is too long"); }

        if (c == '\\') {
            unsigned cp;
            r->pos++;
            if (r->pos >= r->length) { free(buffer); return fail(r, "unterminated escape"); }
            switch (r->p[r->pos++]) {
            case '"': buffer[used++] = '"'; break;
            case '\\': buffer[used++] = '\\'; break;
            case '/': buffer[used++] = '/'; break;
            case 'b': buffer[used++] = '\b'; break;
            case 'f': buffer[used++] = '\f'; break;
            case 'n': buffer[used++] = '\n'; break;
            case 'r': buffer[used++] = '\r'; break;
            case 't': buffer[used++] = '\t'; break;
            case 'u':
                if (!read_hex4(r, &cp)) { free(buffer); return NULL; }
                if (cp >= 0xD800u && cp <= 0xDBFFu) {            /* high surrogate: needs a low one */
                    unsigned low;
                    if (r->pos + 2 > r->length || r->p[r->pos] != '\\' || r->p[r->pos + 1] != 'u') {
                        free(buffer); return fail(r, "lone surrogate");
                    }
                    r->pos += 2;
                    if (!read_hex4(r, &low)) { free(buffer); return NULL; }
                    if (low < 0xDC00u || low > 0xDFFFu) { free(buffer); return fail(r, "lone surrogate"); }
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
                } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                    free(buffer); return fail(r, "lone surrogate");
                }
                if (cp == 0) { free(buffer); return fail(r, "NUL character in string"); }
                used += encode_utf8(cp, buffer + used);
                break;
            default:
                free(buffer);
                r->pos--;
                return fail(r, "bad escape");
            }
        } else if (c < 0x80) {
            buffer[used++] = c;
            r->pos++;
        } else {
            size_t n = yog_utf8_sequence_length(r->p + r->pos, r->length - r->pos);
            if (n == 0) { free(buffer); return fail(r, "invalid UTF-8"); }
            memcpy(buffer + used, r->p + r->pos, n);
            used += n;
            r->pos += n;
        }
    }
    buffer[used] = '\0';
    *out_length = used;
    return (char *)buffer;
}

/* ------------------------------------------------------------------- values */

static bool parse_value(Reader *r, YogJson *out, unsigned depth);

static bool parse_number(Reader *r, YogJson *out)
{
    size_t start = r->pos;
    bool negative = false;
    bool is_float = false;
    uint64_t magnitude = 0;
    bool overflow = false;

    if (r->p[r->pos] == '-') { negative = true; r->pos++; }
    if (r->pos >= r->length) { fail(r, "bad number"); return false; }
    if (r->p[r->pos] == '0') {
        r->pos++;
        if (r->pos < r->length && r->p[r->pos] >= '0' && r->p[r->pos] <= '9') { fail(r, "leading zero in number"); return false; }
    } else if (r->p[r->pos] >= '1' && r->p[r->pos] <= '9') {
        while (r->pos < r->length && r->p[r->pos] >= '0' && r->p[r->pos] <= '9') {
            unsigned digit = (unsigned)(r->p[r->pos] - '0');
            if (magnitude > (UINT64_MAX - digit) / 10u) overflow = true;
            else magnitude = magnitude * 10u + digit;
            r->pos++;
        }
    } else {
        fail(r, "bad number");
        return false;
    }
    if (r->pos < r->length && r->p[r->pos] == '.') {
        is_float = true;
        r->pos++;
        if (r->pos >= r->length || r->p[r->pos] < '0' || r->p[r->pos] > '9') { fail(r, "bad number"); return false; }
        while (r->pos < r->length && r->p[r->pos] >= '0' && r->p[r->pos] <= '9') r->pos++;
    }
    if (r->pos < r->length && (r->p[r->pos] == 'e' || r->p[r->pos] == 'E')) {
        is_float = true;
        r->pos++;
        if (r->pos < r->length && (r->p[r->pos] == '+' || r->p[r->pos] == '-')) r->pos++;
        if (r->pos >= r->length || r->p[r->pos] < '0' || r->p[r->pos] > '9') { fail(r, "bad number"); return false; }
        while (r->pos < r->length && r->p[r->pos] >= '0' && r->p[r->pos] <= '9') r->pos++;
    }
    if (is_float) {
        out->kind = YOG_JSON_FLOAT;
        return true;
    }
    if (overflow || (!negative && magnitude > (uint64_t)INT64_MAX) ||
        (negative && magnitude > (uint64_t)INT64_MAX + 1u)) {
        r->pos = start;
        fail(r, "integer is out of range");
        return false;
    }
    out->kind = YOG_JSON_INT;
    out->integer = negative ? (magnitude == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)magnitude)
                            : (int64_t)magnitude;
    return true;
}

static bool expect_word(Reader *r, const char *word)
{
    size_t n = strlen(word);
    if (r->pos + n > r->length || memcmp(r->p + r->pos, word, n) != 0) { fail(r, "unexpected token"); return false; }
    r->pos += n;
    return true;
}

static bool parse_array(Reader *r, YogJson *out, unsigned depth)
{
    size_t capacity = 0;
    out->kind = YOG_JSON_ARRAY;
    r->pos++;                                   /* [ */
    skip_space(r);
    if (r->pos < r->length && r->p[r->pos] == ']') { r->pos++; return true; }
    for (;;) {
        YogJson item;
        memset(&item, 0, sizeof(item));
        skip_space(r);
        if (!parse_value(r, &item, depth + 1)) { release(&item); return false; }
        if (!append_item(r, out, &capacity, &item, NULL)) { release(&item); return false; }
        skip_space(r);
        if (r->pos >= r->length) { fail(r, "unterminated array"); return false; }
        if (r->p[r->pos] == ',') { r->pos++; continue; }
        if (r->p[r->pos] == ']') { r->pos++; return true; }
        fail(r, "expected ',' or ']'");
        return false;
    }
}

static bool parse_object(Reader *r, YogJson *out, unsigned depth)
{
    size_t capacity = 0;
    out->kind = YOG_JSON_OBJECT;
    r->pos++;                                   /* { */
    skip_space(r);
    if (r->pos < r->length && r->p[r->pos] == '}') { r->pos++; return true; }
    for (;;) {
        YogJson item;
        char *key;
        size_t key_length = 0, i;
        memset(&item, 0, sizeof(item));
        skip_space(r);
        if (r->pos >= r->length || r->p[r->pos] != '"') { fail(r, "expected a string key"); return false; }
        r->pos++;
        key = read_string(r, &key_length);
        if (key == NULL) return false;
        for (i = 0; i < out->count; ++i) {
            if (strcmp(out->keys[i], key) == 0) { free(key); fail(r, "duplicate object key"); return false; }
        }
        skip_space(r);
        if (r->pos >= r->length || r->p[r->pos] != ':') { free(key); fail(r, "expected ':'"); return false; }
        r->pos++;
        skip_space(r);
        if (!parse_value(r, &item, depth + 1)) { free(key); release(&item); return false; }
        if (!append_item(r, out, &capacity, &item, key)) { free(key); release(&item); return false; }
        skip_space(r);
        if (r->pos >= r->length) { fail(r, "unterminated object"); return false; }
        if (r->p[r->pos] == ',') { r->pos++; continue; }
        if (r->p[r->pos] == '}') { r->pos++; return true; }
        fail(r, "expected ',' or '}'");
        return false;
    }
}

static bool parse_value(Reader *r, YogJson *out, unsigned depth)
{
    if (depth > YOG_JSON_MAX_DEPTH) { fail(r, "nesting is too deep"); return false; }
    if (++r->nodes > YOG_JSON_MAX_NODES) { fail(r, "document is too large"); return false; }
    skip_space(r);
    if (r->pos >= r->length) { fail(r, "unexpected end of input"); return false; }
    switch (r->p[r->pos]) {
    case '{': return parse_object(r, out, depth);
    case '[': return parse_array(r, out, depth);
    case '"':
        r->pos++;
        out->kind = YOG_JSON_STRING;
        out->string = read_string(r, &out->string_length);
        return out->string != NULL;
    case 't': out->kind = YOG_JSON_BOOL; out->boolean = true; return expect_word(r, "true");
    case 'f': out->kind = YOG_JSON_BOOL; out->boolean = false; return expect_word(r, "false");
    case 'n': out->kind = YOG_JSON_NULL; return expect_word(r, "null");
    default:
        if (r->p[r->pos] == '-' || (r->p[r->pos] >= '0' && r->p[r->pos] <= '9')) return parse_number(r, out);
        fail(r, "unexpected character");
        return false;
    }
}

YogJson *yog_json_parse(const char *text, size_t length, char *message, size_t message_size)
{
    Reader r;
    YogJson *root;
    if (message != NULL && message_size > 0) message[0] = '\0';
    if (text == NULL) {
        if (message != NULL) (void)snprintf(message, message_size, "json: no input");
        return NULL;
    }
    if (length > YOG_JSON_MAX_INPUT) {
        if (message != NULL) (void)snprintf(message, message_size, "json: input is larger than %u bytes", YOG_JSON_MAX_INPUT);
        return NULL;
    }
    memset(&r, 0, sizeof(r));
    r.p = (const unsigned char *)text;
    r.length = length;
    r.message = message;
    r.message_size = message_size;

    root = calloc(1, sizeof(*root));
    if (root == NULL) { fail(&r, "out of memory"); return NULL; }
    if (!parse_value(&r, root, 0)) { yog_json_free(root); return NULL; }
    skip_space(&r);
    if (r.pos != r.length) { fail(&r, "trailing characters after the value"); yog_json_free(root); return NULL; }
    return root;
}

const YogJson *yog_json_member(const YogJson *object, const char *key)
{
    size_t i;
    if (object == NULL || object->kind != YOG_JSON_OBJECT) return NULL;
    for (i = 0; i < object->count; ++i)
        if (strcmp(object->keys[i], key) == 0) return &object->items[i];
    return NULL;
}
