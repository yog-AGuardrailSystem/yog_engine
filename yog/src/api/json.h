/*
 * json.h -- a small, strict JSON reader used for check requests.
 *
 * Strict on purpose, because request JSON is untrusted input:
 *   - UTF-8 is validated; NUL bytes (raw or \u0000) are rejected;
 *   - duplicate object keys are rejected (they would be ambiguous);
 *   - numbers with a fraction or exponent are parsed as FLOAT so the caller can
 *     reject them with a clear message (YOG has no float type);
 *   - nesting depth, node count, string length and input size are all capped.
 */
#ifndef YOG_JSON_H
#define YOG_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YOG_JSON_MAX_INPUT   (1u << 20)    /* 1 MiB */
#define YOG_JSON_MAX_DEPTH   16u
#define YOG_JSON_MAX_NODES   20000u
#define YOG_JSON_MAX_STRING  (64u * 1024u)

typedef enum { YOG_JSON_NULL, YOG_JSON_BOOL, YOG_JSON_INT, YOG_JSON_FLOAT,
               YOG_JSON_STRING, YOG_JSON_ARRAY, YOG_JSON_OBJECT } YogJsonKind;

typedef struct YogJson YogJson;
struct YogJson {
    YogJsonKind kind;
    bool        boolean;
    int64_t     integer;
    char       *string;        /* STRING: NUL-terminated, UTF-8, no embedded NUL */
    size_t      string_length;
    YogJson    *items;         /* ARRAY elements, or OBJECT member values */
    char      **keys;          /* OBJECT only: key of each member */
    size_t      count;
};

/* Parses a whole document.  On failure returns NULL and writes a message. */
YogJson *yog_json_parse(const char *text, size_t length, char *message, size_t message_size);
void     yog_json_free(YogJson *value);

/* Length (2-4) of the valid UTF-8 multi-byte sequence at p[0] (p[0] >= 0x80), or 0 when the
 * bytes are not valid UTF-8 (overlong, surrogate, out of range, truncated). */
size_t yog_utf8_sequence_length(const unsigned char *p, size_t available);

/* Object member lookup; NULL when absent or when `object` is not an object. */
const YogJson *yog_json_member(const YogJson *object, const char *key);

#endif /* YOG_JSON_H */
