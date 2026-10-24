/*
 * lexer.c -- YOG lexer implementation.
 *
 * Layout (read top to bottom; each section only uses the ones above it):
 *   1. Tables            keywords / operators / punctuation as DATA
 *   2. Character classes ASCII only, locale independent
 *   3. Cursor primitives the only code that moves `pos` / counts lines
 *   4. Error reporting
 *   5. Token construction
 *   6. Line start        indentation -> INDENT / DEDENT
 *   7. Scanners          one function per lexeme kind
 *   8. Public API
 *
 * Contract shared by every scan_* function: on entry the cursor is on the
 * FIRST byte of the lexeme; on return the cursor is just past it (or an
 * error has been recorded).  No scanner reads past the end of the buffer.
 */
#include "lexer/lexer.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ========================================================================
 * 1. Tables  (Open/Closed: new keyword/operator = one new line here)
 * ====================================================================== */

typedef struct {
    const char *text;
    TokenType   type;
} TextEntry;

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

static const TextEntry KEYWORDS[] = {
    {"fact",  TOK_FACT},
    {"rule",  TOK_RULE},
    {"allow", TOK_ALLOW},
    {"deny",  TOK_DENY},
    {"query", TOK_QUERY},
    {"not",   TOK_NOT},
};

/* ORDER MATTERS: longest first, so "<=" is tried before "<". */
static const TextEntry OPERATORS[] = {
    {"<=", TOK_LTE},
    {">=", TOK_GTE},
    {"==", TOK_EQ},
    {"!=", TOK_NEQ},
    {"<",  TOK_LT},
    {">",  TOK_GT},
};

static const TextEntry PUNCTUATION[] = {
    {"(", TOK_LPAREN},
    {")", TOK_RPAREN},
    {",", TOK_COMMA},
    {":", TOK_COLON},
};

/* ========================================================================
 * 2. Character classes (ASCII only: <ctype.h> is locale dependent and has
 *    undefined behaviour for negative chars, so we avoid it)
 * ====================================================================== */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
static bool is_alpha(char c) { return is_upper(c) || (c >= 'a' && c <= 'z'); }
static bool is_word_start(char c) { return is_alpha(c) || c == '_'; }
static bool is_word_part(char c)
{
    return is_alpha(c) || is_digit(c) || c == '_' || c == '.';
}

/* ========================================================================
 * 3. Cursor primitives
 * ====================================================================== */

static bool at_end(const Lexer *lx) { return lx->pos >= lx->len; }

/* Byte at `index`, or '\0' past the end (use at_end() to tell real NULs apart). */
static char peek_at(const Lexer *lx, size_t index)
{
    return index < lx->len ? lx->src[index] : '\0';
}

/* Length of the line terminator at `index`: 0 (none), 1 ("\n") or 2 ("\r\n"). */
static size_t newline_len(const Lexer *lx, size_t index)
{
    if (index >= lx->len) return 0;
    if (lx->src[index] == '\n') return 1;
    if (lx->src[index] == '\r' && index + 1 < lx->len && lx->src[index + 1] == '\n') return 2;
    return 0;
}

/* Precondition: a line terminator is at the cursor. */
static void consume_newline(Lexer *lx)
{
    lx->pos += newline_len(lx, lx->pos);
    lx->line++;
    lx->line_start = lx->pos;
}

/* Move the cursor to the end of the current line (stops BEFORE the newline). */
static void skip_to_eol(Lexer *lx)
{
    while (!at_end(lx) && newline_len(lx, lx->pos) == 0) lx->pos++;
}

static int column_at(const Lexer *lx, size_t index)
{
    return (int)(index - lx->line_start) + 1;
}

/* ========================================================================
 * 4. Error reporting
 * ====================================================================== */

#if defined(__GNUC__) || defined(__clang__)
#define YOG_PRINTF_LIKE(fmt_idx, args_idx) __attribute__((format(printf, fmt_idx, args_idx)))
#else
#define YOG_PRINTF_LIKE(fmt_idx, args_idx)
#endif

static void set_error(Lexer *lx, int line, int column, const char *fmt, ...) YOG_PRINTF_LIKE(4, 5);

/* Record the FIRST error only; later ones are consequences, not causes. */
static void set_error(Lexer *lx, int line, int column, const char *fmt, ...)
{
    va_list args;
    if (lx->failed) return;
    va_start(args, fmt);
    vsnprintf(lx->error.message, sizeof lx->error.message, fmt, args);
    va_end(args);
    lx->error.line = line;
    lx->error.column = column;
    lx->failed = true;
}

/* Printable form of one byte for error messages: 'x' or 0x1F. */
static void describe_byte(char c, char out[8])
{
    unsigned char u = (unsigned char)c;
    if (u >= 32 && u <= 126) snprintf(out, 8, "'%c'", c);
    else                     snprintf(out, 8, "0x%02X", (unsigned)u);
}

/* ========================================================================
 * 5. Token construction
 * ====================================================================== */

static Token make_token(const Lexer *lx, TokenType type, size_t start, size_t length,
                        int line, int column)
{
    Token t;
    t.type = type;
    t.start = lx->src + start;
    t.length = length;
    t.int_value = 0;
    t.line = line;
    t.column = column;
    return t;
}

/* Zero-length token located at the cursor (NEWLINE, INDENT, DEDENT, EOF). */
static Token marker_token(const Lexer *lx, TokenType type)
{
    return make_token(lx, type, lx->pos, 0, lx->line, column_at(lx, lx->pos));
}

static Token error_token(const Lexer *lx)
{
    return make_token(lx, TOK_ERROR, lx->pos, 0, lx->error.line, lx->error.column);
}

/* ========================================================================
 * 6. Line start: indentation  ->  INDENT / DEDENT
 * ====================================================================== */

/* Called once per input end: close every open block. */
static void finish_input(Lexer *lx)
{
    lx->pending_dedents = lx->depth - 1;
    lx->depth = 1;
    lx->at_eof = true;
    lx->at_line_start = false;
}

/* Compare `indent` with the open levels and queue INDENT / DEDENTs. */
static bool apply_indent(Lexer *lx, size_t indent)
{
    if (indent > lx->indent_stack[lx->depth - 1]) {
        if (lx->depth >= YOG_LEXER_MAX_INDENT) {
            set_error(lx, lx->line, column_at(lx, lx->pos),
                      "indentation nested deeper than %d levels", YOG_LEXER_MAX_INDENT - 1);
            return false;
        }
        lx->indent_stack[lx->depth++] = indent;
        lx->pending_indent = true;
    } else {
        while (indent < lx->indent_stack[lx->depth - 1]) {
            lx->depth--;
            lx->pending_dedents++;
        }
        if (indent != lx->indent_stack[lx->depth - 1]) {
            set_error(lx, lx->line, column_at(lx, lx->pos),
                      "inconsistent indentation: %zu spaces does not match any enclosing block",
                      indent);
            return false;
        }
    }
    lx->at_line_start = false;
    return true;
}

/*
 * Skip blank / comment-only lines, then measure the indentation of the next
 * real line.  Leaves the cursor on that line's first non-space byte.
 * Returns false (error recorded) on bad indentation.
 */
static bool begin_line(Lexer *lx)
{
    for (;;) {
        size_t p = lx->pos;
        size_t indent = 0;
        size_t q;

        while (p < lx->len && lx->src[p] == ' ') { p++; indent++; }

        /* q: first byte that is neither space nor tab */
        q = p;
        while (q < lx->len && (lx->src[q] == ' ' || lx->src[q] == '\t')) q++;

        if (q >= lx->len) {                  /* only whitespace until EOF */
            lx->pos = lx->len;
            finish_input(lx);
            return true;
        }
        if (lx->src[q] == '#') {             /* comment-only line */
            lx->pos = q;
            skip_to_eol(lx);
            if (at_end(lx)) { finish_input(lx); return true; }
            consume_newline(lx);
            continue;
        }
        if (newline_len(lx, q) > 0) {        /* blank line (spaces/tabs only) */
            lx->pos = q;
            consume_newline(lx);
            continue;
        }

        /* A real line. Tabs are only an error when they are in the indentation. */
        lx->pos = p;
        if (lx->src[p] == '\t') {
            set_error(lx, lx->line, column_at(lx, p),
                      "tab characters are not allowed in indentation; use spaces");
            return false;
        }
        return apply_indent(lx, indent);
    }
}

/* ========================================================================
 * 7. Scanners
 * ====================================================================== */

static const TextEntry *match_prefix(const Lexer *lx, const TextEntry *table, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        size_t n = strlen(table[i].text);
        if (lx->len - lx->pos >= n && memcmp(lx->src + lx->pos, table[i].text, n) == 0)
            return &table[i];
    }
    return NULL;
}

static const TextEntry *lookup_keyword(const char *text, size_t length)
{
    for (size_t i = 0; i < COUNT_OF(KEYWORDS); i++)
        if (strlen(KEYWORDS[i].text) == length && memcmp(KEYWORDS[i].text, text, length) == 0)
            return &KEYWORDS[i];
    return NULL;
}

static Token scan_newline(Lexer *lx)
{
    Token t = marker_token(lx, TOK_NEWLINE);
    if (!at_end(lx)) consume_newline(lx);
    lx->at_line_start = true;
    return t;
}

/* Operators and punctuation: fixed text, looked up in a table. */
static Token scan_fixed(Lexer *lx, const TextEntry *entry)
{
    size_t n = strlen(entry->text);
    Token t = make_token(lx, entry->type, lx->pos, n, lx->line, column_at(lx, lx->pos));
    lx->pos += n;
    return t;
}

/* keyword | VAR | IDENT | WILDCARD */
static Token scan_word(Lexer *lx)
{
    size_t start = lx->pos;
    int column = column_at(lx, start);
    size_t length;
    TokenType type;
    const TextEntry *kw;

    while (!at_end(lx) && is_word_part(lx->src[lx->pos])) lx->pos++;
    length = lx->pos - start;

    if (length == 1 && lx->src[start] == '_')          type = TOK_WILDCARD;
    else if ((kw = lookup_keyword(lx->src + start, length)) != NULL) type = kw->type;
    else if (is_upper(lx->src[start]))                 type = TOK_VAR;
    else                                               type = TOK_IDENT;

    return make_token(lx, type, start, length, lx->line, column);
}

/* [-]digits.  Out-of-range values are an error, never silent wraparound. */
static Token scan_integer(Lexer *lx)
{
    size_t start = lx->pos;
    int column = column_at(lx, start);
    bool negative = (lx->src[start] == '-');
    unsigned long long limit = negative ? (unsigned long long)LLONG_MAX + 1ULL
                                        : (unsigned long long)LLONG_MAX;
    unsigned long long magnitude = 0;
    bool overflow = false;
    Token t;

    if (negative) lx->pos++;
    while (!at_end(lx) && is_digit(lx->src[lx->pos])) {
        unsigned digit = (unsigned)(lx->src[lx->pos] - '0');
        if (magnitude > (limit - digit) / 10ULL) overflow = true;
        else magnitude = magnitude * 10ULL + digit;
        lx->pos++;
    }

    if (overflow) {
        set_error(lx, lx->line, column, "integer literal out of range");
        return error_token(lx);
    }

    t = make_token(lx, TOK_INT, start, lx->pos - start, lx->line, column);
    if (!negative)                              t.int_value = (long long)magnitude;
    else if (magnitude == limit)                t.int_value = LLONG_MIN;
    else                                        t.int_value = -(long long)magnitude;
    return t;
}

/* "text" on a single line; no escape sequences in v1. */
static Token scan_string(Lexer *lx)
{
    size_t open = lx->pos;
    int column = column_at(lx, open);
    size_t content;

    lx->pos++;                       /* opening quote */
    content = lx->pos;
    while (!at_end(lx) && lx->src[lx->pos] != '"' && lx->src[lx->pos] != '\n') lx->pos++;

    if (at_end(lx) || lx->src[lx->pos] != '"') {
        set_error(lx, lx->line, column, "unterminated string literal");
        return error_token(lx);
    }
    {
        Token t = make_token(lx, TOK_STRING, content, lx->pos - content, lx->line, column);
        lx->pos++;                   /* closing quote */
        return t;
    }
}

static Token fail_unexpected(Lexer *lx)
{
    char c = lx->src[lx->pos];
    char shown[8];
    int column = column_at(lx, lx->pos);

    if (c == '\t') {
        set_error(lx, lx->line, column, "tab characters are not allowed; use spaces");
    } else {
        describe_byte(c, shown);
        set_error(lx, lx->line, column, "unexpected character %s", shown);
    }
    return error_token(lx);
}

/* Scan one token from the middle of a line (cursor is not at a line start). */
static Token scan_in_line(Lexer *lx)
{
    const TextEntry *entry;
    char c;

    while (!at_end(lx) && lx->src[lx->pos] == ' ') lx->pos++;
    if (!at_end(lx) && lx->src[lx->pos] == '#') skip_to_eol(lx);
    if (at_end(lx) || newline_len(lx, lx->pos) > 0) return scan_newline(lx);

    c = lx->src[lx->pos];
    if (is_digit(c) || (c == '-' && is_digit(peek_at(lx, lx->pos + 1)))) return scan_integer(lx);
    if (c == '"')          return scan_string(lx);
    if (is_word_start(c))  return scan_word(lx);

    entry = match_prefix(lx, OPERATORS, COUNT_OF(OPERATORS));
    if (entry == NULL) entry = match_prefix(lx, PUNCTUATION, COUNT_OF(PUNCTUATION));
    if (entry != NULL) return scan_fixed(lx, entry);

    return fail_unexpected(lx);
}

/* ========================================================================
 * 8. Public API
 * ====================================================================== */

void lexer_init(Lexer *lx, const char *src, size_t len)
{
    memset(lx, 0, sizeof *lx);
    lx->src = (src != NULL) ? src : "";
    lx->len = (src != NULL) ? len : 0;
    lx->line = 1;
    lx->indent_stack[0] = 0;
    lx->depth = 1;
    lx->at_line_start = true;
}

Token lexer_next(Lexer *lx)
{
    for (;;) {
        if (lx->failed)               return error_token(lx);

        if (lx->pending_dedents > 0) {
            lx->pending_dedents--;
            return marker_token(lx, TOK_DEDENT);
        }
        if (lx->pending_indent) {
            lx->pending_indent = false;
            return marker_token(lx, TOK_INDENT);
        }
        if (lx->at_eof)               return marker_token(lx, TOK_EOF);

        if (lx->at_line_start) {
            if (!begin_line(lx))      return error_token(lx);
            continue;                 /* emit queued INDENT/DEDENT/EOF first */
        }
        return scan_in_line(lx);
    }
}

const LexError *lexer_error(const Lexer *lx)
{
    return lx->failed ? &lx->error : NULL;
}
