/*
 * test_lexer.c -- unit tests for the YOG lexer.  No external framework.
 *
 *   build:  see CMakeLists.txt  (or: gcc -Isrc src/lexer/lexer.c tests/lexer/test_lexer.c)
 *   run:    ./test_lexer            -> prints each test, exits non-zero on failure
 *
 * Every test is a small function; failures print file:line and the failed
 * expression, so a red test tells you exactly where to look.
 */
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lexer/lexer.h"

/* ------------------------------------------------------------------ */
/* Tiny assertion framework                                            */
/* ------------------------------------------------------------------ */

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failures++;                                                        \
            fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                        \
    } while (0)

/* ------------------------------------------------------------------ */
/* Helpers: lex a whole string into an array                           */
/* ------------------------------------------------------------------ */

#define MAX_TOKENS 4096

typedef struct {
    Token    toks[MAX_TOKENS];
    int      count;      /* tokens stored, INCLUDING the final EOF/ERROR */
    bool     errored;
    LexError err;
    const char *src;
    size_t   len;
} Lexed;

/* Lex until EOF or ERROR (or MAX_TOKENS, which a test would flag). */
static void lex_n(Lexed *out, const char *src, size_t len)
{
    Lexer lx;
    out->count = 0;
    out->errored = false;
    out->src = src;
    out->len = len;
    memset(&out->err, 0, sizeof out->err);

    lexer_init(&lx, src, len);
    while (out->count < MAX_TOKENS) {
        Token t = lexer_next(&lx);
        out->toks[out->count++] = t;
        if (t.type == TOK_EOF) break;
        if (t.type == TOK_ERROR) {
            out->errored = true;
            out->err = *lexer_error(&lx);
            break;
        }
    }
}

static Lexed *lex(const char *src)
{
    static Lexed shared;            /* reused: tests run one at a time */
    lex_n(&shared, src, strlen(src));
    return &shared;
}

static bool lexeme_is(const Token *t, const char *text)
{
    return t->length == strlen(text) && memcmp(t->start, text, t->length) == 0;
}

static int count_type(const Lexed *l, TokenType type)
{
    int n = 0;
    for (int i = 0; i < l->count; i++) if (l->toks[i].type == type) n++;
    return n;
}

/* Compare the whole type sequence; on mismatch print expected vs actual. */
static void expect_types(const char *file, int line, const char *src,
                         const TokenType *expected, int n)
{
    Lexed *l = lex(src);
    bool ok = (l->count == n);
    for (int i = 0; ok && i < n; i++) ok = (l->toks[i].type == expected[i]);

    g_checks++;
    if (!ok) {
        g_failures++;
        fprintf(stderr, "    FAIL %s:%d: token types differ for input \"%s\"\n      expected:", file, line, src);
        for (int i = 0; i < n; i++) fprintf(stderr, " %s", token_type_name(expected[i]));
        fprintf(stderr, "\n      actual:  ");
        for (int i = 0; i < l->count; i++) fprintf(stderr, " %s", token_type_name(l->toks[i].type));
        fprintf(stderr, "\n");
    }
}

#define EXPECT_TYPES(src, ...)                                                   \
    do {                                                                         \
        const TokenType exp_[] = {__VA_ARGS__};                                  \
        expect_types(__FILE__, __LINE__, (src), exp_, (int)(sizeof exp_ / sizeof exp_[0])); \
    } while (0)

/* Lex `src` and require an error at (line, col) whose message contains `needle`. */
static void expect_error(const char *file, int line, const char *src,
                         int err_line, int err_col, const char *needle)
{
    Lexed *l = lex(src);
    bool ok = l->errored && l->err.line == err_line && l->err.column == err_col &&
              strstr(l->err.message, needle) != NULL;
    g_checks++;
    if (!ok) {
        g_failures++;
        fprintf(stderr, "    FAIL %s:%d: input \"%s\"\n      wanted error at %d:%d containing \"%s\"\n",
                file, line, src, err_line, err_col, needle);
        if (l->errored)
            fprintf(stderr, "      got error at %d:%d: \"%s\"\n", l->err.line, l->err.column, l->err.message);
        else
            fprintf(stderr, "      got NO error\n");
    }
}
#define EXPECT_ERROR(src, l, c, needle) expect_error(__FILE__, __LINE__, (src), (l), (c), (needle))

/* ------------------------------------------------------------------ */
/* Tests: basics                                                       */
/* ------------------------------------------------------------------ */

static void test_empty_and_blank_inputs(void)
{
    EXPECT_TYPES("", TOK_EOF);
    EXPECT_TYPES("\n", TOK_EOF);
    EXPECT_TYPES("\n\n   \n", TOK_EOF);
    EXPECT_TYPES("   ", TOK_EOF);
    EXPECT_TYPES("\t\n  \t  \n", TOK_EOF);                 /* whitespace-only lines are blank */
    EXPECT_TYPES("# only a comment", TOK_EOF);
    EXPECT_TYPES("   # indented comment\n\n# another\n", TOK_EOF);

    Lexer lx;                                              /* NULL source is treated as "" */
    lexer_init(&lx, NULL, 123);
    CHECK(lexer_next(&lx).type == TOK_EOF);
}

static void test_simple_fact(void)
{
    EXPECT_TYPES("fact role(alice, admin)\n",
                 TOK_FACT, TOK_IDENT, TOK_LPAREN, TOK_IDENT, TOK_COMMA, TOK_IDENT,
                 TOK_RPAREN, TOK_NEWLINE, TOK_EOF);

    Lexed *l = lex("fact role(alice, admin)\n");
    CHECK(lexeme_is(&l->toks[1], "role"));
    CHECK(lexeme_is(&l->toks[3], "alice"));
    CHECK(lexeme_is(&l->toks[5], "admin"));
}

static void test_keywords(void)
{
    EXPECT_TYPES("fact rule allow deny query not",
                 TOK_FACT, TOK_RULE, TOK_ALLOW, TOK_DENY, TOK_QUERY, TOK_NOT, TOK_NEWLINE, TOK_EOF);

    /* keywords must match the WHOLE word */
    EXPECT_TYPES("factor ruled allowed denying querying nothing",
                 TOK_IDENT, TOK_IDENT, TOK_IDENT, TOK_IDENT, TOK_IDENT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);

    /* keywords are case-sensitive: an uppercase first letter makes a VAR */
    EXPECT_TYPES("Fact NOT Allow",
                 TOK_VAR, TOK_VAR, TOK_VAR, TOK_NEWLINE, TOK_EOF);
}

static void test_words(void)
{
    EXPECT_TYPES("user User _ _x X1 a.b app.yaml _.",
                 TOK_IDENT, TOK_VAR, TOK_WILDCARD, TOK_IDENT, TOK_VAR,
                 TOK_IDENT, TOK_IDENT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);

    Lexed *l = lex("app.yaml");
    CHECK(l->toks[0].type == TOK_IDENT && lexeme_is(&l->toks[0], "app.yaml"));
    l = lex("db_prod_2");
    CHECK(l->toks[0].type == TOK_IDENT && lexeme_is(&l->toks[0], "db_prod_2"));
}

static void test_punctuation(void)
{
    EXPECT_TYPES("(),:", TOK_LPAREN, TOK_RPAREN, TOK_COMMA, TOK_COLON, TOK_NEWLINE, TOK_EOF);
    EXPECT_TYPES("( ) , :", TOK_LPAREN, TOK_RPAREN, TOK_COMMA, TOK_COLON, TOK_NEWLINE, TOK_EOF);
}

static void test_operators(void)
{
    EXPECT_TYPES("a<=b>=c==d!=e<f>g",
                 TOK_IDENT, TOK_LTE, TOK_IDENT, TOK_GTE, TOK_IDENT, TOK_EQ, TOK_IDENT,
                 TOK_NEQ, TOK_IDENT, TOK_LT, TOK_IDENT, TOK_GT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);
    EXPECT_TYPES("Amt <= Limit", TOK_VAR, TOK_LTE, TOK_VAR, TOK_NEWLINE, TOK_EOF);

    /* longest match: "<=" is one token, never "<" then "=" */
    Lexed *l = lex("<=");
    CHECK(l->toks[0].type == TOK_LTE && l->toks[0].length == 2);

    /* a lone '=' or '!' is NOT valid */
    EXPECT_ERROR("a = b", 1, 3, "'='");
    EXPECT_ERROR("a ! b", 1, 3, "'!'");
    EXPECT_ERROR("<==", 1, 3, "'='");
}

/* ------------------------------------------------------------------ */
/* Tests: integers and strings                                         */
/* ------------------------------------------------------------------ */

static void test_integers(void)
{
    Lexed *l = lex("0 42 -7 007");
    CHECK(l->count == 6);   /* 4 ints + NEWLINE + EOF */
    CHECK(l->toks[0].type == TOK_INT && l->toks[0].int_value == 0);
    CHECK(l->toks[1].type == TOK_INT && l->toks[1].int_value == 42);
    CHECK(l->toks[2].type == TOK_INT && l->toks[2].int_value == -7);
    CHECK(lexeme_is(&l->toks[2], "-7"));
    CHECK(l->toks[3].type == TOK_INT && l->toks[3].int_value == 7);

    /* 64-bit boundaries */
    l = lex("9223372036854775807");
    CHECK(l->toks[0].type == TOK_INT && l->toks[0].int_value == LLONG_MAX);
    l = lex("-9223372036854775808");
    CHECK(l->toks[0].type == TOK_INT && l->toks[0].int_value == LLONG_MIN);
    EXPECT_ERROR("9223372036854775808", 1, 1, "out of range");
    EXPECT_ERROR("-9223372036854775809", 1, 1, "out of range");
    EXPECT_ERROR("99999999999999999999999999", 1, 1, "out of range");

    /* '-' must be followed by a digit */
    EXPECT_ERROR("-", 1, 1, "'-'");
    EXPECT_ERROR("- 5", 1, 1, "'-'");

    /* v1 has no floats: "1.5" is INT then an unexpected '.' */
    EXPECT_ERROR("1.5", 1, 2, "'.'");

    /* a number glued to a word is two tokens (the parser rejects it) */
    EXPECT_TYPES("12abc", TOK_INT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);
}

static void test_strings(void)
{
    Lexed *l = lex("\"hello world\"");
    CHECK(l->toks[0].type == TOK_STRING);
    CHECK(lexeme_is(&l->toks[0], "hello world"));        /* quotes excluded */
    CHECK(l->toks[0].column == 1);                       /* column of the opening quote */

    l = lex("\"\"");
    CHECK(l->toks[0].type == TOK_STRING && l->toks[0].length == 0);

    l = lex("\"/etc/passwd\"");
    CHECK(lexeme_is(&l->toks[0], "/etc/passwd"));

    /* '#' and operators inside a string are just text */
    l = lex("\"a # b <= c\"");
    CHECK(l->toks[0].type == TOK_STRING && lexeme_is(&l->toks[0], "a # b <= c"));
    CHECK(l->toks[1].type == TOK_NEWLINE);

    EXPECT_ERROR("\"abc", 1, 1, "unterminated");
    EXPECT_ERROR("fact a(\"abc", 1, 8, "unterminated");   /* points at the opening quote */
    EXPECT_ERROR("\"abc\ndef\"", 1, 1, "unterminated");   /* strings cannot span lines */
}

/* ------------------------------------------------------------------ */
/* Tests: comments, line endings, trailing newline                     */
/* ------------------------------------------------------------------ */

static void test_comments(void)
{
    EXPECT_TYPES("fact a(b) # trailing comment\n",
                 TOK_FACT, TOK_IDENT, TOK_LPAREN, TOK_IDENT, TOK_RPAREN, TOK_NEWLINE, TOK_EOF);
    EXPECT_TYPES("# c1\nfact a(b)\n# c2\n",
                 TOK_FACT, TOK_IDENT, TOK_LPAREN, TOK_IDENT, TOK_RPAREN, TOK_NEWLINE, TOK_EOF);
    EXPECT_TYPES("a #\n", TOK_IDENT, TOK_NEWLINE, TOK_EOF);
}

static void test_missing_trailing_newline(void)
{
    EXPECT_TYPES("fact a(b)",
                 TOK_FACT, TOK_IDENT, TOK_LPAREN, TOK_IDENT, TOK_RPAREN, TOK_NEWLINE, TOK_EOF);
    EXPECT_TYPES("r(X):\n    p(X)",
                 TOK_IDENT, TOK_LPAREN, TOK_VAR, TOK_RPAREN, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_LPAREN, TOK_VAR, TOK_RPAREN, TOK_NEWLINE,
                 TOK_DEDENT, TOK_EOF);
    EXPECT_TYPES("a # comment, no newline", TOK_IDENT, TOK_NEWLINE, TOK_EOF);
}

/* Same tokens (type + text), regardless of line-ending style. */
static bool same_stream(const char *a, const char *b)
{
    static Lexed la, lb;
    lex_n(&la, a, strlen(a));
    lex_n(&lb, b, strlen(b));
    if (la.count != lb.count) return false;
    for (int i = 0; i < la.count; i++) {
        if (la.toks[i].type != lb.toks[i].type) return false;
        if (la.toks[i].length != lb.toks[i].length) return false;
        if (memcmp(la.toks[i].start, lb.toks[i].start, la.toks[i].length) != 0) return false;
    }
    return true;
}

static void test_crlf_line_endings(void)
{
    CHECK(same_stream("fact a(b)\nrule r(X):\n    p(X)\n\n# c\nquery r(a)\n",
                      "fact a(b)\r\nrule r(X):\r\n    p(X)\r\n\r\n# c\r\nquery r(a)\r\n"));
    CHECK(same_stream("a # c\nb\n", "a # c\r\nb\r\n"));

    /* a bare '\r' that is not part of "\r\n" is not a line ending */
    EXPECT_ERROR("a\rb", 1, 2, "0x0D");
}

/* ------------------------------------------------------------------ */
/* Tests: indentation                                                  */
/* ------------------------------------------------------------------ */

static void test_simple_block(void)
{
    EXPECT_TYPES("rule x(Y):\n    foo(Y)\n",
                 TOK_RULE, TOK_IDENT, TOK_LPAREN, TOK_VAR, TOK_RPAREN, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_LPAREN, TOK_VAR, TOK_RPAREN, TOK_NEWLINE,
                 TOK_DEDENT, TOK_EOF);
}

static void test_multi_line_body_has_one_indent(void)
{
    Lexed *l = lex("allow d(U, R):\n    p(U)\n    q(R)\n    not r(U)\nfact z(a)\n");
    CHECK(count_type(l, TOK_INDENT) == 1);
    CHECK(count_type(l, TOK_DEDENT) == 1);
    CHECK(count_type(l, TOK_NEWLINE) == 5);
    CHECK(!l->errored);
}

static void test_nested_blocks(void)
{
    EXPECT_TYPES("a:\n    b:\n        c\nd\n",
                 TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_NEWLINE,
                 TOK_DEDENT, TOK_DEDENT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);

    /* two levels closed at end of input */
    EXPECT_TYPES("a:\n  b:\n    c\n",
                 TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_NEWLINE,
                 TOK_DEDENT, TOK_DEDENT, TOK_EOF);

    /* dedent to an intermediate level */
    EXPECT_TYPES("a:\n  b:\n    c\n  d\ne\n",
                 TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_COLON, TOK_NEWLINE,
                 TOK_INDENT, TOK_IDENT, TOK_NEWLINE,
                 TOK_DEDENT, TOK_IDENT, TOK_NEWLINE,
                 TOK_DEDENT, TOK_IDENT, TOK_NEWLINE, TOK_EOF);
}

static void test_blank_and_comment_lines_do_not_affect_indentation(void)
{
    Lexed *l = lex("rule x(Y):\n"
                   "    p(Y)\n"
                   "\n"
                   "  # oddly indented comment\n"
                   "        # deeper comment\n"
                   "   \t  \n"
                   "    q(Y)\n");
    CHECK(!l->errored);
    CHECK(count_type(l, TOK_INDENT) == 1);
    CHECK(count_type(l, TOK_DEDENT) == 1);
    CHECK(count_type(l, TOK_NEWLINE) == 3);

    /* a comment at column 0 in the middle of a block does not close it */
    l = lex("a:\n    b\n# comment\n    c\n");
    CHECK(count_type(l, TOK_INDENT) == 1 && count_type(l, TOK_DEDENT) == 1);
}

static void test_indented_first_line(void)
{
    /* The lexer reports it; rejecting it is the parser's job. */
    EXPECT_TYPES("  fact x(a)\n",
                 TOK_INDENT, TOK_FACT, TOK_IDENT, TOK_LPAREN, TOK_IDENT, TOK_RPAREN, TOK_NEWLINE,
                 TOK_DEDENT, TOK_EOF);
}

static void test_inconsistent_dedent(void)
{
    /* stack is [0, 8]; 4 matches neither */
    EXPECT_ERROR("a:\n        b\n    c\n", 3, 5, "inconsistent indentation");
    EXPECT_ERROR("a:\n    b:\n        c\n      d\n", 4, 7, "inconsistent indentation");
}

static void test_tabs(void)
{
    EXPECT_ERROR("a:\n\tb\n", 2, 1, "tab");
    EXPECT_ERROR("a:\n  \tb\n", 2, 3, "tab");
    EXPECT_ERROR("a\tb", 1, 2, "tab");                /* tab inside a line */
    EXPECT_ERROR("a \t\nb", 1, 3, "tab");             /* trailing tab after code */
    EXPECT_TYPES("a\n\t\nb\n", TOK_IDENT, TOK_NEWLINE, TOK_IDENT, TOK_NEWLINE, TOK_EOF); /* tab-only line is blank */

    /* A tab in the indentation is reported AS a tab problem, even when the
     * space count in front of it would also be wrong (clearer message, and
     * no INDENT/DEDENT is queued from a line we are about to reject). */
    EXPECT_ERROR("a:\n    b\n  \tc\n", 3, 3, "tab");
    {
        Lexed *l = lex("a:\n \tb\n");
        CHECK(l->errored);
        CHECK(count_type(l, TOK_INDENT) == 0);        /* no INDENT before the error */
    }
}

static void test_max_indent_depth(void)
{
    char buf[8192];
    size_t n;

    /* 64 levels (indents 0..63) is exactly the limit and must work */
    n = 0;
    for (int i = 0; i < 64; i++) {
        for (int s = 0; s < i; s++) buf[n++] = ' ';
        buf[n++] = 'x'; buf[n++] = '\n';
    }
    buf[n] = '\0';
    Lexed *l = lex(buf);
    CHECK(!l->errored);
    CHECK(count_type(l, TOK_INDENT) == 63);
    CHECK(count_type(l, TOK_DEDENT) == 63);

    /* one more level must produce a clean error, not a buffer overflow */
    n = 0;
    for (int i = 0; i < 70; i++) {
        for (int s = 0; s < i; s++) buf[n++] = ' ';
        buf[n++] = 'x'; buf[n++] = '\n';
    }
    buf[n] = '\0';
    l = lex(buf);
    CHECK(l->errored);
    CHECK(l->err.line == 65);
    CHECK(strstr(l->err.message, "deeper") != NULL);
}

/* ------------------------------------------------------------------ */
/* Tests: positions                                                    */
/* ------------------------------------------------------------------ */

typedef struct { TokenType type; int line; int column; } Pos;

static void test_line_and_column_tracking(void)
{
    static const Pos expected[] = {
        {TOK_FACT,    1, 1}, {TOK_IDENT,  1, 6}, {TOK_LPAREN, 1, 10}, {TOK_IDENT, 1, 11},
        {TOK_COMMA,   1, 12}, {TOK_IDENT, 1, 14}, {TOK_RPAREN, 1, 15}, {TOK_NEWLINE, 1, 16},
        {TOK_RULE,    2, 1}, {TOK_IDENT,  2, 6}, {TOK_LPAREN, 2, 7},  {TOK_VAR,   2, 8},
        {TOK_RPAREN,  2, 9}, {TOK_COLON,  2, 10}, {TOK_NEWLINE, 2, 11},
        {TOK_INDENT,  3, 5}, {TOK_IDENT,  3, 5}, {TOK_LPAREN, 3, 8},  {TOK_VAR,   3, 9},
        {TOK_RPAREN,  3, 10}, {TOK_NEWLINE, 3, 11},
        {TOK_DEDENT,  4, 1}, {TOK_EOF,    4, 1},
    };
    Lexed *l = lex("fact role(a, b)\nrule x(Y):\n    foo(Y)\n");
    CHECK(l->count == (int)(sizeof expected / sizeof expected[0]));
    for (int i = 0; i < l->count && i < (int)(sizeof expected / sizeof expected[0]); i++) {
        if (l->toks[i].type != expected[i].type || l->toks[i].line != expected[i].line ||
            l->toks[i].column != expected[i].column) {
            fprintf(stderr, "    token %d: got %s at %d:%d, wanted %s at %d:%d\n", i,
                    token_type_name(l->toks[i].type), l->toks[i].line, l->toks[i].column,
                    token_type_name(expected[i].type), expected[i].line, expected[i].column);
        }
        CHECK(l->toks[i].type == expected[i].type);
        CHECK(l->toks[i].line == expected[i].line);
        CHECK(l->toks[i].column == expected[i].column);
    }

    /* line numbers keep counting across blank and comment lines */
    l = lex("\n\n# c\n\nfact a(b)\n");
    CHECK(l->toks[0].type == TOK_FACT && l->toks[0].line == 5 && l->toks[0].column == 1);

    /* CRLF: columns/lines are the same as for LF */
    l = lex("a\r\nb\r\n");
    CHECK(l->toks[2].type == TOK_IDENT && l->toks[2].line == 2 && l->toks[2].column == 1);
}

static void test_error_positions(void)
{
    EXPECT_ERROR("fact a(b)\nfact c(@)\n", 2, 8, "'@'");
    EXPECT_ERROR("\n\n   $", 3, 4, "'$'");
}

/* ------------------------------------------------------------------ */
/* Tests: error behaviour                                              */
/* ------------------------------------------------------------------ */

static void test_unexpected_characters(void)
{
    const char *bad = "@$%{}[]|&\\;'`~?*+/=!^.";
    for (const char *p = bad; *p; p++) {
        char src[2] = {*p, '\0'};
        Lexed *l = lex(src);
        CHECK(l->errored);
        CHECK(l->err.line == 1 && l->err.column == 1);
        CHECK(l->toks[l->count - 1].type == TOK_ERROR);
    }
    EXPECT_ERROR("\xC3\xA9", 1, 1, "0xC3");            /* non-ASCII byte */
    EXPECT_ERROR("fact a(b\x01)", 1, 9, "0x01");       /* control char, shown as hex */
}

static void test_embedded_nul(void)
{
    static Lexed l;
    lex_n(&l, "a\0b", 3);                              /* NUL is data, not end of input */
    CHECK(l.toks[0].type == TOK_IDENT);
    CHECK(l.errored && l.err.column == 2);
    CHECK(strstr(l.err.message, "0x00") != NULL);

    lex_n(&l, "\"a\0b\"", 5);                          /* NUL inside a string is fine */
    CHECK(l.toks[0].type == TOK_STRING && l.toks[0].length == 3);
}

static void test_errors_are_sticky(void)
{
    Lexer lx;
    lexer_init(&lx, "a @ b\n", 6);
    CHECK(lexer_error(&lx) == NULL);                   /* no error yet */
    CHECK(lexer_next(&lx).type == TOK_IDENT);
    CHECK(lexer_error(&lx) == NULL);
    CHECK(lexer_next(&lx).type == TOK_ERROR);
    CHECK(lexer_error(&lx) != NULL);
    for (int i = 0; i < 5; i++) {
        Token t = lexer_next(&lx);
        CHECK(t.type == TOK_ERROR);
        CHECK(t.line == 1 && t.column == 3);
    }
    CHECK(lexer_error(&lx)->column == 3);              /* first error is kept */

    /* Errors that MOVE the cursor (unterminated string, bad integer, bad
     * indentation) must stay sticky too: without the guard in lexer_next the
     * lexer would carry on and happily emit tokens after the error. */
    static const char *const bad_inputs[] = {
        "\"abc",                         /* unterminated string  */
        "99999999999999999999 x y\n",    /* integer out of range */
        "a:\n        b\n    c\n d\n",     /* inconsistent dedent  */
        "a:\n\tb\n c\n",                 /* tab in indentation   */
    };
    for (size_t i = 0; i < sizeof bad_inputs / sizeof bad_inputs[0]; i++) {
        Lexer l2;
        Token t;
        int guard = 0;
        lexer_init(&l2, bad_inputs[i], strlen(bad_inputs[i]));
        do { t = lexer_next(&l2); } while (t.type != TOK_ERROR && t.type != TOK_EOF && ++guard < 100);
        CHECK(t.type == TOK_ERROR);
        const LexError first = *lexer_error(&l2);
        for (int k = 0; k < 5; k++) {
            CHECK(lexer_next(&l2).type == TOK_ERROR);
            CHECK(lexer_error(&l2)->line == first.line && lexer_error(&l2)->column == first.column);
            CHECK(strcmp(lexer_error(&l2)->message, first.message) == 0);
        }
    }
}

static void test_eof_is_sticky(void)
{
    Lexer lx;
    lexer_init(&lx, "a:\n  b\n", 7);
    Token t;
    do { t = lexer_next(&lx); } while (t.type != TOK_EOF);
    for (int i = 0; i < 5; i++) CHECK(lexer_next(&lx).type == TOK_EOF);
    CHECK(lexer_error(&lx) == NULL);
}

/* ------------------------------------------------------------------ */
/* Tests: structural properties                                        */
/* ------------------------------------------------------------------ */

static void test_tokens_point_into_source(void)
{
    const char *src = "fact role(\"a b\", 42)\nrule x(Y):\n    p(Y)\n";
    Lexed *l = lex(src);
    size_t len = strlen(src);
    for (int i = 0; i < l->count; i++) {
        const Token *t = &l->toks[i];
        CHECK(t->start >= src && t->start + t->length <= src + len + 1);
    }
}

static void test_token_names(void)
{
    for (int t = 0; t < TOK_TYPE_COUNT; t++) {
        const char *name = token_type_name((TokenType)t);
        CHECK(name != NULL && strcmp(name, "UNKNOWN") != 0);
        for (int u = t + 1; u < TOK_TYPE_COUNT; u++)
            CHECK(strcmp(name, token_type_name((TokenType)u)) != 0);   /* all distinct */
    }
    CHECK(strcmp(token_type_name(TOK_TYPE_COUNT), "UNKNOWN") == 0);
}

/* ------------------------------------------------------------------ */
/* Tests: realistic policy                                             */
/* ------------------------------------------------------------------ */

static void test_realistic_policy(void)
{
    const char *policy =
        "# policy\n"
        "fact role(agent, developer)\n"
        "fact transfer_limit(finance_bot, 10000)\n"
        "\n"
        "rule is_admin(User):\n"
        "    role(User, admin)\n"
        "\n"
        "allow delete(User, Resource):\n"
        "    owns_via_team(User, Resource)   # second clause = OR\n"
        "    not is_protected(Resource)\n"
        "\n"
        "deny delete(User, Resource):\n"
        "    is_protected(Resource)\n"
        "    not role(User, admin)\n"
        "\n"
        "allow transfer(User, Account):\n"
        "    transfer_limit(User, Limit)\n"
        "    amount(Account, Amt)\n"
        "    Amt <= Limit\n"
        "\n"
        "query is_admin(\"admin user\")\n"
        "query is_protected(_)\n";
    Lexed *l = lex(policy);

    CHECK(!l->errored);
    CHECK(l->toks[l->count - 1].type == TOK_EOF);
    CHECK(count_type(l, TOK_FACT) == 2);
    CHECK(count_type(l, TOK_RULE) == 1);
    CHECK(count_type(l, TOK_ALLOW) == 2);
    CHECK(count_type(l, TOK_DENY) == 1);
    CHECK(count_type(l, TOK_QUERY) == 2);
    CHECK(count_type(l, TOK_NOT) == 2);
    CHECK(count_type(l, TOK_LTE) == 1);
    CHECK(count_type(l, TOK_INT) == 1);
    CHECK(count_type(l, TOK_STRING) == 1);
    CHECK(count_type(l, TOK_WILDCARD) == 1);
    CHECK(count_type(l, TOK_INDENT) == 4);              /* one block per rule/allow/deny */
    CHECK(count_type(l, TOK_INDENT) == count_type(l, TOK_DEDENT));
}

/* ------------------------------------------------------------------ */
/* Test: randomized stress (deterministic seed -> reproducible)        */
/* ------------------------------------------------------------------ */

static unsigned long long g_rng = 0x9E3779B97F4A7C15ULL;

static unsigned rnd(void)                               /* xorshift64* */
{
    g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
    return (unsigned)((g_rng * 0x2545F4914F6CDD1DULL) >> 32);
}

static void test_random_input_never_breaks_invariants(void)
{
    static const char alphabet[] = "abcXYZ_.019 \n\n\t\r\"#(),:<>=!-@fact rule not allow deny query";
    static char buf[300];
    static Lexed l;

    for (int iter = 0; iter < 30000; iter++) {
        size_t len = rnd() % 200;
        for (size_t i = 0; i < len; i++)
            buf[i] = (rnd() % 20 == 0) ? (char)(rnd() & 0xFF)       /* occasional raw byte */
                                       : alphabet[rnd() % (sizeof alphabet - 1)];
        lex_n(&l, buf, len);

        /* 1. it terminated (reached EOF or ERROR within a generous cap) */
        const Token *last = &l.toks[l.count - 1];
        if (!(last->type == TOK_EOF || last->type == TOK_ERROR)) {
            g_checks++; g_failures++;
            fprintf(stderr, "    FAIL: lexer did not terminate on random input #%d\n", iter);
            return;
        }
        /* 2. positions are valid and pointers stay in bounds */
        for (int i = 0; i < l.count; i++) {
            const Token *t = &l.toks[i];
            if (t->line < 1 || t->column < 1 || t->start < buf || t->start + t->length > buf + len + 0) {
                if (!(t->length == 0 && t->start <= buf + len && t->start >= buf)) {
                    g_checks++; g_failures++;
                    fprintf(stderr, "    FAIL: bad position/pointer on random input #%d\n", iter);
                    return;
                }
            }
        }
        /* 3. a successful run always has balanced INDENT/DEDENT */
        if (!l.errored && count_type(&l, TOK_INDENT) != count_type(&l, TOK_DEDENT)) {
            g_checks++; g_failures++;
            fprintf(stderr, "    FAIL: unbalanced INDENT/DEDENT on random input #%d\n", iter);
            return;
        }
        /* 4. NEWLINE never appears twice in a row */
        for (int i = 1; i < l.count; i++) {
            if (l.toks[i].type == TOK_NEWLINE && l.toks[i - 1].type == TOK_NEWLINE) {
                g_checks++; g_failures++;
                fprintf(stderr, "    FAIL: empty line produced a NEWLINE on random input #%d\n", iter);
                return;
            }
        }
        g_checks++;
    }
}

/* ------------------------------------------------------------------ */
/* Runner                                                              */
/* ------------------------------------------------------------------ */

typedef struct { const char *name; void (*fn)(void); } TestCase;

#define TEST(fn) {#fn, fn}

int main(void)
{
    static const TestCase tests[] = {
        TEST(test_empty_and_blank_inputs),
        TEST(test_simple_fact),
        TEST(test_keywords),
        TEST(test_words),
        TEST(test_punctuation),
        TEST(test_operators),
        TEST(test_integers),
        TEST(test_strings),
        TEST(test_comments),
        TEST(test_missing_trailing_newline),
        TEST(test_crlf_line_endings),
        TEST(test_simple_block),
        TEST(test_multi_line_body_has_one_indent),
        TEST(test_nested_blocks),
        TEST(test_blank_and_comment_lines_do_not_affect_indentation),
        TEST(test_indented_first_line),
        TEST(test_inconsistent_dedent),
        TEST(test_tabs),
        TEST(test_max_indent_depth),
        TEST(test_line_and_column_tracking),
        TEST(test_error_positions),
        TEST(test_unexpected_characters),
        TEST(test_embedded_nul),
        TEST(test_errors_are_sticky),
        TEST(test_eof_is_sticky),
        TEST(test_tokens_point_into_source),
        TEST(test_token_names),
        TEST(test_realistic_policy),
        TEST(test_random_input_never_breaks_invariants),
    };
    int failed_tests = 0;

    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int before = g_failures;
        tests[i].fn();
        if (g_failures == before) {
            printf("  ok    %s\n", tests[i].name);
        } else {
            printf("  FAIL  %s\n", tests[i].name);
            failed_tests++;
        }
    }
    printf("\n%d checks, %d failed, %zu/%zu tests passed\n", g_checks, g_failures,
           sizeof tests / sizeof tests[0] - (size_t)failed_tests, sizeof tests / sizeof tests[0]);
    return g_failures == 0 ? 0 : 1;
}
