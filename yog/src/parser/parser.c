#include "parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Two-token lookahead is enough to distinguish `name(...)` from comparisons. */
#define YOG_PARSER_LOOKAHEAD 3U
typedef struct {
    Lexer *lexer;
    Token lookahead[YOG_PARSER_LOOKAHEAD];
    size_t count;
    YogParseError *error;
} Parser;

static const Token *peek(Parser *p, size_t k)
{
    while (p->count <= k && p->count < YOG_PARSER_LOOKAHEAD) {
        p->lookahead[p->count++] = lexer_next(p->lexer);
    }
    return k < p->count ? &p->lookahead[k] : NULL;
}

static const Token *current(Parser *p) { return peek(p, 0); }
static Token take(Parser *p)
{
    Token result = { TOK_EOF, NULL, 0, 0, 0, 0 };
    size_t i;
    const Token *t = current(p);
    if (t == NULL) return result;
    result = *t;
    if (result.type != TOK_EOF && result.type != TOK_ERROR) {
        for (i = 1; i < p->count; ++i) p->lookahead[i - 1] = p->lookahead[i];
        --p->count;
    }
    return result;
}

static YogParseStatus set_error(Parser *p, const Token *t, YogParseStatus code,
                                const char *fmt, ...)
{
    va_list ap;
    if (p->error != NULL && p->error->code == YOG_PARSE_OK) {
        p->error->code = code;
        p->error->line = t != NULL ? t->line : 0;
        p->error->column = t != NULL ? t->column : 0;
        va_start(ap, fmt);
        (void)vsnprintf(p->error->message, sizeof(p->error->message), fmt, ap);
        va_end(ap);
    }
    return code;
}

static YogParseStatus fail_here(Parser *p, YogParseStatus code, const char *expected)
{
    const Token *t = current(p);
    if (t != NULL && t->type == TOK_ERROR) {
        const LexError *le = lexer_error(p->lexer);
        return set_error(p, t, YOG_PARSE_LEXICAL_ERROR, "Lexical error: %s",
                         le != NULL ? le->message : "unknown lexer error");
    }
    return set_error(p, t, code, "Expected %s, found %s", expected,
                     t != NULL ? token_type_name(t->type) : "no token");
}

static int match(Parser *p, TokenType type)
{
    const Token *t = current(p);
    if (t == NULL || t->type != type) return 0;
    (void)take(p);
    return 1;
}

static YogParseStatus expect(Parser *p, TokenType type, const char *description, Token *out)
{
    const Token *t = current(p);
    if (t == NULL || t->type != type) return fail_here(p, YOG_PARSE_SYNTAX_ERROR, description);
    if (out != NULL) *out = *t;
    (void)take(p);
    return YOG_PARSE_OK;
}

static YogText text_of(const Token *t)
{
    YogText text = { NULL, 0 };
    if (t != NULL) { text.text = t->start; text.length = t->length; }
    return text;
}

static int is_term(TokenType t)
{
    return t == TOK_VAR || t == TOK_IDENT || t == TOK_STRING || t == TOK_INT || t == TOK_WILDCARD;
}

static YogTermType term_type(TokenType t)
{
    switch (t) {
    case TOK_VAR: return YOG_TERM_VARIABLE;
    case TOK_IDENT: return YOG_TERM_IDENTIFIER;
    case TOK_STRING: return YOG_TERM_STRING;
    case TOK_INT: return YOG_TERM_INTEGER;
    case TOK_WILDCARD: return YOG_TERM_WILDCARD;
    default: return YOG_TERM_IDENTIFIER;
    }
}

static YogParseStatus parse_term(Parser *p, YogTerm *out)
{
    const Token *t = current(p);
    Token copy;
    if (out == NULL) return set_error(p, t, YOG_PARSE_INVALID_ARGUMENT, "Null term output");
    if (t == NULL || !is_term(t->type)) return fail_here(p, YOG_PARSE_SYNTAX_ERROR, "a term");
    copy = take(p);
    if (!yog_term_init(out, term_type(copy.type), &copy))
        return set_error(p, &copy, YOG_PARSE_OUT_OF_MEMORY, "Could not initialize term");
    return YOG_PARSE_OK;
}

static YogParseStatus parse_atom(Parser *p, YogAtom *out)
{
    Token pred;
    YogTerm *terms = NULL;
    size_t count = 0, capacity = 0;
    YogParseStatus status;
    memset(out, 0, sizeof(*out));
    status = expect(p, TOK_IDENT, "predicate identifier", &pred);
    if (status != YOG_PARSE_OK) return status;
    status = expect(p, TOK_LPAREN, "'('", NULL);
    if (status != YOG_PARSE_OK) return status;
    if (!match(p, TOK_RPAREN)) {
        for (;;) {
            YogTerm term;
            status = parse_term(p, &term);
            if (status != YOG_PARSE_OK) { free(terms); return status; }
            if (count == capacity) {
                size_t next = capacity == 0 ? 4 : capacity * 2;
                YogTerm *grown;
                if (next < capacity || next > SIZE_MAX / sizeof(*grown)) {
                    free(terms); return set_error(p, &pred, YOG_PARSE_OUT_OF_MEMORY, "Too many atom arguments");
                }
                grown = realloc(terms, next * sizeof(*grown));
                if (grown == NULL) { free(terms); return set_error(p, &pred, YOG_PARSE_OUT_OF_MEMORY, "Out of memory parsing atom"); }
                terms = grown; capacity = next;
            }
            terms[count++] = term;
            if (!match(p, TOK_COMMA)) break;
        }
        status = expect(p, TOK_RPAREN, "')'", NULL);
        if (status != YOG_PARSE_OK) { free(terms); return status; }
    }
    out->predicate = text_of(&pred);
    out->terms = terms;
    out->term_count = count;
    out->line = pred.line;
    out->column = pred.column;
    return YOG_PARSE_OK;
}

static int is_comparison(TokenType t)
{
    return t == TOK_EQ || t == TOK_NEQ || t == TOK_LT || t == TOK_LTE || t == TOK_GT || t == TOK_GTE;
}
static YogComparisonOperator comparison_type(TokenType t)
{
    switch (t) {
    case TOK_EQ: return YOG_COMPARE_EQ;
    case TOK_NEQ: return YOG_COMPARE_NE;
    case TOK_LT: return YOG_COMPARE_LT;
    case TOK_LTE: return YOG_COMPARE_LE;
    case TOK_GT: return YOG_COMPARE_GT;
    case TOK_GTE: return YOG_COMPARE_GE;
    default: return YOG_COMPARE_EQ;
    }
}

static YogParseStatus parse_goal(Parser *p, YogGoal *out)
{
    const Token *start = current(p);
    YogParseStatus status;
    memset(out, 0, sizeof(*out));
    if (start != NULL && start->type == TOK_NOT) {
        Token not_token = take(p);
        out->type = YOG_GOAL_NEGATION; out->line = not_token.line; out->column = not_token.column;
        status = parse_atom(p, &out->as.atom);
        return status;
    }
    if (start != NULL && is_term(start->type) && is_comparison(peek(p, 1)->type)) {
        Token left_token;
        status = parse_term(p, &out->as.comparison.left);
        if (status != YOG_PARSE_OK) return status;
        left_token = take(p);
        out->as.comparison.operator_type = comparison_type(left_token.type);
        status = parse_term(p, &out->as.comparison.right);
        if (status != YOG_PARSE_OK) return status;
        out->type = YOG_GOAL_COMPARISON; out->line = start->line; out->column = start->column;
        return YOG_PARSE_OK;
    }
    out->type = YOG_GOAL_ATOM;
    if (start != NULL) { out->line = start->line; out->column = start->column; }
    return parse_atom(p, &out->as.atom);
}

static YogParseStatus parse_body(Parser *p, YogBody *body)
{
    YogParseStatus status;
    memset(body, 0, sizeof(*body));
    status = expect(p, TOK_NEWLINE, "newline after ':'", NULL);
    if (status != YOG_PARSE_OK) return status;
    status = expect(p, TOK_INDENT, "an indented body", NULL);
    if (status != YOG_PARSE_OK) return status;
    if (current(p)->type == TOK_DEDENT) return fail_here(p, YOG_PARSE_SYNTAX_ERROR, "at least one body goal");
    while (current(p)->type != TOK_DEDENT && current(p)->type != TOK_EOF) {
        YogGoal goal;
        status = parse_goal(p, &goal);
        if (status != YOG_PARSE_OK) { yog_body_free(body); return status; }
        if (!yog_body_append_goal(body, &goal)) {
            yog_goal_free(&goal); yog_body_free(body);
            return set_error(p, current(p), YOG_PARSE_OUT_OF_MEMORY, "Out of memory appending body goal");
        }
        status = expect(p, TOK_NEWLINE, "newline after body goal", NULL);
        if (status != YOG_PARSE_OK) { yog_body_free(body); return status; }
    }
    status = expect(p, TOK_DEDENT, "end of indented body", NULL);
    if (status != YOG_PARSE_OK) yog_body_free(body);
    return status;
}

static YogParseStatus parse_statement(Parser *p, YogStatement *out)
{
    Token keyword;
    YogParseStatus status;
    const Token *t = current(p);
    memset(out, 0, sizeof(*out));
    if (t == NULL) return fail_here(p, YOG_PARSE_SYNTAX_ERROR, "statement keyword");
    if (t->type == TOK_FACT || t->type == TOK_QUERY) {
        TokenType kind = t->type;
        keyword = take(p);
        out->type = kind == TOK_FACT ? YOG_STATEMENT_FACT : YOG_STATEMENT_QUERY;
        out->line = keyword.line; out->column = keyword.column;
        status = kind == TOK_FACT ? parse_atom(p, &out->as.fact) : parse_atom(p, &out->as.query);
        if (status == YOG_PARSE_OK) status = expect(p, TOK_NEWLINE, "newline after statement", NULL);
        if (status != YOG_PARSE_OK) yog_statement_free(out);
        return status;
    }
    if (t->type == TOK_RULE || t->type == TOK_ALLOW || t->type == TOK_DENY) {
        keyword = take(p);
        out->type = keyword.type == TOK_RULE ? YOG_STATEMENT_RULE :
                    keyword.type == TOK_ALLOW ? YOG_STATEMENT_ALLOW : YOG_STATEMENT_DENY;
        out->line = keyword.line; out->column = keyword.column;
        status = parse_atom(p, &out->as.clause.head);
        if (status == YOG_PARSE_OK) status = expect(p, TOK_COLON, "':' after clause head", NULL);
        if (status == YOG_PARSE_OK) status = parse_body(p, &out->as.clause.body);
        if (status != YOG_PARSE_OK) yog_statement_free(out);
        return status;
    }
    return fail_here(p, YOG_PARSE_SYNTAX_ERROR, "fact, rule, allow, deny, or query");
}

YogParseStatus yog_parse(Lexer *lexer, YogProgram **out_program, YogParseError *out_error)
{
    Parser p;
    YogProgram *program;
    if (out_program != NULL) *out_program = NULL;
    if (out_error != NULL) { memset(out_error, 0, sizeof(*out_error)); out_error->code = YOG_PARSE_OK; }
    if (lexer == NULL || out_program == NULL) {
        if (out_error != NULL) { out_error->code = YOG_PARSE_INVALID_ARGUMENT; (void)snprintf(out_error->message, sizeof(out_error->message), "lexer and out_program must not be NULL"); }
        return YOG_PARSE_INVALID_ARGUMENT;
    }
    memset(&p, 0, sizeof(p)); p.lexer = lexer; p.error = out_error;
    program = calloc(1, sizeof(*program));
    if (program == NULL) return set_error(&p, current(&p), YOG_PARSE_OUT_OF_MEMORY, "Out of memory allocating program AST");
    for (;;) {
        const Token *t = current(&p);
        YogStatement statement;
        YogParseStatus status;
        if (t == NULL) { yog_program_free(program); return fail_here(&p, YOG_PARSE_SYNTAX_ERROR, "token"); }
        if (t->type == TOK_ERROR) { yog_program_free(program); return fail_here(&p, YOG_PARSE_LEXICAL_ERROR, "valid token"); }
        if (t->type == TOK_EOF) break;
        if (match(&p, TOK_NEWLINE)) continue;
        if (t->type == TOK_INDENT || t->type == TOK_DEDENT) {
            yog_program_free(program); return fail_here(&p, YOG_PARSE_SYNTAX_ERROR, "top-level statement");
        }
        status = parse_statement(&p, &statement);
        if (status != YOG_PARSE_OK) { yog_program_free(program); return status; }
        if (!yog_program_append_statement(program, &statement)) {
            yog_statement_free(&statement); yog_program_free(program);
            return set_error(&p, current(&p), YOG_PARSE_OUT_OF_MEMORY, "Out of memory appending statement");
        }
    }
    *out_program = program;
    return YOG_PARSE_OK;
}

const char *yog_parse_status_name(YogParseStatus status)
{
    switch (status) {
    case YOG_PARSE_OK: return "YOG_PARSE_OK";
    case YOG_PARSE_SYNTAX_ERROR: return "YOG_PARSE_SYNTAX_ERROR";
    case YOG_PARSE_LEXICAL_ERROR: return "YOG_PARSE_LEXICAL_ERROR";
    case YOG_PARSE_OUT_OF_MEMORY: return "YOG_PARSE_OUT_OF_MEMORY";
    case YOG_PARSE_INVALID_ARGUMENT: return "YOG_PARSE_INVALID_ARGUMENT";
    default: return "YOG_PARSE_UNKNOWN_STATUS";
    }
}
