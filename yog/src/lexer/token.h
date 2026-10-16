/*
 * token.h -- the vocabulary shared by the lexer and (later) the parser.
 *
 * Why a separate header?  The parser must know what a Token is, but must NOT
 * depend on how the lexer produces one.  Keeping the data definition here
 * means lexer.h can change freely without touching the parser.
 */
#ifndef YOG_TOKEN_H
#define YOG_TOKEN_H

#include <stddef.h>

/*
 * X-macro: ONE line per token type.  The enum and the name table are both
 * generated from this list, so they can never get out of sync.
 * To add a token: add one X(...) line here, nothing else.
 */
#define YOG_TOKEN_TYPES(X)                                                    \
    /* --- structure --- */                                                   \
    X(TOK_EOF,      "EOF")      /* end of input (returned forever)       */   \
    X(TOK_ERROR,    "ERROR")    /* lexical error; see lexer_error()      */   \
    X(TOK_NEWLINE,  "NEWLINE")  /* end of a non-blank line               */   \
    X(TOK_INDENT,   "INDENT")   /* indentation increased                 */   \
    X(TOK_DEDENT,   "DEDENT")   /* indentation decreased (one per level) */   \
    /* --- names and literals --- */                                          \
    X(TOK_IDENT,    "IDENT")    /* lowercase word: alice, role, app.yaml */   \
    X(TOK_VAR,      "VAR")      /* Uppercase word: User, DB              */   \
    X(TOK_WILDCARD, "WILDCARD") /* a lone underscore                     */   \
    X(TOK_STRING,   "STRING")   /* "quoted atom" (lexeme excludes quotes)*/   \
    X(TOK_INT,      "INT")      /* 42, -7  (value in Token.int_value)    */   \
    /* --- keywords --- */                                                    \
    X(TOK_FACT,     "FACT")                                                   \
    X(TOK_RULE,     "RULE")                                                   \
    X(TOK_ALLOW,    "ALLOW")                                                  \
    X(TOK_DENY,     "DENY")                                                   \
    X(TOK_QUERY,    "QUERY")                                                  \
    X(TOK_NOT,      "NOT")                                                    \
    /* --- punctuation --- */                                                 \
    X(TOK_LPAREN,   "LPAREN")                                                 \
    X(TOK_RPAREN,   "RPAREN")                                                 \
    X(TOK_COMMA,    "COMMA")                                                  \
    X(TOK_COLON,    "COLON")                                                  \
    /* --- comparison operators --- */                                        \
    X(TOK_EQ,       "EQ")       /* ==  */                                     \
    X(TOK_NEQ,      "NEQ")      /* !=  */                                     \
    X(TOK_LT,       "LT")       /* <   */                                     \
    X(TOK_LTE,      "LTE")      /* <=  */                                     \
    X(TOK_GT,       "GT")       /* >   */                                     \
    X(TOK_GTE,      "GTE")      /* >=  */

typedef enum {
#define YOG_X(id, name) id,
    YOG_TOKEN_TYPES(YOG_X)
#undef YOG_X
    TOK_TYPE_COUNT /* not a real token: number of token types */
} TokenType;

/* Human-readable name, for error messages, tests and debug dumps. */
static inline const char *token_type_name(TokenType type)
{
    switch (type) {
#define YOG_X(id, name) case id: return name;
        YOG_TOKEN_TYPES(YOG_X)
#undef YOG_X
    default:
        return "UNKNOWN";
    }
}

/*
 * A token does NOT own any memory.  `start` points INTO the source buffer
 * that was given to lexer_init(), so it is only valid while that buffer is
 * alive, and it is NOT NUL-terminated -- always use `length`.
 *
 *   TOK_STRING : start/length cover the text BETWEEN the quotes.
 *   TOK_INT    : start/length cover the digits; the value is in int_value.
 *   NEWLINE/INDENT/DEDENT/EOF/ERROR : length is 0.
 *
 * line and column are 1-based.
 */
typedef struct {
    TokenType   type;
    const char *start;
    size_t      length;
    long long   int_value; /* meaningful only when type == TOK_INT */
    int         line;
    int         column;
} Token;

#endif /* YOG_TOKEN_H */
