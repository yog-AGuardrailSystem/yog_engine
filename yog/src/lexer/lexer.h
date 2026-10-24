/*
 * lexer.h -- public interface of the YOG lexer.
 *
 * Usage:
 *     Lexer lx;
 *     lexer_init(&lx, source, strlen(source));
 *     for (;;) {
 *         Token t = lexer_next(&lx);
 *         if (t.type == TOK_ERROR) { report(lexer_error(&lx)); break; }
 *         if (t.type == TOK_EOF)   break;
 *         ...
 *     }
 *
 * Design rules (these are what make it easy to test):
 *   - No file I/O, no malloc, no printing, no global state.  It only ever
 *     sees a (pointer, length) pair, so tests just pass string literals.
 *   - The caller owns the source buffer and must keep it alive while the
 *     tokens are in use (tokens point into it).
 *   - Errors are sticky: after the first TOK_ERROR, every call returns
 *     TOK_ERROR again.  After TOK_EOF, every call returns TOK_EOF again.
 *
 * Token stream contract (matches the Python reference, reference/yog.py):
 *   - Blank lines and comment-only lines produce NO tokens.
 *   - Every other line ends with exactly one TOK_NEWLINE (even if the file
 *     has no trailing newline).
 *   - TOK_INDENT / TOK_DEDENT are emitted BEFORE the first token of a line.
 *   - At end of input one TOK_DEDENT is emitted per still-open block,
 *     followed by TOK_EOF.  INDENT and DEDENT are therefore always balanced.
 *   - Only spaces may be used for indentation (tabs are an error).
 *   - LF and CRLF line endings are both accepted.
 */
#ifndef YOG_LEXER_H
#define YOG_LEXER_H

#include <stdbool.h>
#include <stddef.h>

#include "lexer/token.h"

/* Maximum number of simultaneously open indentation levels (incl. level 0). */
#define YOG_LEXER_MAX_INDENT 64
#define YOG_LEXER_ERROR_MSG_SIZE 128

typedef struct {
    char message[YOG_LEXER_ERROR_MSG_SIZE]; /* actionable, e.g. "unexpected character '@'" */
    int  line;                              /* 1-based */
    int  column;                            /* 1-based */
} LexError;

/*
 * The struct is declared here only so callers can put it on the stack.
 * Treat every field as PRIVATE: use the functions below, never touch fields.
 */
typedef struct {
    const char *src;
    size_t      len;
    size_t      pos;        /* cursor: index of the next unread byte        */
    int         line;       /* 1-based line of the cursor                   */
    size_t      line_start; /* index of the first byte of the current line  */

    size_t indent_stack[YOG_LEXER_MAX_INDENT]; /* open indentation levels   */
    size_t depth;                              /* entries in indent_stack   */
    size_t pending_dedents;                    /* DEDENTs still to emit     */
    bool   pending_indent;                     /* INDENT still to emit      */

    bool at_line_start; /* next call must measure indentation first */
    bool at_eof;        /* input exhausted and blocks closed        */

    bool     failed;
    LexError error;
} Lexer;

/* Prepare `lx` to tokenize `src[0..len)`.  A NULL `src` is treated as "". */
void lexer_init(Lexer *lx, const char *src, size_t len);

/* Return the next token.  Never returns NULL, never allocates, never blocks. */
Token lexer_next(Lexer *lx);

/* Details of the first error, or NULL if no error has happened yet. */
const LexError *lexer_error(const Lexer *lx);

#endif /* YOG_LEXER_H */
