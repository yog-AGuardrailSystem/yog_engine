#ifndef YOG_PARSER_H
#define YOG_PARSER_H

#include <stddef.h>
#include "lexer/lexer.h"
#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    YOG_PARSE_OK = 0,
    YOG_PARSE_SYNTAX_ERROR,
    YOG_PARSE_LEXICAL_ERROR,
    YOG_PARSE_OUT_OF_MEMORY,
    YOG_PARSE_INVALID_ARGUMENT
} YogParseStatus;

typedef struct {
    YogParseStatus code;
    int line;
    int column;
    char message[192];
} YogParseError;

/*
 * Consume tokens from an already initialized Lexer. The lexer and source are
 * caller-owned. AST text slices point into the source; keep it alive while
 * using the returned program. On failure, *out_program is NULL.
 */
YogParseStatus yog_parse(Lexer *lexer, YogProgram **out_program, YogParseError *out_error);
const char *yog_parse_status_name(YogParseStatus status);

#ifdef __cplusplus
}
#endif
#endif
