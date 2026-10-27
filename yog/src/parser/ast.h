#ifndef YOG_AST_H
#define YOG_AST_H

#include <stddef.h>
#include <stdint.h>
#include "lexer/token.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Text is a non-owning slice into the original source buffer. */
typedef struct { const char *text; size_t length; } YogText;

typedef enum {
    YOG_TERM_VARIABLE, YOG_TERM_IDENTIFIER, YOG_TERM_STRING,
    YOG_TERM_INTEGER, YOG_TERM_WILDCARD
} YogTermType;

typedef struct {
    YogTermType type;
    YogText text;
    int64_t integer_value;
    int line;
    int column;
} YogTerm;

typedef struct {
    YogText predicate;
    YogTerm *terms;
    size_t term_count;
    int line;
    int column;
} YogAtom;

typedef enum {
    YOG_COMPARE_EQ, YOG_COMPARE_NE, YOG_COMPARE_LT,
    YOG_COMPARE_LE, YOG_COMPARE_GT, YOG_COMPARE_GE
} YogComparisonOperator;

typedef enum { YOG_GOAL_ATOM, YOG_GOAL_NEGATION, YOG_GOAL_COMPARISON } YogGoalType;
typedef struct YogGoal YogGoal;
struct YogGoal {
    YogGoalType type;
    int line;
    int column;
    union {
        YogAtom atom;
        struct { YogTerm left; YogComparisonOperator operator_type; YogTerm right; } comparison;
    } as;
};

typedef struct { YogGoal *goals; size_t goal_count; } YogBody;
typedef enum {
    YOG_STATEMENT_FACT, YOG_STATEMENT_RULE, YOG_STATEMENT_ALLOW,
    YOG_STATEMENT_DENY, YOG_STATEMENT_QUERY
} YogStatementType;
typedef struct YogStatement YogStatement;
struct YogStatement {
    YogStatementType type;
    int line;
    int column;
    union {
        YogAtom fact;
        struct { YogAtom head; YogBody body; } clause;
        YogAtom query;
    } as;
};
typedef struct { YogStatement *statements; size_t statement_count; } YogProgram;

int yog_term_init(YogTerm *term, YogTermType type, const Token *token);
int yog_atom_init(YogAtom *atom, YogText predicate, const YogTerm *terms,
                  size_t term_count, int line, int column);
int yog_body_append_goal(YogBody *body, const YogGoal *goal);
int yog_program_append_statement(YogProgram *program, const YogStatement *statement);
void yog_atom_free(YogAtom *atom);
void yog_goal_free(YogGoal *goal);
void yog_body_free(YogBody *body);
void yog_statement_free(YogStatement *statement);
void yog_program_free(YogProgram *program);

#ifdef __cplusplus
}
#endif
#endif
