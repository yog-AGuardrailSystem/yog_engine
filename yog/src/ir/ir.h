/*
 * ir.h -- the compiled policy image.
 *
 * The AST preserves what the user wrote; this IR is what the evaluator runs.
 * It is a clause-table representation (facts, rules, allow/deny clauses,
 * queries) plus a constant pool.  No bytecode yet: v1 policies are acyclic,
 * so a resolved clause table is both sufficient and easy to snapshot-test.
 *
 * Ownership: everything is owned by YogModule and released by yog_ir_free().
 * Text slices point into the source buffer, which the caller owns.
 */
#ifndef YOG_IR_H
#define YOG_IR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "parser/ast.h"
#include "sema/symbol_table.h"

#define YOG_IR_MAX_VALUES     65536u
#define YOG_IR_MAX_PREDICATES 4096u
#define YOG_IR_MAX_CLAUSES    65536u
#define YOG_IR_MAX_QUERIES    4096u
#define YOG_IR_MAX_ARGS       64u
#define YOG_IR_MAX_GOALS      256u

typedef enum { YOG_IR_VAR, YOG_IR_CONST } YogIRTermKind;

/* A variable term stores a clause-local slot; the evaluator rebases it onto
 * its activation frame.  A constant term stores a pool index. */
typedef struct {
    YogIRTermKind kind;
    size_t        index;
} YogIRTerm;

typedef enum { YOG_IR_CALL, YOG_IR_NOT, YOG_IR_COMPARE } YogIRGoalKind;

typedef struct {
    YogIRGoalKind           kind;
    YogComparisonOperator   comparison;  /* valid for YOG_IR_COMPARE */
    size_t                  predicate;   /* valid for CALL / NOT */
    YogIRTerm              *args;
    size_t                  arg_count;
    int                     line;
    int                     column;
} YogIRGoal;

typedef enum {
    YOG_CLAUSE_FACT,
    YOG_CLAUSE_RULE,
    YOG_CLAUSE_ALLOW,
    YOG_CLAUSE_DENY
} YogClauseKind;

typedef struct {
    YogClauseKind kind;
    size_t        predicate;
    YogIRTerm    *head;
    size_t        head_count;
    YogIRGoal    *goals;
    size_t        goal_count;
    size_t        variable_base;   /* no longer used by the evaluator; kept for dumps */
    size_t        variable_count;
    int           line;
    int           column;
} YogIRClause;

typedef struct {
    YogText          name;
    size_t           arity;
    YogPredicateRole role;
    size_t          *facts;
    size_t           fact_count;
    size_t           fact_capacity;
    size_t          *rules;
    size_t           rule_count;
    size_t           rule_capacity;
    size_t          *decisions;
    size_t           decision_count;
    size_t           decision_capacity;
} YogIRPredicate;

typedef struct {
    size_t    predicate;      /* SIZE_MAX when the query names an unknown predicate */
    YogText   name;
    size_t    arity;
    YogIRTerm *args;
    size_t    arg_count;
    YogText  *variables;      /* names by local slot, for printing bindings */
    size_t    variable_count;
    int       line;
    int       column;
} YogIRQuery;

typedef enum { YOG_VALUE_TEXT, YOG_VALUE_INTEGER } YogValueKind;

typedef struct {
    YogValueKind kind;
    YogText      text;       /* identifiers and quoted strings share this kind */
    int64_t      integer;
} YogValue;

typedef struct YogModule {
    const char     *source;
    size_t          source_length;

    YogValue       *values;
    size_t          value_count;
    size_t          value_capacity;

    YogIRPredicate *predicates;
    size_t          predicate_count;
    size_t          predicate_capacity;

    YogIRClause    *clauses;
    size_t          clause_count;
    size_t          clause_capacity;

    YogIRQuery     *queries;
    size_t          query_count;
    size_t          query_capacity;

    size_t          variable_count;   /* informational: total slots allocated */
} YogModule;

typedef struct {
    int  line;
    int  column;
    char message[192];
} YogIRError;

/* Consumes nothing; the AST and symbol table stay owned by the caller. */
bool yog_ir_build(const YogProgram *program, const YogSymbolTable *symbols,
                  const char *source, YogModule **out_module, YogIRError *error);
void yog_ir_free(YogModule *module);

/* Stable, line-oriented dump used by `yogc ir` and snapshot tests. */
void yog_ir_dump(const YogModule *module, FILE *out);

#endif /* YOG_IR_H */
