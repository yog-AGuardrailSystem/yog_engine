#include "ast.h"

#include <stdlib.h>
#include <string.h>

int yog_term_init(YogTerm *term, YogTermType type, const Token *token)
{
    if (term == NULL || token == NULL) return 0;
    term->type = type;
    term->text.text = token->start;
    term->text.length = token->length;
    term->integer_value = (type == YOG_TERM_INTEGER) ? (int64_t)token->int_value : 0;
    term->line = token->line;
    term->column = token->column;
    return 1;
}

int yog_atom_init(YogAtom *atom, YogText predicate, const YogTerm *terms,
                  size_t term_count, int line, int column)
{
    YogTerm *copy = NULL;
    if (atom == NULL || (term_count > 0 && terms == NULL)) return 0;
    memset(atom, 0, sizeof(*atom));
    if (term_count > 0) {
        if (term_count > SIZE_MAX / sizeof(*copy)) return 0;
        copy = malloc(term_count * sizeof(*copy));
        if (copy == NULL) return 0;
        memcpy(copy, terms, term_count * sizeof(*copy));
    }
    atom->predicate = predicate;
    atom->terms = copy;
    atom->term_count = term_count;
    atom->line = line;
    atom->column = column;
    return 1;
}

int yog_body_append_goal(YogBody *body, const YogGoal *goal)
{
    YogGoal *grown;
    if (body == NULL || goal == NULL || body->goal_count >= SIZE_MAX / sizeof(*grown)) return 0;
    grown = realloc(body->goals, (body->goal_count + 1) * sizeof(*grown));
    if (grown == NULL) return 0;
    body->goals = grown;
    body->goals[body->goal_count++] = *goal;
    return 1;
}

int yog_program_append_statement(YogProgram *program, const YogStatement *statement)
{
    YogStatement *grown;
    if (program == NULL || statement == NULL || program->statement_count >= SIZE_MAX / sizeof(*grown)) return 0;
    grown = realloc(program->statements, (program->statement_count + 1) * sizeof(*grown));
    if (grown == NULL) return 0;
    program->statements = grown;
    program->statements[program->statement_count++] = *statement;
    return 1;
}

void yog_atom_free(YogAtom *atom)
{
    if (atom == NULL) return;
    free(atom->terms);
    memset(atom, 0, sizeof(*atom));
}

void yog_goal_free(YogGoal *goal)
{
    if (goal == NULL) return;
    if (goal->type == YOG_GOAL_ATOM || goal->type == YOG_GOAL_NEGATION) yog_atom_free(&goal->as.atom);
    memset(goal, 0, sizeof(*goal));
}

void yog_body_free(YogBody *body)
{
    size_t i;
    if (body == NULL) return;
    for (i = 0; i < body->goal_count; ++i) yog_goal_free(&body->goals[i]);
    free(body->goals);
    memset(body, 0, sizeof(*body));
}

void yog_statement_free(YogStatement *statement)
{
    if (statement == NULL) return;
    switch (statement->type) {
    case YOG_STATEMENT_FACT: yog_atom_free(&statement->as.fact); break;
    case YOG_STATEMENT_RULE:
    case YOG_STATEMENT_ALLOW:
    case YOG_STATEMENT_DENY:
        yog_atom_free(&statement->as.clause.head);
        yog_body_free(&statement->as.clause.body);
        break;
    case YOG_STATEMENT_QUERY: yog_atom_free(&statement->as.query); break;
    }
    memset(statement, 0, sizeof(*statement));
}

void yog_program_free(YogProgram *program)
{
    size_t i;
    if (program == NULL) return;
    for (i = 0; i < program->statement_count; ++i) yog_statement_free(&program->statements[i]);
    free(program->statements);
    free(program);
}
