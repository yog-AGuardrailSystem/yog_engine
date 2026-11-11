/*
 * symbol_table.h -- predicate symbols shared by the semantic analyser and the
 * IR builder.
 *
 * This header deliberately knows nothing about the checker or the IR: it is
 * the vocabulary both passes agree on (the C analogue of token.h for the
 * lexer/parser pair).
 *
 * A predicate is identified by (name, arity).  Keeping the arity in the key is
 * what makes role/1 and role/2 two different predicates, matching the Python
 * reference.
 */
#ifndef YOG_SYMBOL_TABLE_H
#define YOG_SYMBOL_TABLE_H

#include <stdbool.h>
#include <stddef.h>

#include "parser/ast.h"

typedef enum {
    YOG_ROLE_FACT = 0,
    YOG_ROLE_RULE,
    YOG_ROLE_DECISION
} YogPredicateRole;

typedef struct {
    YogText          name;     /* slice into the source buffer */
    size_t           arity;
    YogPredicateRole role;
    int              line;      /* first defining statement */
} YogSymbol;

typedef struct {
    YogSymbol *items;
    size_t     count;
    size_t     capacity;
} YogSymbolTable;

void yog_symbol_table_init(YogSymbolTable *table);
void yog_symbol_table_free(YogSymbolTable *table);

/* Linear search on purpose: policies have tens of predicates, not millions.
 * Returns true and the index when found. */
bool yog_symbol_table_find(const YogSymbolTable *table, YogText name, size_t arity,
                           size_t *out_index);

/* Appends a symbol.  Returns false only on allocation failure; role conflicts
 * are detected by the caller via yog_symbol_table_find(). */
bool yog_symbol_table_add(YogSymbolTable *table, YogText name, size_t arity,
                          YogPredicateRole role, int line, size_t *out_index);

const char *yog_role_name(YogPredicateRole role);

#endif /* YOG_SYMBOL_TABLE_H */
