#include "sema/symbol_table.h"

#include <stdlib.h>
#include <string.h>

static bool text_equal(YogText a, YogText b)
{
    return a.length == b.length &&
           (a.length == 0 || memcmp(a.text, b.text, a.length) == 0);
}

void yog_symbol_table_init(YogSymbolTable *table)
{
    if (table == NULL) return;
    memset(table, 0, sizeof(*table));
}

void yog_symbol_table_free(YogSymbolTable *table)
{
    if (table == NULL) return;
    free(table->items);
    memset(table, 0, sizeof(*table));
}

bool yog_symbol_table_find(const YogSymbolTable *table, YogText name, size_t arity,
                           size_t *out_index)
{
    size_t i;
    if (table == NULL) return false;
    for (i = 0; i < table->count; ++i) {
        if (table->items[i].arity == arity && text_equal(table->items[i].name, name)) {
            if (out_index != NULL) *out_index = i;
            return true;
        }
    }
    return false;
}

bool yog_symbol_table_add(YogSymbolTable *table, YogText name, size_t arity,
                          YogPredicateRole role, int line, size_t *out_index)
{
    YogSymbol *grown;
    size_t next;

    if (table == NULL) return false;
    if (table->count == table->capacity) {
        next = table->capacity == 0 ? 8 : table->capacity * 2;
        if (next < table->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(table->items, next * sizeof(*grown));
        if (grown == NULL) return false;
        table->items = grown;
        table->capacity = next;
    }
    table->items[table->count].name = name;
    table->items[table->count].arity = arity;
    table->items[table->count].role = role;
    table->items[table->count].line = line;
    if (out_index != NULL) *out_index = table->count;
    table->count++;
    return true;
}

const char *yog_role_name(YogPredicateRole role)
{
    switch (role) {
    case YOG_ROLE_FACT: return "fact";
    case YOG_ROLE_RULE: return "rule head";
    case YOG_ROLE_DECISION: return "allow/deny head";
    default: return "unknown";
    }
}
