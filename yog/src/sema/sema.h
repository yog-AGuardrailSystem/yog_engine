/*
 * sema.h -- semantic analysis of a parsed policy.
 *
 * Ports the checks from the Python reference (check_program) and adds the one
 * rule the Python parser enforces while parsing: facts must be ground.
 *
 * Contract:
 *   - Returns true and fills `symbols` when the program is well formed.
 *   - Returns false and fills `error` with the FIRST problem found, in source
 *     order.  The symbol table is left empty on failure.
 *
 * Responsibilities are separated from the IR builder: this pass validates,
 * it does not lower.
 */
#ifndef YOG_SEMA_H
#define YOG_SEMA_H

#include <stdbool.h>

#include "parser/ast.h"
#include "sema/symbol_table.h"

typedef struct {
    int  line;
    int  column;
    char message[192];
} YogSemaError;

bool yog_sema_check(const YogProgram *program, YogSymbolTable *symbols,
                    YogSemaError *error);

#endif /* YOG_SEMA_H */
