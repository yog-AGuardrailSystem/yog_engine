/*
 * unify.c -- substitution store and unification.
 *
 * A store is a stack of cells (one per variable slot of the activation being
 * evaluated) plus a trail of the cells that were bound, so backtracking is
 * O(bindings) and never copies the environment.
 *
 * Only unbound cells are ever bound, which is what keeps the trail undo
 * trivial: resetting a mark sets the cell back to "unbound".
 */
#include "vm/vm.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ value space */

const YogValue *yog_value_at(const YogValueSpace *space, size_t index)
{
    if (space == NULL || space->module == NULL) return NULL;
    if (index < space->module->value_count) return &space->module->values[index];
    index -= space->module->value_count;
    if (space->context != NULL) {
        if (index < space->context->value_count) return &space->context->values[index];
        index -= space->context->value_count;
    }
    if (index < space->request_count) return &space->request[index];
    return NULL;
}

static bool values_equal(const YogValueSpace *space, size_t left, size_t right)
{
    const YogValue *a = yog_value_at(space, left);
    const YogValue *b = yog_value_at(space, right);
    if (a == NULL || b == NULL) return false;
    if (a->kind != b->kind) return false;
    if (a->kind == YOG_VALUE_INTEGER) return a->integer == b->integer;
    if (a->text.length != b->text.length) return false;
    return a->text.length == 0 || memcmp(a->text.text, b->text.text, a->text.length) == 0;
}

/* ---------------------------------------------------------- substitutions */

void yog_store_init(YogStore *store)
{
    if (store != NULL) memset(store, 0, sizeof(*store));
}

void yog_store_free(YogStore *store)
{
    if (store == NULL) return;
    free(store->cells);
    free(store->trail);
    memset(store, 0, sizeof(*store));
}

size_t yog_store_mark(const YogStore *store)
{
    return store == NULL ? 0 : store->trail_count;
}

static bool store_ensure_cells(YogStore *store, size_t needed)
{
    size_t next;
    YogIRTerm *grown;
    if (needed <= store->cell_capacity) return true;
    next = store->cell_capacity == 0 ? 32 : store->cell_capacity;
    while (next < needed) {
        if (next > SIZE_MAX / 2) return false;
        next *= 2;
    }
    grown = realloc(store->cells, next * sizeof(*grown));
    if (grown == NULL) return false;
    store->cells = grown;
    store->cell_capacity = next;
    return true;
}

static bool trail_push(YogStore *store, size_t slot)
{
    size_t next;
    size_t *grown;
    if (store->trail_count == store->trail_capacity) {
        next = store->trail_capacity == 0 ? 32 : store->trail_capacity * 2;
        if (next < store->trail_capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(store->trail, next * sizeof(*grown));
        if (grown == NULL) return false;
        store->trail = grown;
        store->trail_capacity = next;
    }
    store->trail[store->trail_count++] = slot;
    return true;
}

bool yog_store_push_frame(YogStore *store, size_t count, size_t *out_base)
{
    size_t base = store->cell_count;
    size_t i;
    if (count > SIZE_MAX - base) return false;
    if (!store_ensure_cells(store, base + count)) return false;
    for (i = 0; i < count; ++i) {
        store->cells[base + i].kind = YOG_IR_VAR;
        store->cells[base + i].index = YOG_VM_UNBOUND;
    }
    store->cell_count = base + count;
    if (out_base != NULL) *out_base = base;
    return true;
}

bool yog_store_reset(YogStore *store, size_t mark)
{
    if (store == NULL || mark > store->trail_count) return false;
    while (store->trail_count > mark) {
        size_t slot = store->trail[--store->trail_count];
        store->cells[slot].kind = YOG_IR_VAR;
        store->cells[slot].index = YOG_VM_UNBOUND;
    }
    return true;
}

YogIRTerm yog_store_resolve(const YogStore *store, YogIRTerm term)
{
    size_t guard = 0;
    if (store == NULL) return term;
    while (term.kind == YOG_IR_VAR && term.index < store->cell_count) {
        YogIRTerm cell = store->cells[term.index];
        if (cell.kind == YOG_IR_VAR && cell.index == YOG_VM_UNBOUND) return term;
        term = cell;
        if (++guard > store->cell_count + 1) return term; /* defensive: never loop */
    }
    return term;
}

static bool bind_slot(YogStore *store, size_t slot, YogIRTerm term)
{
    if (slot >= store->cell_count) return false;
    if (!trail_push(store, slot)) return false;
    store->cells[slot] = term;
    return true;
}

bool yog_unify(YogStore *store, const YogValueSpace *space,
               YogIRTerm left, YogIRTerm right)
{
    YogIRTerm a = yog_store_resolve(store, left);
    YogIRTerm b = yog_store_resolve(store, right);

    if (a.kind == YOG_IR_VAR && b.kind == YOG_IR_VAR) {
        if (a.index == b.index) return true;
        return bind_slot(store, a.index, b);
    }
    if (a.kind == YOG_IR_VAR) return bind_slot(store, a.index, b);
    if (b.kind == YOG_IR_VAR) return bind_slot(store, b.index, a);
    return values_equal(space, a.index, b.index);
}
