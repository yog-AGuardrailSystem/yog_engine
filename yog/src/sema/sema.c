/*
 * sema.c -- checks C0..C5.
 *
 *   C0  facts are ground (no variables, no wildcards)
 *   C1  a predicate keeps one role: fact, rule head, or allow/deny head
 *   C2  every rule-head variable is bound by the body
 *   C3  variables in `not` and in comparisons are bound earlier
 *   C4  every body predicate is defined by a fact or a rule
 *   C5  the rule dependency graph is acyclic (v1 forbids recursion)
 *   C6  constants passed to an `input` predicate match its declared types
 *   C7  built-in arguments are bound (or constant) before the call
 *   C8  `version` is the first statement, appears once, and is supported
 *   C9  `obligation` appears only in allow/require_approval bodies, bound args
 *
 * The implementation is deliberately data-driven: it never rewrites the AST.
 */
#include "sema/sema.h"

#include "builtin/builtin.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ helpers */

static bool text_equal(YogText a, YogText b)
{
    return a.length == b.length &&
           (a.length == 0 || memcmp(a.text, b.text, a.length) == 0);
}

static bool set_error(YogSemaError *error, int line, int column, const char *fmt, ...)
{
    va_list args;
    if (error == NULL) return false;
    error->line = line;
    error->column = column;
    va_start(args, fmt);
    (void)vsnprintf(error->message, sizeof(error->message), fmt, args);
    va_end(args);
    return false;
}

/* Variable names are compared by text; the set is tiny, so linear is right. */
typedef struct {
    YogText *items;
    size_t   count;
    size_t   capacity;
} VarSet;

static void var_set_init(VarSet *set) { memset(set, 0, sizeof(*set)); }

static void var_set_free(VarSet *set)
{
    if (set == NULL) return;
    free(set->items);
    memset(set, 0, sizeof(*set));
}

static bool var_set_contains(const VarSet *set, YogText name)
{
    size_t i;
    for (i = 0; i < set->count; ++i)
        if (text_equal(set->items[i], name)) return true;
    return false;
}

static bool var_set_add(VarSet *set, YogText name)
{
    YogText *grown;
    size_t next;
    if (var_set_contains(set, name)) return true;
    if (set->count == set->capacity) {
        next = set->capacity == 0 ? 8 : set->capacity * 2;
        if (next < set->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(set->items, next * sizeof(*grown));
        if (grown == NULL) return false;
        set->items = grown;
        set->capacity = next;
    }
    set->items[set->count++] = name;
    return true;
}

/* Atoms bind their variables; negated atoms and comparisons do not. */
static bool vars_from_atom(const YogAtom *atom, VarSet *set)
{
    size_t i;
    for (i = 0; i < atom->term_count; ++i)
        if (atom->terms[i].type == YOG_TERM_VARIABLE && !var_set_add(set, atom->terms[i].text))
            return false;
    return true;
}

static bool head_has_unbound(const YogAtom *head, const VarSet *bound)
{
    size_t i;
    for (i = 0; i < head->term_count; ++i)
        if (head->terms[i].type == YOG_TERM_VARIABLE && !var_set_contains(bound, head->terms[i].text))
            return true;
    return false;
}

static const YogAtom *goal_atom(const YogGoal *goal)
{
    if (goal->type == YOG_GOAL_ATOM || goal->type == YOG_GOAL_NEGATION) return &goal->as.atom;
    return NULL;
}

/* Highest policy language version this engine understands. */
#define YOG_SUPPORTED_LANGUAGE_VERSION 2

static bool is_builtin_atom(const YogAtom *atom)
{
    return yog_builtin_find(atom->predicate.text, atom->predicate.length, atom->term_count) !=
           YOG_BUILTIN_NONE;
}

typedef enum { TYPE_ANY, TYPE_TEXT, TYPE_INT, TYPE_BOOL, TYPE_INVALID } InputType;

static InputType parse_input_type(const YogTerm *term)
{
    if (term->type != YOG_TERM_IDENTIFIER) return TYPE_INVALID;
    if (term->text.length == 3 && memcmp(term->text.text, "any", 3) == 0) return TYPE_ANY;
    if (term->text.length == 4 && memcmp(term->text.text, "text", 4) == 0) return TYPE_TEXT;
    if (term->text.length == 3 && memcmp(term->text.text, "int", 3) == 0) return TYPE_INT;
    if (term->text.length == 4 && memcmp(term->text.text, "bool", 4) == 0) return TYPE_BOOL;
    return TYPE_INVALID;
}

static const char *input_type_name(InputType type)
{
    switch (type) {
    case TYPE_TEXT: return "text";
    case TYPE_INT: return "int";
    case TYPE_BOOL: return "bool";
    default: return "any";
    }
}

/* Does a constant term fit a declared type?  Variables always fit. */
static bool constant_fits(const YogTerm *term, InputType type)
{
    if (type == TYPE_ANY) return true;
    switch (term->type) {
    case YOG_TERM_VARIABLE:
    case YOG_TERM_WILDCARD: return true;
    case YOG_TERM_IDENTIFIER:
    case YOG_TERM_STRING: return type == TYPE_TEXT;
    case YOG_TERM_INTEGER: return type == TYPE_INT;
    case YOG_TERM_BOOLEAN: return type == TYPE_BOOL;
    default: return false;
    }
}

/* ------------------------------------------------------------------ C1 / C0 */

static bool build_symbols(const YogProgram *program, YogSymbolTable *symbols,
                          YogSemaError *error)
{
    size_t i;
    for (i = 0; i < program->statement_count; ++i) {
        const YogStatement *statement = &program->statements[i];
        const YogAtom *atom = NULL;
        YogPredicateRole role;
        size_t existing;
        YogText name;
        size_t arity;

        switch (statement->type) {
        case YOG_STATEMENT_FACT:
            atom = &statement->as.fact;
            role = YOG_ROLE_FACT;
            break;
        case YOG_STATEMENT_RULE:
            atom = &statement->as.clause.head;
            role = YOG_ROLE_RULE;
            break;
        case YOG_STATEMENT_ALLOW:
        case YOG_STATEMENT_DENY:
        case YOG_STATEMENT_REQUIRE_APPROVAL:
            atom = &statement->as.clause.head;
            role = YOG_ROLE_DECISION;
            break;
        case YOG_STATEMENT_INPUT: {
            size_t t;
            atom = &statement->as.fact;
            role = YOG_ROLE_INPUT;
            for (t = 0; t < atom->term_count; ++t) {
                if (parse_input_type(&atom->terms[t]) == TYPE_INVALID)
                    return set_error(error, atom->terms[t].line, atom->terms[t].column,
                                     "unknown input type in %.*s/%zu (use text, int, bool or any)",
                                     (int)atom->predicate.length, atom->predicate.text,
                                     atom->term_count);
            }
            break;
        }
        case YOG_STATEMENT_VERSION: {
            int64_t version = statement->as.fact.terms[0].integer_value;
            if (i != 0)
                return set_error(error, statement->line, statement->column,
                                 "version must be the first statement of the policy");
            if (version < 1 || version > YOG_SUPPORTED_LANGUAGE_VERSION)
                return set_error(error, statement->line, statement->column,
                                 "policy requires language version %lld; this engine supports 1 to %d",
                                 (long long)version, YOG_SUPPORTED_LANGUAGE_VERSION);
            continue; /* defines no predicate */
        }
        case YOG_STATEMENT_QUERY:
            continue; /* a query never defines a predicate */
        default:
            continue;
        }

        name = atom->predicate;
        arity = atom->term_count;

        if (yog_builtin_find(name.text, name.length, arity) != YOG_BUILTIN_NONE)
            return set_error(error, atom->line, atom->column,
                             "%.*s/%zu is a built-in predicate and cannot be redefined",
                             (int)name.length, name.text, arity);

        if (role == YOG_ROLE_FACT) {
            size_t t;
            for (t = 0; t < atom->term_count; ++t) {
                if (atom->terms[t].type == YOG_TERM_VARIABLE ||
                    atom->terms[t].type == YOG_TERM_WILDCARD)
                    return set_error(error, atom->line, atom->column,
                                     "facts must be ground (no variables): %.*s/%zu",
                                     (int)name.length, name.text, arity);
            }
        }

        if (yog_symbol_table_find(symbols, name, arity, &existing)) {
            if (role == YOG_ROLE_INPUT && symbols->items[existing].role == YOG_ROLE_INPUT)
                return set_error(error, atom->line, atom->column,
                                 "input %.*s/%zu is declared twice",
                                 (int)name.length, name.text, arity);
            if (symbols->items[existing].role == YOG_ROLE_INPUT || role == YOG_ROLE_INPUT)
                return set_error(error, atom->line, atom->column,
                                 "%.*s/%zu is an input (supplied with each request) and cannot "
                                 "also be a %s",
                                 (int)name.length, name.text, arity,
                                 yog_role_name(role == YOG_ROLE_INPUT ? symbols->items[existing].role : role));
            if (symbols->items[existing].role != role)
                return set_error(error, atom->line, atom->column,
                                 "predicate %.*s/%zu is both a %s and a %s; pick one role for it",
                                 (int)name.length, name.text, arity,
                                 yog_role_name(symbols->items[existing].role),
                                 yog_role_name(role));
        } else {
            size_t added;
            if (!yog_symbol_table_add(symbols, name, arity, role, atom->line, &added))
                return set_error(error, atom->line, atom->column, "out of memory building the symbol table");
            if (role == YOG_ROLE_INPUT) symbols->items[added].input_decl = atom;
        }
    }
    return true;
}

static bool lookup_known(const YogSymbolTable *symbols, YogText name, size_t arity,
                         size_t *out_index)
{
    size_t index;
    if (!yog_symbol_table_find(symbols, name, arity, &index)) return false;
    if (symbols->items[index].role == YOG_ROLE_DECISION) return false;
    if (out_index != NULL) *out_index = index;
    return true;
}

/* ----------------------------------------------------------- C2 / C3 / C4 */

static bool check_clause(const YogStatement *statement, const YogSymbolTable *symbols,
                         YogSemaError *error)
{
    const YogAtom *head = &statement->as.clause.head;
    const YogBody *body = &statement->as.clause.body;
    VarSet seen;
    size_t g;
    bool ok = true;

    var_set_init(&seen);

    /* C2 -- range restriction, rules only.  A decision head's variables are
     * inputs supplied by check(), so they are exempt (same as the reference). */
    if (statement->type == YOG_STATEMENT_RULE) {
        VarSet bound;
        size_t i;
        var_set_init(&bound);
        for (g = 0; g < body->goal_count; ++g) {
            if (body->goals[g].type == YOG_GOAL_ATOM && !is_builtin_atom(&body->goals[g].as.atom) &&
                !vars_from_atom(&body->goals[g].as.atom, &bound)) {
                ok = set_error(error, head->line, head->column, "out of memory analysing a rule body");
                goto done;
            }
        }
        for (i = 0; i < head->term_count; ++i) {
            if (head->terms[i].type == YOG_TERM_WILDCARD) {
                ok = set_error(error, head->line, head->column,
                               "wildcard is not allowed in the head of rule %.*s/%zu",
                               (int)head->predicate.length, head->predicate.text, head->term_count);
                goto done;
            }
        }
        if (head_has_unbound(head, &bound)) {
            for (i = 0; i < head->term_count; ++i) {
                if (head->terms[i].type != YOG_TERM_VARIABLE) continue;
                if (var_set_contains(&bound, head->terms[i].text)) continue;
                ok = set_error(error, head->line, head->column,
                               "variable %.*s in head of %.*s is never bound by the body",
                               (int)head->terms[i].text.length, head->terms[i].text.text,
                               (int)head->predicate.length, head->predicate.text);
                break;
            }
            var_set_free(&bound);
            goto done;
        }
        var_set_free(&bound);
    } else {
        /* Decision heads start with their parameters already bound. */
        if (!vars_from_atom(head, &seen)) {
            ok = set_error(error, head->line, head->column, "out of memory analysing a decision head");
            goto done;
        }
    }

    for (g = 0; g < body->goal_count; ++g) {
        const YogGoal *goal = &body->goals[g];

        /* C9 -- an obligation is an annotation on a winning allow or
         * require_approval clause.  Its arguments are read when the clause has
         * matched, so a variable only has to be bound somewhere in the body. */
        if (goal->type == YOG_GOAL_OBLIGATION) {
            size_t t;
            VarSet final_bound;
            size_t h;
            if (statement->type != YOG_STATEMENT_ALLOW &&
                statement->type != YOG_STATEMENT_REQUIRE_APPROVAL) {
                ok = set_error(error, goal->line, goal->column,
                               "obligation is only allowed in allow and require_approval clauses");
                goto done;
            }
            var_set_init(&final_bound);
            if (!vars_from_atom(head, &final_bound)) {
                var_set_free(&final_bound);
                ok = set_error(error, goal->line, goal->column, "out of memory analysing an obligation");
                goto done;
            }
            for (h = 0; h < body->goal_count; ++h) {
                if (body->goals[h].type == YOG_GOAL_ATOM && !is_builtin_atom(&body->goals[h].as.atom) &&
                    !vars_from_atom(&body->goals[h].as.atom, &final_bound)) {
                    var_set_free(&final_bound);
                    ok = set_error(error, goal->line, goal->column, "out of memory analysing an obligation");
                    goto done;
                }
            }
            for (t = 0; t < goal->as.atom.term_count; ++t) {
                const YogTerm *term = &goal->as.atom.terms[t];
                if (term->type == YOG_TERM_WILDCARD ||
                    (term->type == YOG_TERM_VARIABLE && !var_set_contains(&final_bound, term->text))) {
                    const char *what = term->type == YOG_TERM_WILDCARD ? "_" : term->text.text;
                    size_t what_len = term->type == YOG_TERM_WILDCARD ? 1 : term->text.length;
                    var_set_free(&final_bound);
                    ok = set_error(error, goal->line, goal->column,
                                   "variable %.*s is not bound by the clause body, so it cannot be "
                                   "used in an obligation", (int)what_len, what);
                    goto done;
                }
            }
            var_set_free(&final_bound);
            continue;
        }

        if (goal->type == YOG_GOAL_ATOM) {
            if (is_builtin_atom(&goal->as.atom)) {
                /* C7 -- built-ins read their arguments, so every variable must
                 * already be bound by an earlier positive atom. */
                size_t t;
                for (t = 0; t < goal->as.atom.term_count; ++t) {
                    const YogTerm *term = &goal->as.atom.terms[t];
                    if (term->type == YOG_TERM_WILDCARD ||
                        (term->type == YOG_TERM_VARIABLE && !var_set_contains(&seen, term->text))) {
                        const char *what = term->type == YOG_TERM_WILDCARD ? "_" : term->text.text;
                        size_t what_len = term->type == YOG_TERM_WILDCARD ? 1 : term->text.length;
                        ok = set_error(error, goal->line, goal->column,
                                       "variable %.*s is not bound before built-in %.*s",
                                       (int)what_len, what, (int)goal->as.atom.predicate.length,
                                       goal->as.atom.predicate.text);
                        goto done;
                    }
                }
            } else if (!vars_from_atom(&goal->as.atom, &seen)) {
                ok = set_error(error, goal->line, goal->column, "out of memory analysing a goal");
                goto done;
            }
        } else if (goal->type == YOG_GOAL_NEGATION) {
            /* C3 -- negated variables must already be bound. */
            size_t t;
            for (t = 0; t < goal->as.atom.term_count; ++t) {
                const YogTerm *term = &goal->as.atom.terms[t];
                if (term->type == YOG_TERM_WILDCARD ||
                    (term->type == YOG_TERM_VARIABLE && !var_set_contains(&seen, term->text))) {
                    const char *what = term->type == YOG_TERM_WILDCARD ? "_" : term->text.text;
                    size_t what_len = term->type == YOG_TERM_WILDCARD ? 1 : term->text.length;
                    ok = set_error(error, goal->line, goal->column,
                                   "variable %.*s is not bound before `not`",
                                   (int)what_len, what);
                    goto done;
                }
            }
        } else if (goal->type == YOG_GOAL_COMPARISON) {
            /* C3 -- comparison operands must already be bound. */
            const YogTerm *operands[2];
            size_t t;
            operands[0] = &goal->as.comparison.left;
            operands[1] = &goal->as.comparison.right;
            if ((operands[0]->type == YOG_TERM_BOOLEAN || operands[1]->type == YOG_TERM_BOOLEAN) &&
                goal->as.comparison.operator_type != YOG_COMPARE_EQ &&
                goal->as.comparison.operator_type != YOG_COMPARE_NE) {
                ok = set_error(error, goal->line, goal->column,
                               "booleans can only be compared with == and !=");
                goto done;
            }
            for (t = 0; t < 2; ++t) {
                const YogTerm *term = operands[t];
                if (term->type == YOG_TERM_WILDCARD ||
                    (term->type == YOG_TERM_VARIABLE && !var_set_contains(&seen, term->text))) {
                    const char *what = term->type == YOG_TERM_WILDCARD ? "_" : term->text.text;
                    size_t what_len = term->type == YOG_TERM_WILDCARD ? 1 : term->text.length;
                    ok = set_error(error, goal->line, goal->column,
                                   "variable %.*s is not bound before a comparison",
                                   (int)what_len, what);
                    goto done;
                }
            }
        }

        /* C4 -- every called predicate must be defined by a fact or a rule. */
        {
            const YogAtom *atom = goal_atom(goal);
            size_t symbol_index = 0;
            if (atom != NULL && !is_builtin_atom(atom) &&
                !lookup_known(symbols, atom->predicate, atom->term_count, &symbol_index)) {
                ok = set_error(error, goal->line, goal->column,
                               "%.*s/%zu is not defined by any fact or rule",
                               (int)atom->predicate.length, atom->predicate.text,
                               atom->term_count);
                goto done;
            }
            /* C6 -- constants given to an input predicate must have its type. */
            if (atom != NULL && !is_builtin_atom(atom) &&
                symbols->items[symbol_index].role == YOG_ROLE_INPUT) {
                const YogAtom *declaration = symbols->items[symbol_index].input_decl;
                size_t t;
                for (t = 0; declaration != NULL && t < atom->term_count; ++t) {
                    InputType type = parse_input_type(&declaration->terms[t]);
                    if (!constant_fits(&atom->terms[t], type)) {
                        ok = set_error(error, atom->terms[t].line, atom->terms[t].column,
                                       "argument %zu of input %.*s/%zu must be %s",
                                       t + 1, (int)atom->predicate.length, atom->predicate.text,
                                       atom->term_count, input_type_name(type));
                        goto done;
                    }
                }
            }
        }
    }

done:
    var_set_free(&seen);
    return ok;
}

/* --------------------------------------------------------------------- C5 */

typedef struct {
    size_t *items;
    size_t  count;
    size_t  capacity;
} IndexList;

static void index_list_free(IndexList *list)
{
    if (list == NULL) return;
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static bool index_list_add(IndexList *list, size_t value)
{
    size_t *grown;
    size_t next;
    if (list->count == list->capacity) {
        next = list->capacity == 0 ? 4 : list->capacity * 2;
        if (next < list->capacity || next > SIZE_MAX / sizeof(*grown)) return false;
        grown = realloc(list->items, next * sizeof(*grown));
        if (grown == NULL) return false;
        list->items = grown;
        list->capacity = next;
    }
    list->items[list->count++] = value;
    return true;
}

typedef struct {
    size_t node;
    size_t edge;
} DfsFrame;

static bool check_cycles(const YogProgram *program, const YogSymbolTable *symbols,
                         YogSemaError *error)
{
    IndexList *edges = NULL;
    unsigned char *color = NULL;
    DfsFrame *stack = NULL;
    size_t *path = NULL;
    size_t stack_count = 0;
    size_t path_count = 0;
    size_t i;
    bool ok = true;

    if (symbols->count == 0) return true;

    edges = calloc(symbols->count, sizeof(*edges));
    color = calloc(symbols->count, sizeof(*color));
    stack = calloc(symbols->count + 1, sizeof(*stack));
    path = calloc(symbols->count + 1, sizeof(*path));
    if (edges == NULL || color == NULL || stack == NULL || path == NULL) {
        ok = set_error(error, 1, 1, "out of memory checking rule cycles");
        goto done;
    }

    for (i = 0; i < program->statement_count; ++i) {
        const YogStatement *statement = &program->statements[i];
        size_t head_index;
        size_t g;

        if (statement->type != YOG_STATEMENT_RULE &&
            statement->type != YOG_STATEMENT_ALLOW &&
            statement->type != YOG_STATEMENT_DENY &&
            statement->type != YOG_STATEMENT_REQUIRE_APPROVAL)
            continue;
        if (!yog_symbol_table_find(symbols, statement->as.clause.head.predicate,
                                   statement->as.clause.head.term_count, &head_index))
            continue;
        for (g = 0; g < statement->as.clause.body.goal_count; ++g) {
            const YogAtom *atom = goal_atom(&statement->as.clause.body.goals[g]);
            size_t target;
            if (atom == NULL) continue;
            if (!yog_symbol_table_find(symbols, atom->predicate, atom->term_count, &target)) continue;
            if (symbols->items[target].role != YOG_ROLE_RULE) continue;
            if (!index_list_add(&edges[head_index], target)) {
                ok = set_error(error, statement->line, statement->column,
                               "out of memory checking rule cycles");
                goto done;
            }
        }
    }

    for (i = 0; i < symbols->count; ++i) {
        if (color[i] != 0) continue;
        if (symbols->items[i].role == YOG_ROLE_FACT) { color[i] = 2; continue; }

        stack_count = 0;
        path_count = 0;
        stack[stack_count].node = i;
        stack[stack_count].edge = 0;
        stack_count++;
        path[path_count++] = i;
        color[i] = 1;

        while (stack_count > 0) {
            DfsFrame *frame = &stack[stack_count - 1];
            size_t node = frame->node;

            if (frame->edge >= edges[node].count) {
                color[node] = 2;
                stack_count--;
                if (path_count > 0) path_count--;
                continue;
            }

            {
                size_t child = edges[node].items[frame->edge++];
                if (color[child] == 1) {
                    size_t k;
                    (void)set_error(error, symbols->items[child].line, 1, "rule cycle: ");
                    ok = false;
                    /* Append the path tail so the message is actionable. */
                    if (error != NULL) {
                        size_t used = strlen(error->message);
                        const size_t prefix = strlen("rule cycle: ");
                        for (k = 0; k < path_count && used + 40 < sizeof(error->message); ++k) {
                            int written;
                            written = snprintf(error->message + used,
                                               sizeof(error->message) - used,
                                               "%s%.*s/%zu",
                                               used > prefix ? " -> " : "",
                                               (int)symbols->items[path[k]].name.length,
                                               symbols->items[path[k]].name.text,
                                               symbols->items[path[k]].arity);
                            if (written < 0) break;
                            used += (size_t)written;
                        }
                        (void)snprintf(error->message + used, sizeof(error->message) - used,
                                       " -> %.*s/%zu",
                                       (int)symbols->items[child].name.length,
                                       symbols->items[child].name.text,
                                       symbols->items[child].arity);
                    }
                    goto done;
                }
                if (color[child] == 0) {
                    color[child] = 1;
                    stack[stack_count].node = child;
                    stack[stack_count].edge = 0;
                    stack_count++;
                    path[path_count++] = child;
                }
            }
        }
    }

done:
    if (edges != NULL) {
        for (i = 0; i < symbols->count; ++i) index_list_free(&edges[i]);
    }
    free(edges);
    free(color);
    free(stack);
    free(path);
    return ok;
}

/* ------------------------------------------------------------------ public */

bool yog_sema_check(const YogProgram *program, YogSymbolTable *symbols,
                    YogSemaError *error)
{
    size_t i;

    if (error != NULL) {
        error->line = 0;
        error->column = 0;
        error->message[0] = '\0';
    }
    if (program == NULL || symbols == NULL)
        return set_error(error, 0, 0, "invalid argument to the semantic analyser");

    if (!build_symbols(program, symbols, error)) {
        yog_symbol_table_free(symbols);
        return false;
    }

    for (i = 0; i < program->statement_count; ++i) {
        const YogStatement *statement = &program->statements[i];
        if (statement->type != YOG_STATEMENT_RULE &&
            statement->type != YOG_STATEMENT_ALLOW &&
            statement->type != YOG_STATEMENT_DENY &&
            statement->type != YOG_STATEMENT_REQUIRE_APPROVAL)
            continue;
        if (!check_clause(statement, symbols, error)) {
            yog_symbol_table_free(symbols);
            return false;
        }
    }

    if (!check_cycles(program, symbols, error)) {
        yog_symbol_table_free(symbols);
        return false;
    }

    return true;
}
