/*
 * builtin.c -- pure, bounded built-in predicates (see builtin.h).
 */
#include "builtin/builtin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ table */

typedef struct {
    const char  *name;
    YogBuiltinId id;
    size_t       min_arity;
    size_t       max_arity;   /* SIZE_MAX means variadic */
} BuiltinInfo;

static const BuiltinInfo BUILTINS[] = {
    {"in",          YOG_BUILTIN_IN,          2, (size_t)-1},
    {"matches",     YOG_BUILTIN_MATCHES,     2, 2},
    {"glob",        YOG_BUILTIN_GLOB,        2, 2},
    {"under",       YOG_BUILTIN_UNDER,       2, 2},
    {"starts_with", YOG_BUILTIN_STARTS_WITH, 2, 2},
    {"ends_with",   YOG_BUILTIN_ENDS_WITH,   2, 2},
    {"contains",    YOG_BUILTIN_CONTAINS,    2, 2},
    {"cidr",        YOG_BUILTIN_CIDR,        2, 2},
};
#define BUILTIN_COUNT (sizeof(BUILTINS) / sizeof(BUILTINS[0]))

YogBuiltinId yog_builtin_find(const char *name, size_t length, size_t arity)
{
    size_t i;
    for (i = 0; i < BUILTIN_COUNT; ++i) {
        const BuiltinInfo *info = &BUILTINS[i];
        if (strlen(info->name) != length || memcmp(info->name, name, length) != 0) continue;
        if (arity < info->min_arity || arity > info->max_arity) return YOG_BUILTIN_NONE;
        return info->id;
    }
    return YOG_BUILTIN_NONE;
}

const char *yog_builtin_name(YogBuiltinId id)
{
    size_t i;
    for (i = 0; i < BUILTIN_COUNT; ++i)
        if (BUILTINS[i].id == id) return BUILTINS[i].name;
    return "?";
}

static bool fail(char *message, size_t size, const char *fmt, const char *a)
{
    if (message != NULL && size > 0) (void)snprintf(message, size, fmt, a);
    return false;
}

/* ------------------------------------------------------------------ regex */
/*
 * A small Thompson-NFA matcher.  Supported syntax:
 *   literals  .  [abc] [a-z] [^...]  \d \w \s \D \W \S  \x (escaped literal)
 *   * + ?     |     ( )     ^ $      and a leading (?i) for case-insensitive.
 * There is no backtracking, so matching time is O(text * program) and a
 * hostile pattern cannot cause exponential blow-up.
 */

#define RE_MAX_NODES   512
#define RE_MAX_CLASSES 64
#define RE_MAX_INSTR   1024
#define RE_MAX_DEPTH   32

typedef enum {
    N_EMPTY, N_CHAR, N_ANY, N_CLASS, N_BOL, N_EOL, N_CAT, N_ALT, N_STAR, N_PLUS, N_QUEST
} NodeKind;

typedef struct {
    NodeKind      kind;
    int           a;
    int           b;
    unsigned char ch;
} Node;

typedef struct {
    Node          nodes[RE_MAX_NODES];
    int           node_count;
    unsigned char classes[RE_MAX_CLASSES][32];
    int           class_count;
    const char   *p;
    size_t        len;
    size_t        pos;
    bool          icase;
    int           depth;
    char          error[96];
} ReParser;

static int re_error(ReParser *rp, const char *message)
{
    if (rp->error[0] == '\0') (void)snprintf(rp->error, sizeof(rp->error), "%s", message);
    return -1;
}

static int re_node(ReParser *rp, NodeKind kind, int a, int b, unsigned char ch)
{
    Node *node;
    if (rp->node_count >= RE_MAX_NODES) return re_error(rp, "regular expression is too complex");
    node = &rp->nodes[rp->node_count];
    node->kind = kind;
    node->a = a;
    node->b = b;
    node->ch = ch;
    return rp->node_count++;
}

static void class_set(unsigned char *set, unsigned value)
{
    set[value >> 3] = (unsigned char)(set[value >> 3] | (1u << (value & 7u)));
}

static bool class_has(const unsigned char *set, unsigned value)
{
    return (set[value >> 3] & (1u << (value & 7u))) != 0;
}

static int re_new_class(ReParser *rp)
{
    if (rp->class_count >= RE_MAX_CLASSES) return re_error(rp, "too many character classes");
    memset(rp->classes[rp->class_count], 0, 32);
    return rp->class_count++;
}

static bool is_alpha_byte(unsigned c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

static void class_add_range(ReParser *rp, unsigned char *set, unsigned lo, unsigned hi)
{
    unsigned c;
    for (c = lo; c <= hi; ++c) {
        class_set(set, c);
        if (rp->icase && is_alpha_byte(c)) class_set(set, c ^ 0x20u);
    }
}

/* \d \w \s and their negations, added to `set`. */
static bool class_add_escape(unsigned char *set, int letter)
{
    unsigned c;
    switch (letter) {
    case 'd': for (c = '0'; c <= '9'; ++c) class_set(set, c); return true;
    case 'w':
        for (c = '0'; c <= '9'; ++c) class_set(set, c);
        for (c = 'a'; c <= 'z'; ++c) class_set(set, c);
        for (c = 'A'; c <= 'Z'; ++c) class_set(set, c);
        class_set(set, '_');
        return true;
    case 's':
        class_set(set, ' '); class_set(set, '\t'); class_set(set, '\n');
        class_set(set, '\r'); class_set(set, '\f'); class_set(set, '\v');
        return true;
    default: return false;
    }
}

static int re_literal(ReParser *rp, unsigned char ch)
{
    if (rp->icase && is_alpha_byte(ch)) {
        int cls = re_new_class(rp);
        if (cls < 0) return -1;
        class_set(rp->classes[cls], ch);
        class_set(rp->classes[cls], (unsigned)ch ^ 0x20u);
        return re_node(rp, N_CLASS, cls, 0, 0);
    }
    return re_node(rp, N_CHAR, 0, 0, ch);
}

static int re_alt(ReParser *rp);

static int re_escape_node(ReParser *rp)
{
    int letter;
    int cls;
    if (rp->pos >= rp->len) return re_error(rp, "pattern ends with a backslash");
    letter = (unsigned char)rp->p[rp->pos++];
    if (letter == 'd' || letter == 'w' || letter == 's') {
        cls = re_new_class(rp);
        if (cls < 0) return -1;
        (void)class_add_escape(rp->classes[cls], letter);
        return re_node(rp, N_CLASS, cls, 0, 0);
    }
    if (letter == 'D' || letter == 'W' || letter == 'S') {
        unsigned c;
        cls = re_new_class(rp);
        if (cls < 0) return -1;
        (void)class_add_escape(rp->classes[cls], letter + ('a' - 'A'));
        for (c = 0; c < 32; ++c) rp->classes[cls][c] = (unsigned char)~rp->classes[cls][c];
        return re_node(rp, N_CLASS, cls, 0, 0);
    }
    if (letter == 'n') return re_literal(rp, '\n');
    if (letter == 't') return re_literal(rp, '\t');
    if (letter == 'r') return re_literal(rp, '\r');
    return re_literal(rp, (unsigned char)letter);
}

static int re_class_node(ReParser *rp)
{
    bool negate = false;
    bool any = false;
    int cls = re_new_class(rp);
    unsigned char *set;
    if (cls < 0) return -1;
    set = rp->classes[cls];
    if (rp->pos < rp->len && rp->p[rp->pos] == '^') { negate = true; rp->pos++; }
    while (rp->pos < rp->len && rp->p[rp->pos] != ']') {
        unsigned lo = (unsigned char)rp->p[rp->pos++];
        if (lo == '\\') {
            int letter;
            if (rp->pos >= rp->len) return re_error(rp, "unterminated character class");
            letter = (unsigned char)rp->p[rp->pos++];
            if (class_add_escape(set, letter)) { any = true; continue; }
            if (letter == 'n') lo = '\n';
            else if (letter == 't') lo = '\t';
            else if (letter == 'r') lo = '\r';
            else lo = (unsigned)letter;
        }
        if (rp->pos + 1 < rp->len && rp->p[rp->pos] == '-' && rp->p[rp->pos + 1] != ']') {
            unsigned hi = (unsigned char)rp->p[rp->pos + 1];
            rp->pos += 2;
            if (hi < lo) return re_error(rp, "character range is reversed");
            class_add_range(rp, set, lo, hi);
        } else {
            class_add_range(rp, set, lo, lo);
        }
        any = true;
    }
    if (rp->pos >= rp->len) return re_error(rp, "unterminated character class");
    rp->pos++; /* ']' */
    if (!any) return re_error(rp, "empty character class");
    if (negate) {
        unsigned c;
        for (c = 0; c < 32; ++c) set[c] = (unsigned char)~set[c];
    }
    return re_node(rp, N_CLASS, cls, 0, 0);
}

static int re_atom(ReParser *rp)
{
    unsigned char c = (unsigned char)rp->p[rp->pos++];
    switch (c) {
    case '(': {
        int inner;
        if (++rp->depth > RE_MAX_DEPTH) return re_error(rp, "groups are nested too deeply");
        inner = re_alt(rp);
        if (inner < 0) return -1;
        if (rp->pos >= rp->len || rp->p[rp->pos] != ')') return re_error(rp, "missing ')'");
        rp->pos++;
        rp->depth--;
        return inner;
    }
    case '[': return re_class_node(rp);
    case '.': return re_node(rp, N_ANY, 0, 0, 0);
    case '^': return re_node(rp, N_BOL, 0, 0, 0);
    case '$': return re_node(rp, N_EOL, 0, 0, 0);
    case '\\': return re_escape_node(rp);
    case '*': case '+': case '?': return re_error(rp, "nothing to repeat");
    default: return re_literal(rp, c);
    }
}

static int re_repeat(ReParser *rp)
{
    int atom = re_atom(rp);
    if (atom < 0) return -1;
    if (rp->pos < rp->len) {
        char q = rp->p[rp->pos];
        if (q == '*' || q == '+' || q == '?') {
            rp->pos++;
            atom = re_node(rp, q == '*' ? N_STAR : (q == '+' ? N_PLUS : N_QUEST), atom, 0, 0);
            if (atom < 0) return -1;
            if (rp->pos < rp->len &&
                (rp->p[rp->pos] == '*' || rp->p[rp->pos] == '+' || rp->p[rp->pos] == '?'))
                return re_error(rp, "nested quantifiers are not supported");
        }
    }
    return atom;
}

static int re_cat(ReParser *rp)
{
    int left = -1;
    while (rp->pos < rp->len && rp->p[rp->pos] != '|' && rp->p[rp->pos] != ')') {
        int next = re_repeat(rp);
        if (next < 0) return -1;
        if (left < 0) {
            left = next;
        } else {
            left = re_node(rp, N_CAT, left, next, 0);
            if (left < 0) return -1;
        }
    }
    if (left < 0) return re_node(rp, N_EMPTY, 0, 0, 0);
    return left;
}

static int re_alt(ReParser *rp)
{
    int left = re_cat(rp);
    if (left < 0) return -1;
    while (rp->pos < rp->len && rp->p[rp->pos] == '|') {
        int right;
        rp->pos++;
        right = re_cat(rp);
        if (right < 0) return -1;
        left = re_node(rp, N_ALT, left, right, 0);
        if (left < 0) return -1;
    }
    return left;
}

typedef enum { I_CHAR, I_ANY, I_CLASS, I_BOL, I_EOL, I_SPLIT, I_JMP, I_MATCH } Op;

typedef struct {
    Op            op;
    int           x;
    int           y;
    unsigned char ch;
} Instr;

typedef struct {
    Instr instr[RE_MAX_INSTR];
    int   count;
    bool  overflow;
} Prog;

static int emit(Prog *prog, Op op, int x, int y, unsigned char ch)
{
    Instr *in;
    if (prog->count >= RE_MAX_INSTR) { prog->overflow = true; return 0; }
    in = &prog->instr[prog->count];
    in->op = op; in->x = x; in->y = y; in->ch = ch;
    return prog->count++;
}

static void gen(const ReParser *rp, Prog *prog, int n)
{
    const Node *node = &rp->nodes[n];
    int split, jmp;
    switch (node->kind) {
    case N_EMPTY: break;
    case N_CHAR: (void)emit(prog, I_CHAR, 0, 0, node->ch); break;
    case N_ANY: (void)emit(prog, I_ANY, 0, 0, 0); break;
    case N_CLASS: (void)emit(prog, I_CLASS, node->a, 0, 0); break;
    case N_BOL: (void)emit(prog, I_BOL, 0, 0, 0); break;
    case N_EOL: (void)emit(prog, I_EOL, 0, 0, 0); break;
    case N_CAT: gen(rp, prog, node->a); gen(rp, prog, node->b); break;
    case N_ALT:
        split = emit(prog, I_SPLIT, 0, 0, 0);
        prog->instr[split].x = prog->count;
        gen(rp, prog, node->a);
        jmp = emit(prog, I_JMP, 0, 0, 0);
        prog->instr[split].y = prog->count;
        gen(rp, prog, node->b);
        prog->instr[jmp].x = prog->count;
        break;
    case N_STAR:
        split = emit(prog, I_SPLIT, 0, 0, 0);
        prog->instr[split].x = prog->count;
        gen(rp, prog, node->a);
        (void)emit(prog, I_JMP, split, 0, 0);
        prog->instr[split].y = prog->count;
        break;
    case N_PLUS:
        split = prog->count;
        gen(rp, prog, node->a);
        jmp = emit(prog, I_SPLIT, split, 0, 0);
        prog->instr[jmp].y = prog->count;
        break;
    case N_QUEST:
        split = emit(prog, I_SPLIT, 0, 0, 0);
        prog->instr[split].x = prog->count;
        gen(rp, prog, node->a);
        prog->instr[split].y = prog->count;
        break;
    }
}

typedef struct {
    int      pcs[RE_MAX_INSTR];
    int      count;
} ThreadList;

/* Follow empty transitions from `pc`, evaluating assertions at `pos`. */
static void add_thread(const Prog *prog, ThreadList *list, unsigned *mark, unsigned generation,
                       int start_pc, size_t pos, size_t len)
{
    int stack[RE_MAX_INSTR];
    int top = 0;
    stack[top++] = start_pc;
    while (top > 0) {
        int pc = stack[--top];
        const Instr *in;
        if (mark[pc] == generation) continue;
        mark[pc] = generation;
        in = &prog->instr[pc];
        switch (in->op) {
        case I_JMP:
            if (top < RE_MAX_INSTR) stack[top++] = in->x;
            break;
        case I_SPLIT:
            if (top + 2 <= RE_MAX_INSTR) { stack[top++] = in->y; stack[top++] = in->x; }
            break;
        case I_BOL:
            if (pos == 0 && top < RE_MAX_INSTR) stack[top++] = pc + 1;
            break;
        case I_EOL:
            if (pos == len && top < RE_MAX_INSTR) stack[top++] = pc + 1;
            break;
        default:
            list->pcs[list->count++] = pc;
            break;
        }
    }
}

typedef struct {
    ReParser   parser;
    Prog       prog;
    unsigned   mark[RE_MAX_INSTR];
    ThreadList lists[2];
} ReWork;

static bool regex_search(ReWork *work, const char *text, size_t len)
{
    const ReParser *rp = &work->parser;
    const Prog *prog = &work->prog;
    unsigned *mark = work->mark;
    ThreadList *cl = &work->lists[0];
    ThreadList *nl = &work->lists[1];
    unsigned generation = 1;
    size_t pos;

    memset(work->mark, 0, sizeof(work->mark));
    cl->count = 0;
    add_thread(prog, cl, mark, generation, 0, 0, len);
    for (pos = 0; pos <= len; ++pos) {
        int i;
        unsigned char byte = pos < len ? (unsigned char)text[pos] : 0;
        nl->count = 0;
        generation++;
        for (i = 0; i < cl->count; ++i) {
            const Instr *in = &prog->instr[cl->pcs[i]];
            bool step = false;
            switch (in->op) {
            case I_MATCH: return true;
            case I_CHAR: step = pos < len && byte == in->ch; break;
            case I_ANY: step = pos < len; break;
            case I_CLASS: step = pos < len && class_has(rp->classes[in->x], byte); break;
            default: break;
            }
            if (step) add_thread(prog, nl, mark, generation, cl->pcs[i] + 1, pos + 1, len);
        }
        {
            ThreadList *tmp = cl;
            cl = nl;
            nl = tmp;
        }
        if (pos < len) add_thread(prog, cl, mark, generation, 0, pos + 1, len);
    }
    return false;
}

static bool builtin_matches(const YogBuiltinArg *text, const YogBuiltinArg *pattern,
                            bool *result, char *message, size_t message_size)
{
    ReWork *work;
    ReParser *rp;
    int root;
    size_t offset = 0;
    bool ok = true;

    if (pattern->length > YOG_BUILTIN_MAX_PATTERN)
        return fail(message, message_size, "matches: pattern is longer than %s bytes", "256");
    if (text->length > YOG_BUILTIN_MAX_TEXT)
        return fail(message, message_size, "matches: text is longer than %s bytes", "4096");

    /* The compiled program is tens of KiB; keep it off the stack so small
     * thread stacks (and WebAssembly) are safe.  Allocation failure is an
     * evaluation error, which callers treat as DENY. */
    work = calloc(1, sizeof(*work));
    if (work == NULL) return fail(message, message_size, "%s", "matches: out of memory");
    rp = &work->parser;
    rp->p = pattern->text;
    rp->len = pattern->length;
    if (rp->len >= 4 && memcmp(rp->p, "(?i)", 4) == 0) { rp->icase = true; offset = 4; }
    rp->pos = offset;

    root = re_alt(rp);
    if (root >= 0 && rp->pos < rp->len) root = re_error(rp, "unmatched ')'");
    if (root < 0) {
        char reason[128];
        (void)snprintf(reason, sizeof(reason), "matches: invalid pattern (%s)", rp->error);
        ok = fail(message, message_size, "%s", reason);
    } else {
        work->prog.count = 0;
        work->prog.overflow = false;
        gen(rp, &work->prog, root);
        (void)emit(&work->prog, I_MATCH, 0, 0, 0);
        if (work->prog.overflow)
            ok = fail(message, message_size, "%s", "matches: regular expression is too complex");
        else
            *result = regex_search(work, text->text, text->length);
    }
    free(work);
    return ok;
}

/* ------------------------------------------------------------------- glob */

static bool glob_match(const char *text, size_t tn, const char *pat, size_t pn)
{
    size_t t = 0, p = 0;
    size_t star_p = (size_t)-1, star_t = 0;
    while (t < tn) {
        if (p < pn && pat[p] == '*') {
            star_p = p++;
            star_t = t;
        } else if (p < pn && (pat[p] == '?' || pat[p] == text[t])) {
            t++; p++;
        } else if (star_p != (size_t)-1) {
            p = star_p + 1;
            t = ++star_t;
        } else {
            return false;
        }
    }
    while (p < pn && pat[p] == '*') p++;
    return p == pn;
}

/* ------------------------------------------------------------------ paths */

#define PATH_MAX_SEGMENTS 128

typedef struct {
    const char *text;
    size_t      length;
} Segment;

typedef struct {
    Segment segments[PATH_MAX_SEGMENTS];
    size_t  count;
    bool    absolute;
} NormalPath;

/* Normalises like a POSIX shell would: "." and empty segments vanish and ".."
 * removes the previous segment ("/.." stays at the root).  Returns false when
 * the path has more than PATH_MAX_SEGMENTS segments. */
static bool normalise_path(const char *path, size_t length, NormalPath *out)
{
    size_t i = 0;
    out->count = 0;
    out->absolute = length > 0 && path[0] == '/';
    while (i < length) {
        size_t start;
        while (i < length && path[i] == '/') i++;
        start = i;
        while (i < length && path[i] != '/') i++;
        if (i == start) continue;
        if (i - start == 1 && path[start] == '.') continue;
        if (i - start == 2 && path[start] == '.' && path[start + 1] == '.') {
            if (out->count > 0 &&
                !(out->segments[out->count - 1].length == 2 &&
                  out->segments[out->count - 1].text[0] == '.' &&
                  out->segments[out->count - 1].text[1] == '.')) {
                out->count--;
            } else if (!out->absolute) {
                if (out->count >= PATH_MAX_SEGMENTS) return false;
                out->segments[out->count].text = path + start;
                out->segments[out->count].length = 2;
                out->count++;
            }
            continue;
        }
        if (out->count >= PATH_MAX_SEGMENTS) return false;
        out->segments[out->count].text = path + start;
        out->segments[out->count].length = i - start;
        out->count++;
    }
    return true;
}

static bool path_under(const YogBuiltinArg *path, const YogBuiltinArg *prefix, bool *result,
                       char *message, size_t message_size)
{
    NormalPath p, q;
    size_t i;
    if (path->length > YOG_BUILTIN_MAX_TEXT || prefix->length > YOG_BUILTIN_MAX_TEXT)
        return fail(message, message_size, "under: path is longer than %s bytes", "4096");
    if (!normalise_path(path->text, path->length, &p) ||
        !normalise_path(prefix->text, prefix->length, &q))
        return fail(message, message_size, "under: path has more than %s segments", "128");
    *result = false;
    if (p.absolute != q.absolute || q.count > p.count) return true;
    for (i = 0; i < q.count; ++i)
        if (p.segments[i].length != q.segments[i].length ||
            memcmp(p.segments[i].text, q.segments[i].text, q.segments[i].length) != 0)
            return true;
    *result = true;
    return true;
}

/* ------------------------------------------------------------------- cidr */

static bool parse_ipv4(const char *s, size_t n, uint32_t *out, size_t *consumed)
{
    uint32_t value = 0;
    size_t i = 0;
    int part;
    for (part = 0; part < 4; ++part) {
        size_t start = i;
        unsigned number = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            number = number * 10u + (unsigned)(s[i] - '0');
            if (number > 255u) return false;
            i++;
        }
        if (i == start) return false;
        if (i - start > 1 && s[start] == '0') return false; /* no leading zeros */
        value = (value << 8) | number;
        if (part < 3) {
            if (i >= n || s[i] != '.') return false;
            i++;
        }
    }
    *out = value;
    *consumed = i;
    return true;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* RFC 4291 text form: 1-4 hex digits per group, one "::" standing for one or more all-zero groups, and an
 * optional dotted IPv4 tail in the last 32 bits.  No zone ids, no brackets, no prefix. */
static bool parse_ipv6(const char *s, size_t n, uint64_t *hi, uint64_t *lo)
{
    unsigned groups[8];
    unsigned full[8];
    size_t count = 0, i = 0, tail, k;
    int gap = -1;
    if (n < 2 || n > 45) return false;
    if (s[0] == ':') {
        if (s[1] != ':') return false;
        gap = 0;
        i = 2;
    }
    while (i < n) {
        size_t start = i;
        unsigned value = 0;
        while (i < n && hex_value(s[i]) >= 0) {
            value = value * 16u + (unsigned)hex_value(s[i]);
            i++;
            if (i - start > 4) return false;
        }
        if (i == start) return false;
        if (i < n && s[i] == '.') { /* an IPv4 tail: it must be the last thing and fill two groups */
            uint32_t v4;
            size_t used = 0;
            if (!parse_ipv4(s + start, n - start, &v4, &used) || used != n - start) return false;
            if (count > 6) return false;
            groups[count++] = (unsigned)(v4 >> 16);
            groups[count++] = (unsigned)(v4 & 0xFFFFu);
            break;
        }
        if (count >= 8) return false;
        groups[count++] = value;
        if (i == n) break;
        if (s[i] != ':') return false;
        i++;
        if (i < n && s[i] == ':') {
            if (gap >= 0) return false;
            gap = (int)count;
            i++;
        } else if (i == n) {
            return false; /* a single trailing colon */
        }
    }
    if (gap < 0 ? count != 8 : count > 7) return false;
    if (gap < 0) {
        for (k = 0; k < 8; ++k) full[k] = groups[k];
    } else {
        tail = count - (size_t)gap;
        for (k = 0; k < 8; ++k) full[k] = 0;
        for (k = 0; k < (size_t)gap; ++k) full[k] = groups[k];
        for (k = 0; k < tail; ++k) full[8 - tail + k] = groups[(size_t)gap + k];
    }
    *hi = ((uint64_t)full[0] << 48) | ((uint64_t)full[1] << 32) | ((uint64_t)full[2] << 16) | full[3];
    *lo = ((uint64_t)full[4] << 48) | ((uint64_t)full[5] << 32) | ((uint64_t)full[6] << 16) | full[7];
    return true;
}

static bool parse_prefix(const char *s, size_t n, unsigned max_digits, unsigned *bits)
{
    size_t i;
    unsigned value = 0;
    if (n == 0 || n > max_digits) return false;
    for (i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        value = value * 10u + (unsigned)(s[i] - '0');
    }
    *bits = value;
    return true;
}

static bool cidr_contains_v6(const YogBuiltinArg *net, uint64_t address_hi, uint64_t address_lo, bool *result,
                             char *message, size_t message_size)
{
    uint64_t net_hi = 0, net_lo = 0, mask_hi, mask_lo;
    const char *slash = memchr(net->text, '/', net->length);
    unsigned bits = 0;
    if (slash == NULL || !parse_ipv6(net->text, (size_t)(slash - net->text), &net_hi, &net_lo))
        return fail(message, message_size, "cidr: invalid network %s", "(expected a.b.c.d/n)");
    if (!parse_prefix(slash + 1, net->length - (size_t)(slash - net->text) - 1u, 3, &bits))
        return fail(message, message_size, "cidr: invalid network %s", "(bad prefix length)");
    if (bits > 128u) return fail(message, message_size, "cidr: invalid network %s", "(prefix over 128)");
    mask_hi = bits >= 64u ? ~(uint64_t)0 : (bits == 0u ? 0u : (~(uint64_t)0 << (64u - bits)));
    mask_lo = bits <= 64u ? 0u : (bits == 128u ? ~(uint64_t)0 : (~(uint64_t)0 << (128u - bits)));
    *result = (address_hi & mask_hi) == (net_hi & mask_hi) && (address_lo & mask_lo) == (net_lo & mask_lo);
    return true;
}

static bool cidr_contains(const YogBuiltinArg *ip, const YogBuiltinArg *net, bool *result,
                          char *message, size_t message_size)
{
    uint32_t address = 0, network, mask;
    uint64_t address_hi = 0, address_lo = 0;
    size_t used = 0;
    unsigned bits = 0;
    size_t i;
    bool ip_is_v6, net_is_v6;
    *result = false;
    if (ip->length > 64 || net->length > 64) return true;
    ip_is_v6 = memchr(ip->text, ':', ip->length) != NULL;
    net_is_v6 = memchr(net->text, ':', net->length) != NULL;
    if (ip_is_v6) {
        if (!parse_ipv6(ip->text, ip->length, &address_hi, &address_lo)) return true;
    } else if (!parse_ipv4(ip->text, ip->length, &address, &used) || used != ip->length) {
        return true;
    }
    if (net_is_v6) {
        bool inside = false;
        if (!cidr_contains_v6(net, address_hi, address_lo, &inside, message, message_size)) return false;
        *result = ip_is_v6 && inside; /* an IPv4 address is never inside an IPv6 network */
        return true;
    }
    if (!parse_ipv4(net->text, net->length, &network, &used) || used >= net->length ||
        net->text[used] != '/')
        return fail(message, message_size, "cidr: invalid network %s", "(expected a.b.c.d/n)");
    i = used + 1;
    if (i >= net->length || net->length - i > 2)
        return fail(message, message_size, "cidr: invalid network %s", "(bad prefix length)");
    for (; i < net->length; ++i) {
        if (net->text[i] < '0' || net->text[i] > '9')
            return fail(message, message_size, "cidr: invalid network %s", "(bad prefix length)");
        bits = bits * 10u + (unsigned)(net->text[i] - '0');
    }
    if (bits > 32u) return fail(message, message_size, "cidr: invalid network %s", "(prefix over 32)");
    mask = bits == 0 ? 0u : (0xFFFFFFFFu << (32u - bits));
    *result = !ip_is_v6 && (address & mask) == (network & mask);
    return true;
}

/* ------------------------------------------------------------------- eval */

static bool same_value(const YogBuiltinArg *a, const YogBuiltinArg *b)
{
    if (a->kind != b->kind) return false;
    if (a->kind == YOG_ARG_TEXT)
        return a->length == b->length && (a->length == 0 || memcmp(a->text, b->text, a->length) == 0);
    return a->integer == b->integer;
}

static bool need_text(const YogBuiltinArg *args, size_t count, YogBuiltinId id,
                      char *message, size_t message_size)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        if (args[i].kind != YOG_ARG_TEXT) {
            if (message != NULL && message_size > 0)
                (void)snprintf(message, message_size, "%s expects text arguments",
                               yog_builtin_name(id));
            return false;
        }
    }
    return true;
}

bool yog_builtin_eval(YogBuiltinId id, const YogBuiltinArg *args, size_t count,
                      bool *result, char *message, size_t message_size)
{
    size_t i;
    if (result == NULL || args == NULL) return fail(message, message_size, "%s", "built-in called with no arguments");
    *result = false;
    if (id == YOG_BUILTIN_IN) {
        if (count < 2) return fail(message, message_size, "%s", "in() needs a value and at least one candidate");
        for (i = 1; i < count; ++i) {
            if (same_value(&args[0], &args[i])) { *result = true; break; }
        }
        return true;
    }
    if (count != 2) return fail(message, message_size, "%s", "built-in called with the wrong number of arguments");
    if (!need_text(args, count, id, message, message_size)) return false;
    switch (id) {
    case YOG_BUILTIN_MATCHES: return builtin_matches(&args[0], &args[1], result, message, message_size);
    case YOG_BUILTIN_GLOB:
        if (args[0].length > YOG_BUILTIN_MAX_TEXT || args[1].length > YOG_BUILTIN_MAX_PATTERN)
            return fail(message, message_size, "%s", "glob: input is over the size limit");
        *result = glob_match(args[0].text, args[0].length, args[1].text, args[1].length);
        return true;
    case YOG_BUILTIN_UNDER: return path_under(&args[0], &args[1], result, message, message_size);
    case YOG_BUILTIN_STARTS_WITH:
        *result = args[1].length <= args[0].length &&
                  (args[1].length == 0 || memcmp(args[0].text, args[1].text, args[1].length) == 0);
        return true;
    case YOG_BUILTIN_ENDS_WITH:
        *result = args[1].length <= args[0].length &&
                  (args[1].length == 0 ||
                   memcmp(args[0].text + (args[0].length - args[1].length), args[1].text,
                          args[1].length) == 0);
        return true;
    case YOG_BUILTIN_CONTAINS:
        if (args[1].length == 0) { *result = true; return true; }
        if (args[1].length > args[0].length) return true;
        for (i = 0; i + args[1].length <= args[0].length; ++i) {
            if (memcmp(args[0].text + i, args[1].text, args[1].length) == 0) { *result = true; break; }
        }
        return true;
    case YOG_BUILTIN_CIDR: return cidr_contains(&args[0], &args[1], result, message, message_size);
    default: return fail(message, message_size, "%s", "unknown built-in");
    }
}
