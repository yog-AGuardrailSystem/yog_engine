/*
 * lexdump -- print the token stream of a .yog file.  A debugging aid:
 *
 *     ./lexdump examples/example.yog
 *
 * Output, one token per line:   LINE:COL  TYPE  [text]
 * Exit status: 0 = ok, 1 = lexical error (message on stderr), 2 = usage/IO.
 *
 * All file I/O lives HERE, not in the lexer, so the lexer stays testable
 * with plain strings.
 */
#include <stdio.h>
#include <stdlib.h>

#include "lexer/lexer.h"

static char *read_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    long size;

    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = malloc((size_t)size + 1);
    if (!buf) { fclose(fp); return NULL; }
    *out_len = fread(buf, 1, (size_t)size, fp);
    buf[*out_len] = '\0';
    fclose(fp);
    return buf;
}

int main(int argc, char **argv)
{
    size_t len = 0;
    char *src;
    Lexer lx;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.yog>\n", argv[0]);
        return 2;
    }
    src = read_file(argv[1], &len);
    if (!src) {
        fprintf(stderr, "%s: cannot read file\n", argv[1]);
        return 2;
    }

    lexer_init(&lx, src, len);
    for (;;) {
        Token t = lexer_next(&lx);

        if (t.type == TOK_ERROR) {
            const LexError *e = lexer_error(&lx);
            fprintf(stderr, "%s:%d:%d: lexical error: %s\n", argv[1], e->line, e->column, e->message);
            free(src);
            return 1;
        }

        printf("%d:%d %s", t.line, t.column, token_type_name(t.type));
        if (t.type == TOK_INT)
            printf(" %lld", t.int_value);
        else if (t.type == TOK_IDENT || t.type == TOK_VAR || t.type == TOK_STRING)
            printf(" %.*s", (int)t.length, t.start);
        printf("\n");

        if (t.type == TOK_EOF) break;
    }
    free(src);
    return 0;
}
