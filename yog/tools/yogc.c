/*
 * yogc -- command-line front end of the YOG compiler.
 *
 *   yogc run   policy.yog [--trace]                 run every `query` in the file
 *   yogc check policy.yog ACTOR ACTION RESOURCE [--context "fact a(b); fact c(d)"] [--trace]
 *   yogc batch policy.yog [--trace]                 requests on stdin:
 *                                                   "actor action resource [| context]"
 *   yogc ir    policy.yog                           dump the compiled IR
 *
 * Exit status: 0 ok / allowed, 1 compile error, 2 usage or I/O error, 3 denied.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api/yog.h"
#include "ir/ir.h"

static char *read_file(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    char *buf;

    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = malloc((size_t)size + 1);
    if (!buf) { fclose(fp); return NULL; }
    *len = fread(buf, 1, (size_t)size, fp);
    buf[*len] = '\0';
    fclose(fp);
    return buf;
}

static Yog *load(const char *path)
{
    size_t len = 0;
    char *src = read_file(path, &len);
    YogError err;
    Yog *y;

    if (!src) {
        fprintf(stderr, "%s: cannot read file\n", path);
        exit(2);
    }
    y = yog_compile(src, len, &err);
    free(src);
    if (!y) {
        fprintf(stderr, "%s:%d:%d: error: %s\n", path, err.line, err.column, err.message);
        exit(1);
    }
    return y;
}

static void print_result(const YogResult *result, bool trace)
{
    printf("%s|%s\n", result->decision == YOG_ALLOW ? "ALLOW" : "DENY", result->reason);
    if (trace && result->trace != NULL) {
        const char *line = result->trace;
        while (*line) {
            const char *nl = strchr(line, '\n');
            size_t n = nl ? (size_t)(nl - line) : strlen(line);
            printf("> %.*s\n", (int)n, line);
            line += n + (nl ? 1u : 0u);
        }
    }
}

/* Split off the next whitespace-separated word (portable: no strtok_r). */
static char *next_word(char **cursor)
{
    char *s = *cursor;
    char *start;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s) { *cursor = s; return NULL; }
    start = s;
    while (*s && *s != ' ' && *s != '\t') s++;
    if (*s) *s++ = '\0';
    *cursor = s;
    return start;
}

static int cmd_batch(Yog *yog, bool trace)
{
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        char *context = strchr(line, '|');
        char *actor;
        char *action;
        char *resource;
        char *cursor;
        YogResult result;
        YogError err;

        line[strcspn(line, "\r\n")] = '\0';
        if (context) *context++ = '\0';
        cursor = line;
        actor = next_word(&cursor);
        action = next_word(&cursor);
        resource = next_word(&cursor);
        if (!actor || !action || !resource) {
            puts("ERROR|bad request line");
            puts("--");
            continue;
        }

        if (yog_check(yog, actor, action, resource, context, trace, &result, &err)) {
            print_result(&result, trace);
            yog_result_free(&result);
        } else {
            printf("ERROR|%s\n", err.message);
        }
        puts("--");
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd;
    const char *path;
    const char *context = NULL;
    bool trace = false;
    int npos = 0;
    const char *pos[8];
    Yog *yog;
    int rc = 0;
    int i;

    if (argc < 3) goto usage;
    cmd = argv[1];
    path = argv[2];
    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--trace") == 0) {
            trace = true;
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            context = argv[++i];
        } else if (npos < 8) {
            pos[npos++] = argv[i];
        }
    }

    yog = load(path);
    if (strcmp(cmd, "run") == 0) {
        if (!yog_run_queries(yog, stdout, trace)) rc = 2;
    } else if (strcmp(cmd, "ir") == 0) {
        yog_ir_dump(yog_module(yog), stdout);
    } else if (strcmp(cmd, "batch") == 0) {
        rc = cmd_batch(yog, trace);
    } else if (strcmp(cmd, "check") == 0 && npos == 3) {
        YogResult result;
        YogError err;
        if (!yog_check(yog, pos[0], pos[1], pos[2], context, trace, &result, &err)) {
            fprintf(stderr, "error: %s\n", err.message);
            rc = 2;
        } else {
            print_result(&result, trace);
            rc = result.decision == YOG_ALLOW ? 0 : 3;
            yog_result_free(&result);
        }
    } else {
        yog_free(yog);
        goto usage;
    }
    yog_free(yog);
    return rc;

usage:
    fputs("usage: yogc run|ir|batch POLICY [--trace]\n"
          "       yogc check POLICY ACTOR ACTION RESOURCE [--context \"fact a(b); ...\"] [--trace]\n", stderr);
    return 2;
}
