/*
 * bench_yog.c -- measure compile time, check latency and resident memory.
 *
 *   bench_yog compile POLICY [--iterations N]
 *   bench_yog check POLICY ACTOR ACTION RESOURCE [--context "fact a(b)"] [--iterations N]
 *
 * Output is one JSON object per line on stdout, so scripts can aggregate
 * without parsing prose.  This harness measures the engine only: process
 * startup, file I/O and the CLI are measured end-to-end by
 * benchmarks/run_benchmarks.py.
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#endif

#include "api/yog.h"
#include "ir/ir.h"

static long rss_kb(void)
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters;
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) return -1;
    return (long)(counters.WorkingSetSize / 1024u);
#else
    FILE *statm = fopen("/proc/self/statm", "r");
    long total = 0;
    long resident = 0;
    long page_size;
    if (statm == NULL) return -1;
    if (fscanf(statm, "%ld %ld", &total, &resident) != 2) resident = -1;
    fclose(statm);
    page_size = sysconf(_SC_PAGESIZE);
    if (resident < 0 || page_size <= 0) return -1;
    return (resident * page_size) / 1024;
#endif
}

static double now_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1e9 / (double)frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
#endif
}

static int compare_double(const void *left, const void *right)
{
    double a = *(const double *)left;
    double b = *(const double *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

static double percentile(const double *sorted, size_t count, double fraction)
{
    size_t index;
    if (count == 0) return 0.0;
    index = (size_t)(fraction * (double)count);
    if (index >= count) index = count - 1;
    return sorted[index];
}

static char *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    long size;
    char *buffer;

    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    buffer = malloc((size_t)size + 1);
    if (buffer == NULL) { fclose(file); return NULL; }
    *length = fread(buffer, 1, (size_t)size, file);
    buffer[*length] = '\0';
    fclose(file);
    return buffer;
}

static void report_stats(const Yog *yog)
{
    const YogModule *module = yog_module(yog);
    if (module == NULL) return;
    printf("{\"mode\":\"stats\",\"predicates\":%zu,"
           "\"clauses\":%zu,\"values\":%zu,\"queries\":%zu}\n",
           module->predicate_count, module->clause_count,
           module->value_count, module->query_count);
}

static void report_latency(const char *mode, const char *decision,
                           const double *samples, size_t count, double elapsed_ns,
                           long rss_before, long rss_after)
{
    double *sorted;
    double sum = 0.0;
    size_t i;

    sorted = malloc(count * sizeof(*sorted));
    if (sorted == NULL) return;
    memcpy(sorted, samples, count * sizeof(*sorted));
    qsort(sorted, count, sizeof(*sorted), compare_double);
    for (i = 0; i < count; ++i) sum += samples[i];

    printf("{\"mode\":\"%s\",\"decision\":\"%s\","
           "\"iterations\":%zu,\"mean_us\":%.3f,\"p50_us\":%.3f,"
           "\"p95_us\":%.3f,\"p99_us\":%.3f,\"max_us\":%.3f,"
           "\"throughput_per_s\":%.1f,\"rss_before_kb\":%ld,\"rss_after_kb\":%ld}\n",
           mode, decision, count,
           (sum / (double)count) / 1000.0,
           percentile(sorted, count, 0.50) / 1000.0,
           percentile(sorted, count, 0.95) / 1000.0,
           percentile(sorted, count, 0.99) / 1000.0,
           sorted[count - 1] / 1000.0,
           (double)count / (elapsed_ns / 1e9),
           rss_before, rss_after);
    free(sorted);
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *policy;
    const char *context = NULL;
    const char *actor = NULL;
    const char *action = NULL;
    const char *resource = NULL;
    size_t iterations = 10000;
    char *source;
    size_t source_length = 0;
    YogError error;
    Yog *yog;
    long rss_before;
    long rss_after;
    int i;

    if (argc < 3) {
        fputs("usage: bench_yog compile POLICY [--iterations N]\n"
              "       bench_yog check POLICY ACTOR ACTION RESOURCE "
              "[--context \"fact a(b)\"] [--iterations N]\n", stderr);
        return 2;
    }
    mode = argv[1];
    policy = argv[2];

    if (strcmp(mode, "check") == 0) {
        if (argc < 6) {
            fputs("check needs ACTOR ACTION RESOURCE\n", stderr);
            return 2;
        }
        actor = argv[3];
        action = argv[4];
        resource = argv[5];
        i = 6;
    } else if (strcmp(mode, "compile") == 0) {
        i = 3;
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            context = argv[++i];
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            long requested = strtol(argv[++i], NULL, 10);
            if (requested > 0) iterations = (size_t)requested;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    source = read_file(policy, &source_length);
    if (source == NULL) {
        fprintf(stderr, "%s: cannot read policy\n", policy);
        return 2;
    }

    rss_before = rss_kb();
    if (strcmp(mode, "compile") == 0) {
        double *samples = malloc(iterations * sizeof(*samples));
        double start;
        double elapsed;
        size_t k;
        if (samples == NULL) { free(source); return 2; }
        yog = yog_compile(source, source_length, &error);
        if (yog == NULL) {
            fprintf(stderr, "%s: %s\n", policy, error.message);
            free(samples);
            free(source);
            return 1;
        }
        report_stats(yog);
        yog_free(yog);
        start = now_ns();
        for (k = 0; k < iterations; ++k) {
            double before = now_ns();
            yog = yog_compile(source, source_length, &error);
            double after = now_ns();
            if (yog == NULL) {
                fprintf(stderr, "%s: %s\n", policy, error.message);
                free(samples);
                free(source);
                return 1;
            }
            yog_free(yog);
            samples[k] = after - before;
        }
        elapsed = now_ns() - start;
        rss_after = rss_kb();
        report_latency("compile", "n/a", samples, iterations, elapsed,
                       rss_before, rss_after);
        free(samples);
        free(source);
        return 0;
    }

    yog = yog_compile(source, source_length, &error);
    if (yog == NULL) {
        fprintf(stderr, "%s: %s\n", policy, error.message);
        free(source);
        return 1;
    }
    report_stats(yog);
    {
        double *samples = malloc(iterations * sizeof(*samples));
        double start;
        double elapsed;
        size_t k;
        YogResult result;
        const char *decision = "ERROR";

        if (samples == NULL) { yog_free(yog); free(source); return 2; }

        /* Warm up caches and page the module in before measuring. */
        for (k = 0; k < (iterations / 20 > 100 ? iterations / 20 : 100); ++k) {
            if (yog_check(yog, actor, action, resource, context, false, &result, &error))
                yog_result_free(&result);
        }

        start = now_ns();
        for (k = 0; k < iterations; ++k) {
            double before = now_ns();
            bool ok = yog_check(yog, actor, action, resource, context, false, &result, &error);
            double after = now_ns();
            if (!ok) {
                fprintf(stderr, "check failed: %s\n", error.message);
                free(samples);
                yog_free(yog);
                free(source);
                return 1;
            }
            samples[k] = after - before;
            decision = result.decision == YOG_ALLOW ? "ALLOW" : "DENY";
            yog_result_free(&result);
        }
        elapsed = now_ns() - start;
        rss_after = rss_kb();
        report_latency("check", decision, samples, iterations, elapsed,
                       rss_before, rss_after);
        free(samples);
    }

    yog_free(yog);
    free(source);
    return 0;
}
