/*
 * fuzz_smoke.c -- deterministic robustness smoke test.
 *
 * Feeds generated and mutated inputs through the whole pipeline.  A crash,
 * sanitizer finding or hang fails the test.  This is not a replacement for
 * coverage-guided fuzzing (see fuzz_compile.c / docs/CORRECTNESS.md); it is a
 * fast regression net that runs on every CI build.
 *
 * The generator is a small LCG so results are identical on every platform.
 */
#include "../test_util.h"

#include <stdio.h>
#include <stdlib.h>

#include "api/yog.h"
#include "builtin/builtin.h"

static unsigned long long rng_state = 0x9e3779b97f4a7c15ull;

static unsigned next_random(void)
{
    rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
    return (unsigned)(rng_state >> 33);
}

static const char *SEEDS[] = {
    "fact role(alice, admin)\n"
    "allow can_delete(User, DB):\n"
    "    role(User, admin)\n",
    "fact role(i_customer, customer)\n"
    "fact transfer_limit(i_customer, 10000)\n"
    "fact reserved_schema(reserved_account, reserved_amount)\n"
    "rule amount(Account, Amount):\n"
    "    reserved_schema(Account, Amount)\n"
    "    0 == 1\n"
    "allow can_transfer(User, Account):\n"
    "    transfer_limit(User, Limit)\n"
    "    amount(Account, Amt)\n"
    "    Amt <= Limit\n",
    "fact role(a, admin)\n"
    "fact role(b, dev)\n"
    "rule admin_of(X):\n"
    "    role(X, admin)\n"
    "allow can_admin(User, DB):\n"
    "    admin_of(User)\n"
    "deny can_admin(User, DB):\n"
    "    not role(User, dev)\n",
    "fact p(a)\nquery p(a)\nquery p(b)\n",
    "version 2\n"
    "input arg(text, any)\n"
    "input env(text, any)\n"
    "input now(int)\n"
    "deny act(U, R):\n"
    "    arg(\"q\", V)\n"
    "    matches(V, \"(?i)drop|^(a+)+$\")\n"
    "require_approval act(U, R):\n"
    "    env(\"stage\", \"prod\")\n"
    "    obligation audit(\"prod\", R)\n"
    "allow act(U, R):\n"
    "    arg(\"p\", P)\n"
    "    under(P, \"/work\")\n"
    "    not cidr(R, \"10.0.0.0/8\")\n"
    "    in(U, \"a\", \"b\")\n"
    "    now(T)\n"
    "    T > 5\n"
    "    obligation seen(T, true)\n",
};

#define SEED_COUNT (sizeof(SEEDS) / sizeof(SEEDS[0]))

static char *mutate(const char *seed, size_t length, size_t *out_length)
{
    char *copy = malloc(length + 33);
    size_t i;
    unsigned edits;

    if (copy == NULL) return NULL;
    memcpy(copy, seed, length);
    *out_length = length;

    edits = next_random() % 6;
    for (i = 0; i < edits; ++i) {
        unsigned operation = next_random() % 4;
        size_t position = *out_length == 0 ? 0 : next_random() % *out_length;
        if (operation == 0) {
            copy[position] = (char)(32 + next_random() % 95);
        } else if (operation == 1 && *out_length > 1) {
            memmove(copy + position, copy + position + 1, *out_length - position);
            (*out_length)--;
        } else if (operation == 2 && *out_length < length + 16) {
            memmove(copy + position + 1, copy + position, *out_length - position + 1);
            copy[position] = (char)(next_random() % 128);
            (*out_length)++;
        } else if (operation == 3) {
            size_t run = 1 + next_random() % 16;
            size_t j;
            for (j = 0; j < run && position + j < length + 32; ++j)
                copy[position + j] = ' ';
        }
    }
    copy[*out_length] = '\0';
    return copy;
}

static void exercise(const char *source, size_t length)
{
    YogError error;
    Yog *yog = yog_compile(source, length, &error);
    if (yog == NULL) return;

    {
        FILE *sink = tmpfile();
        if (sink != NULL) {
            (void)yog_run_queries(yog, sink, next_random() % 8 == 0);
            fclose(sink);
        }
    }
    {
        static const char *actors[] = { "alice", "i_customer", "", "a b" };
        static const char *actions[] = { "can_delete", "can_transfer", "missing", "" };
        static const char *resources[] = { "db1", "i_acct_999", "reserved_account", "" };
        static const char *contexts[] = {
            NULL, "fact amount(i_acct_999, 9000)", "fact amount(i_acct_999, 50000)",
            "rule bad(X):\n    p(X)", "fact x(y); fact z(w)"
        };
        YogResult result;
        bool ok = yog_check(yog,
                            actors[next_random() % 4],
                            actions[next_random() % 4],
                            resources[next_random() % 4],
                            contexts[next_random() % 5],
                            next_random() % 8 == 0,
                            &result, &error);
        if (ok) {
            TEST_CHECK(result.decision == YOG_ALLOW || result.decision == YOG_DENY ||
                       result.decision == YOG_REQUIRE_APPROVAL);
            yog_result_free(&result);
        } else {
            /* A failed check must never look like an allow. */
            TEST_CHECK(result.decision == YOG_DENY);
        }
    }
    yog_free(yog);
}

/* ---------------------------------------------------------------- JSON requests */

static const char JSON_POLICY[] =
    "version 2\n"
    "input arg(text, any)\n"
    "input env(text, any)\n"
    "input state(text, any)\n"
    "input state_version(int)\n"
    "input now(int)\n"
    "deny act(U, R):\n    arg(\"q\", V)\n    contains(V, \"drop\")\n"
    "require_approval act(U, R):\n    env(\"stage\", \"prod\")\n    obligation audit(R)\n"
    "allow act(U, R):\n    arg(\"n\", N)\n    N > 3\n    state(\"c\", C)\n    C < 9\n    obligation tag(N, C, U)\n";

static const char *JSON_SEEDS[] = {
    "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\"}",
    "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"select\",\"n\":7,\"a\":{\"b\":[1,2,true]}},"
    "\"env\":{\"stage\":\"prod\"},\"state\":{\"version\":3,\"values\":{\"c\":4}},\"now\":100,\"request_id\":\"x\"}",
    "{\"actor\":\"caf\\u00e9\",\"action\":\"act\",\"resource\":\"\\ud83d\\ude00\",\"facts\":[{\"predicate\":\"p\",\"args\":[1,\"a\",false]}]}",
    "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":-9223372036854775808,\"z\":1.5e3,\"y\":null}}",
};
#define JSON_SEED_COUNT (sizeof(JSON_SEEDS) / sizeof(JSON_SEEDS[0]))

static void exercise_json(Yog *yog, const char *json, size_t length)
{
    YogResult result;
    YogError error;
    bool ok = yog_check_json(yog, json, length, next_random() % 8 == 0, &result, &error);
    if (ok) {
        char *text;
        TEST_CHECK(result.decision == YOG_ALLOW || result.decision == YOG_DENY ||
                   result.decision == YOG_REQUIRE_APPROVAL);
        text = yog_result_to_json(yog, &result);
        TEST_CHECK(text != NULL);
        yog_string_free(text);
    } else {
        char *text;
        TEST_CHECK(result.decision == YOG_DENY);        /* an error must never look like an allow */
        text = yog_error_to_json(&error);
        TEST_CHECK(text != NULL);
        yog_string_free(text);
    }
    yog_result_free(&result);
}

static void fuzz_json(void)
{
    YogError error;
    Yog *yog = yog_compile(JSON_POLICY, strlen(JSON_POLICY), &error);
    size_t seed;
    int iteration;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    for (seed = 0; seed < JSON_SEED_COUNT; ++seed) {
        size_t length = strlen(JSON_SEEDS[seed]);
        exercise_json(yog, JSON_SEEDS[seed], length);
        for (iteration = 0; iteration < 400; ++iteration) {
            size_t mutated_length = 0;
            char *mutated = mutate(JSON_SEEDS[seed], length, &mutated_length);
            TEST_CHECK(mutated != NULL);
            if (mutated == NULL) continue;
            exercise_json(yog, mutated, mutated_length);
            free(mutated);
        }
    }
    for (iteration = 0; iteration < 500; ++iteration) {          /* arbitrary bytes, including high ones */
        char buffer[200];
        size_t length = next_random() % sizeof(buffer);
        size_t i;
        for (i = 0; i < length; ++i) buffer[i] = (char)(next_random() % 256);
        exercise_json(yog, buffer, length);
    }
    yog_free(yog);
}

/* ------------------------------------------------------------------ regex built-in */

static void fuzz_regex(void)
{
    static const char ALPHABET[] = "ab.*+?|()[]^$\\-0 dws";
    int iteration;
    for (iteration = 0; iteration < 3000; ++iteration) {
        char pattern[40], text[40];
        YogBuiltinArg args[2];
        bool result = false;
        char message[160];
        size_t pl = next_random() % 20, tl = next_random() % 30, i;
        for (i = 0; i < pl; ++i) pattern[i] = ALPHABET[next_random() % (sizeof(ALPHABET) - 1)];
        for (i = 0; i < tl; ++i) text[i] = "ab 0-"[next_random() % 5];
        args[0].kind = YOG_ARG_TEXT; args[0].text = text; args[0].length = tl; args[0].integer = 0;
        args[1].kind = YOG_ARG_TEXT; args[1].text = pattern; args[1].length = pl; args[1].integer = 0;
        /* either an answer or a clean error: never a crash, hang or out-of-bounds access */
        (void)yog_builtin_eval(YOG_BUILTIN_MATCHES, args, 2, &result, message, sizeof(message));
        (void)yog_builtin_eval(YOG_BUILTIN_GLOB, args, 2, &result, message, sizeof(message));
        (void)yog_builtin_eval(YOG_BUILTIN_UNDER, args, 2, &result, message, sizeof(message));
        (void)yog_builtin_eval(YOG_BUILTIN_CIDR, args, 2, &result, message, sizeof(message));
    }
}

int main(void)
{
    size_t seed;
    int iteration;

    fuzz_json();
    fuzz_regex();

    for (seed = 0; seed < SEED_COUNT; ++seed) {
        size_t length = strlen(SEEDS[seed]);
        exercise(SEEDS[seed], length);
        for (iteration = 0; iteration < 250; ++iteration) {
            size_t mutated_length = 0;
            char *mutated = mutate(SEEDS[seed], length, &mutated_length);
            TEST_CHECK(mutated != NULL);
            if (mutated == NULL) continue;
            exercise(mutated, mutated_length);
            free(mutated);
        }
    }

    for (iteration = 0; iteration < 500; ++iteration) {
        char buffer[257];
        size_t length = next_random() % 256;
        size_t i;
        for (i = 0; i < length; ++i) buffer[i] = (char)(next_random() % 128);
        exercise(buffer, length);
    }

    return test_report("fuzz_smoke");
}
