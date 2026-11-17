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
            TEST_CHECK(result.decision == YOG_ALLOW || result.decision == YOG_DENY);
            yog_result_free(&result);
        } else {
            /* A failed check must never look like an allow. */
            TEST_CHECK(result.decision == YOG_DENY);
        }
    }
    yog_free(yog);
}

int main(void)
{
    size_t seed;
    int iteration;

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
