/*
 * test_security.c -- the guarantees a guardrail depends on.
 *
 *   1. evaluation limits stop runaway work and fail closed;
 *   2. request context is isolated between checks;
 *   3. a compiled module can be shared by concurrent checks;
 *   4. compile/check/free leaves no state behind (ASan/LeakSanitizer);
 *   5. context accepts facts only.
 */
#include "../test_util.h"

#include <stdlib.h>

#include "api/yog.h"

static const char POLICY[] =
    "fact role(i_customer, customer)\n"
    "fact transfer_limit(i_customer, 10000)\n"
    "fact account(i_acct_999, active)\n"
    "fact reserved_schema(reserved_account, reserved_amount)\n"
    "rule amount(Account, Amount):\n"
    "    reserved_schema(Account, Amount)\n"
    "    0 == 1\n"
    "allow can_transfer(User, Account):\n"
    "    role(User, finance_admin)\n"
    "allow can_transfer(User, Account):\n"
    "    transfer_limit(User, Limit)\n"
    "    amount(Account, Amt)\n"
    "    Amt <= Limit\n";

static Yog *compile_policy(void)
{
    YogError error;
    Yog *yog = yog_compile(POLICY, strlen(POLICY), &error);
    if (yog == NULL) {
        (void)fprintf(stderr, "    compile failed: %s\n", error.message);
    }
    return yog;
}

static YogDecision check(Yog *yog, const char *actor, const char *action,
                         const char *resource, const char *context)
{
    YogError error;
    YogResult result;
    YogDecision decision = YOG_DENY;

    if (!yog_check(yog, actor, action, resource, context, false, &result, &error)) {
        return YOG_DENY; /* fail-closed */
    }
    decision = result.decision;
    yog_result_free(&result);
    return decision;
}

static void test_step_limit_fails_closed(void)
{
    Yog *yog = compile_policy();
    YogLimits limits;
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    limits.max_steps = 1;
    limits.max_depth = 0;
    yog_set_limits(yog, limits);
    TEST_CHECK(yog_get_limits(yog).max_steps == 1);

    /* The request needs at least one clause activation, so one step is not
     * enough.  An error must be reported; it must never become ALLOW. */
    TEST_CHECK(!yog_check(yog, "i_customer", "can_transfer", "i_acct_999",
                          "fact amount(i_acct_999, 9000)", false, &result, &error));
    TEST_CHECK(strstr(error.message, "step limit exceeded") != NULL);
    TEST_CHECK(result.decision != YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_depth_limit_fails_closed(void)
{
    Yog *yog = compile_policy();
    YogLimits limits;
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    limits.max_steps = 0;
    limits.max_depth = 1;
    yog_set_limits(yog, limits);

    TEST_CHECK(!yog_check(yog, "i_customer", "can_transfer", "i_acct_999",
                          "fact amount(i_acct_999, 9000)", false, &result, &error));
    TEST_CHECK(strstr(error.message, "depth limit exceeded") != NULL);
    TEST_CHECK(result.decision != YOG_ALLOW);
    yog_result_free(&result);
    yog_free(yog);
}

static void test_negative_depth_limit_uses_default(void)
{
    Yog *yog = compile_policy();
    YogLimits limits;
    YogLimits defaults;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    defaults = yog_get_limits(yog);
    limits.max_steps = 0;
    limits.max_depth = -1;
    yog_set_limits(yog, limits);

    TEST_CHECK(yog_get_limits(yog).max_depth == defaults.max_depth);
    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999",
                     "fact amount(i_acct_999, 9000)") == YOG_ALLOW);
    yog_free(yog);
}

static void test_context_is_isolated_between_checks(void)
{
    Yog *yog = compile_policy();

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999",
                     "fact amount(i_acct_999, 9000)") == YOG_ALLOW);
    /* The 9000 fact must not survive into the next request. */
    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999", NULL) == YOG_DENY);
    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999",
                     "fact amount(i_acct_999, 50000)") == YOG_DENY);
    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999",
                     "fact amount(i_acct_999, 9000)") == YOG_ALLOW);
    /* A different account is unaffected by the earlier context. */
    TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_other_acct",
                     "fact amount(i_acct_999, 9000)") == YOG_DENY);

    yog_free(yog);
}

static void test_context_rejects_non_facts(void)
{
    Yog *yog = compile_policy();
    YogError error;
    YogResult result;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    TEST_CHECK(!yog_check(yog, "i_customer", "can_transfer", "i_acct_999",
                          "allow can_transfer(User, Account):\n    role(User, customer)",
                          false, &result, &error));
    TEST_CHECK(strstr(error.message, "may only contain fact statements") != NULL);
    yog_free(yog);
}

static void test_repeated_compile_and_free(void)
{
    int i;
    for (i = 0; i < 40; ++i) {
        Yog *yog = compile_policy();
        TEST_CHECK(yog != NULL);
        if (yog == NULL) return;
        TEST_CHECK(check(yog, "i_customer", "can_transfer", "i_acct_999",
                         "fact amount(i_acct_999, 100)") == YOG_ALLOW);
        yog_free(yog);
    }
}

/* ------------------------------------------------------------- threading -- */

#define THREAD_COUNT 4
#define THREAD_ITERATIONS 300

typedef struct {
    Yog         *yog;
    const char  *context;
    YogDecision  expected;
    int          failures;
} Worker;

static void worker_run(Worker *worker)
{
    int i;
    for (i = 0; i < THREAD_ITERATIONS; ++i) {
        YogDecision actual = check(worker->yog, "i_customer", "can_transfer",
                                   "i_acct_999", worker->context);
        if (actual != worker->expected) worker->failures++;
    }
}

#ifdef _WIN32
#include <windows.h>

static DWORD WINAPI worker_entry(LPVOID argument)
{
    worker_run((Worker *)argument);
    return 0;
}

static void test_concurrent_checks(void)
{
    Yog *yog = compile_policy();
    Worker workers[THREAD_COUNT];
    HANDLE handles[THREAD_COUNT];
    int i;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    for (i = 0; i < THREAD_COUNT; ++i) {
        workers[i].yog = yog;
        workers[i].failures = 0;
        switch (i) {
        case 0:
            workers[i].context = "fact amount(i_acct_999, 9000)";
            workers[i].expected = YOG_ALLOW;
            break;
        case 1:
            workers[i].context = "fact amount(i_acct_999, 50000)";
            workers[i].expected = YOG_DENY;
            break;
        case 2:
            workers[i].context = NULL;
            workers[i].expected = YOG_DENY;
            break;
        default:
            workers[i].context = "fact amount(i_acct_999, 10000)";
            workers[i].expected = YOG_ALLOW; /* boundary: <= */
            break;
        }
        handles[i] = CreateThread(NULL, 0, worker_entry, &workers[i], 0, NULL);
        TEST_CHECK(handles[i] != NULL);
    }
    (void)WaitForMultipleObjects(THREAD_COUNT, handles, TRUE, INFINITE);
    for (i = 0; i < THREAD_COUNT; ++i) {
        TEST_CHECK(workers[i].failures == 0);
        if (handles[i] != NULL) (void)CloseHandle(handles[i]);
    }
    yog_free(yog);
}

#else
#include <pthread.h>

static void *worker_entry(void *argument)
{
    worker_run((Worker *)argument);
    return NULL;
}

static void test_concurrent_checks(void)
{
    Yog *yog = compile_policy();
    Worker workers[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    int i;

    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;

    for (i = 0; i < THREAD_COUNT; ++i) {
        workers[i].yog = yog;
        workers[i].failures = 0;
        switch (i) {
        case 0:
            workers[i].context = "fact amount(i_acct_999, 9000)";
            workers[i].expected = YOG_ALLOW;
            break;
        case 1:
            workers[i].context = "fact amount(i_acct_999, 50000)";
            workers[i].expected = YOG_DENY;
            break;
        case 2:
            workers[i].context = NULL;
            workers[i].expected = YOG_DENY;
            break;
        default:
            workers[i].context = "fact amount(i_acct_999, 10000)";
            workers[i].expected = YOG_ALLOW; /* boundary: <= */
            break;
        }
        TEST_CHECK(pthread_create(&threads[i], NULL, worker_entry, &workers[i]) == 0);
    }
    for (i = 0; i < THREAD_COUNT; ++i) {
        (void)pthread_join(threads[i], NULL);
        TEST_CHECK(workers[i].failures == 0);
    }
    yog_free(yog);
}
#endif

int main(void)
{
    test_step_limit_fails_closed();
    test_depth_limit_fails_closed();
    test_negative_depth_limit_uses_default();
    test_context_is_isolated_between_checks();
    test_context_rejects_non_facts();
    test_repeated_compile_and_free();
    test_concurrent_checks();
    return test_report("test_security");
}
