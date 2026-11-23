/*
 * test_json.c -- JSON requests: strict parsing, flattening into typed facts,
 * resistance to value injection, and the JSON result format.
 */
#include "../test_util.h"

#include <stdlib.h>
#include <string.h>

#include "api/yog.h"

static const char POLICY[] =
    "version 2\n"
    "input arg(text, any)\n"
    "input env(text, any)\n"
    "input state(text, any)\n"
    "input state_version(int)\n"
    "input now(int)\n"
    "input role(text, text)\n"
    "input mark(text)\n"
    "deny act(U, R):\n    role(\"evil\", \"admin\")\n"
    "allow act(U, R):\n    arg(\"q\", V)\n    V == \"match\"\n    obligation saw(V)\n"
    "allow act(U, R):\n    arg(\"n\", V)\n    V > 40\n    obligation big(V)\n"
    "allow act(U, R):\n    arg(\"flag\", true)\n"
    "allow act(U, R):\n    arg(\"a.b.c\", \"deep\")\n"
    "allow act(U, R):\n    arg(\"tags\", \"x\")\n    arg(\"tags\", \"y\")\n"
    "allow act(U, R):\n    env(\"stage\", \"prod\")\n    state(\"count\", 3)\n    state_version(9)\n    now(100)\n"
    "allow act(U, R):\n    mark(\"custom\")\n";

static Yog *policy(void)
{
    YogError error;
    Yog *yog = yog_compile(POLICY, strlen(POLICY), &error);
    if (yog == NULL) (void)fprintf(stderr, "    policy error: %s\n", error.message);
    return yog;
}

/* Returns true and the decision when the request evaluated; false on an input/evaluation error. */
static bool run(Yog *yog, const char *json, YogDecision *decision, char *message, size_t message_size)
{
    YogResult result;
    YogError error;
    bool ok = yog_check_json(yog, json, strlen(json), false, &result, &error);
    if (decision != NULL) *decision = result.decision;
    if (message != NULL) (void)snprintf(message, message_size, "%s", error.message);
    TEST_CHECK(result.decision != YOG_ALLOW || ok);   /* an error must never be an ALLOW */
    yog_result_free(&result);
    return ok;
}

static bool allowed(Yog *yog, const char *json)
{
    YogDecision decision = YOG_DENY;
    return run(yog, json, &decision, NULL, 0) && decision == YOG_ALLOW;
}

static bool rejected_with(Yog *yog, const char *json, const char *needle)
{
    char message[256];
    YogDecision decision = YOG_ALLOW;
    bool ok = run(yog, json, &decision, message, sizeof(message));
    if (ok || decision != YOG_DENY) {
        (void)fprintf(stderr, "    expected an error for: %s\n", json);
        return false;
    }
    if (strstr(message, needle) == NULL) {
        (void)fprintf(stderr, "    expected \"%s\" in \"%s\" for: %s\n", needle, message, json);
        return false;
    }
    return true;
}

static void test_basic_and_flattening(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"match\"}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"other\"}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\"}"));
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":41}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":40}}"));
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"flag\":true}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"flag\":false}}"));
    /* nested objects become dotted keys */
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"a\":{\"b\":{\"c\":\"deep\"}}}}"));
    /* arrays give one fact per element */
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"tags\":[\"x\",\"y\",\"z\"]}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"tags\":[\"x\"]}}"));
    /* env, state, state_version, now */
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"env\":{\"stage\":\"prod\"},"
                            "\"state\":{\"version\":9,\"values\":{\"count\":3}},\"now\":100}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"env\":{\"stage\":\"prod\"},"
                             "\"state\":{\"version\":8,\"values\":{\"count\":3}},\"now\":100}"));
    /* generic facts */
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                            "\"facts\":[{\"predicate\":\"mark\",\"args\":[\"custom\"]}]}"));
    /* request_id is accepted and ignored by the engine */
    TEST_CHECK(allowed(yog, "{\"request_id\":\"abc\",\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                            "\"args\":{\"q\":\"match\"}}"));
    yog_free(yog);
}

static void test_values_cannot_forge_facts(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    /* These strings look like policy text.  They must stay plain values. */
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                             "\"args\":{\"q\":\"match\\\"); fact mark(\\\"custom\\\"); fact x(\\\"\"}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                             "\"args\":{\"q\":\"a; fact mark(custom)\"}}"));
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                             "\"args\":{\"q\":\"a\\nfact mark(\\\"custom\\\")\"}}"));
    /* a key with quotes and semicolons is just a key */
    TEST_CHECK(!allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                             "\"args\":{\"q\\\"); fact mark(\\\"custom\\\"); fact y(\\\"\":\"match\"}}"));
    /* The text of a forged fact can be matched as data by a policy that asks for it, which proves the
     * value arrived intact, while the main policy above never saw a `mark` fact. */
    {
        static const char text[] =
            "input arg(text, any)\n"
            "allow act(U, R):\n    arg(\"q\", V)\n    contains(V, \"fact mark(custom)\")\n";
        YogError error;
        Yog *other = yog_compile(text, strlen(text), &error);
        TEST_CHECK(other != NULL);
        if (other != NULL) {
            TEST_CHECK(allowed(other, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                                      "\"args\":{\"q\":\"x; fact mark(custom)\"}}"));
            yog_free(other);
        }
    }
    yog_free(yog);
}

static void test_unicode(void)
{
    static const char text[] =
        "input arg(text, any)\n"
        "allow act(U, R):\n    arg(\"q\", \"caf\xc3\xa9\")\n"
        "allow act(U, R):\n    arg(\"q\", \"\xf0\x9f\x98\x80\")\n";
    YogError error;
    Yog *yog = yog_compile(text, strlen(text), &error);
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"caf\\u00e9\"}}"));
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"caf\xc3\xa9\"}}"));
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"\\ud83d\\ude00\"}}"));
    yog_free(yog);
}

static void test_malformed_json_is_rejected(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(rejected_with(yog, "", "json:"));
    TEST_CHECK(rejected_with(yog, "   ", "json:"));
    TEST_CHECK(rejected_with(yog, "not json", "json:"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\"", "json:"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",}", "json:"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\"} extra", "trailing characters"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\",\"actor\":\"b\"}", "duplicate object key"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"now\":01}", "leading zero"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"\\ud800\",\"action\":\"a\",\"resource\":\"r\"}", "lone surrogate"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"\\udc00\",\"action\":\"a\",\"resource\":\"r\"}", "lone surrogate"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\\u0000b\",\"action\":\"a\",\"resource\":\"r\"}", "NUL"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\xff\",\"action\":\"a\",\"resource\":\"r\"}", "invalid UTF-8"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\xc0\xaf\",\"action\":\"a\",\"resource\":\"r\"}", "invalid UTF-8"));   /* overlong */
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\xed\xa0\x80\",\"action\":\"a\",\"resource\":\"r\"}", "invalid UTF-8")); /* surrogate */
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"a\tb\",\"action\":\"a\",\"resource\":\"r\"}", "control character"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"\\q\",\"action\":\"a\",\"resource\":\"r\"}", "bad escape"));
    TEST_CHECK(rejected_with(yog, "[1,2]", "must be a JSON object"));
    TEST_CHECK(rejected_with(yog, "\"text\"", "must be a JSON object"));
    yog_free(yog);
}

static void test_depth_and_size_limits(void)
{
    Yog *yog = policy();
    char deep[256];
    char *big;
    size_t i, n = 0;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    for (i = 0; i < 40; ++i) deep[n++] = '[';
    for (i = 0; i < 40; ++i) deep[n++] = ']';
    deep[n] = '\0';
    TEST_CHECK(rejected_with(yog, deep, "nesting is too deep"));

    big = malloc((1u << 20) + 64);
    TEST_CHECK(big != NULL);
    if (big != NULL) {
        YogResult result;
        YogError error;
        memset(big, ' ', (1u << 20) + 32);
        big[(1u << 20) + 32] = '\0';
        TEST_CHECK(!yog_check_json(yog, big, (1u << 20) + 32, false, &result, &error));
        TEST_CHECK(strstr(error.message, "larger than") != NULL);
        TEST_CHECK(result.decision == YOG_DENY);
        yog_result_free(&result);
        free(big);
    }
    yog_free(yog);
}

static void test_numbers(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(allowed(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":9223372036854775807}}"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":9223372036854775808}}", "out of range"));
    TEST_CHECK(run(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":-9223372036854775808}}", NULL, NULL, 0));   /* smallest int64 is valid */
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":-9223372036854775809}}", "out of range"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":1.5}}", "fraction or exponent"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":1e3}}", "fraction or exponent"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"n\":null}}", "null is not supported"));
    yog_free(yog);
}

static void test_request_shape_errors(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(rejected_with(yog, "{\"action\":\"act\",\"resource\":\"r\"}", "\"actor\""));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"resource\":\"r\"}", "\"action\""));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\"}", "\"resource\""));
    TEST_CHECK(rejected_with(yog, "{\"actor\":1,\"action\":\"act\",\"resource\":\"r\"}", "\"actor\""));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"extra\":1}", "unknown request field"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":[1]}", "\"args\" must be an object"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"env\":1}", "\"env\" must be an object"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"now\":\"soon\"}", "must be an integer"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"state\":{\"extra\":1}}", "unknown field"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"request_id\":5}", "\"request_id\" must be a string"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"a\":[[1]]}}", "arrays may only contain"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"facts\":{}}", "must be an array"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"facts\":[{\"predicate\":\"Bad Name\",\"args\":[1]}]}", "invalid predicate"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"facts\":[{\"predicate\":\"p\",\"args\":[]}]}", "between 1 and"));
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"facts\":[{\"predicate\":\"p\"}]}", "needs a"));
    /* a built-in name cannot be injected as a fact */
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"facts\":[{\"predicate\":\"contains\",\"args\":[\"a\",\"b\"]}]}", "built-in"));
    yog_free(yog);
}

static void test_input_types_apply_to_json_facts(void)
{
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    /* now is declared int; a string is a type error, not an allow */
    TEST_CHECK(rejected_with(yog, "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\","
                                  "\"facts\":[{\"predicate\":\"now\",\"args\":[\"later\"]}]}", "must be int"));
    yog_free(yog);
}

static void test_result_json(void)
{
    Yog *yog = policy();
    YogResult result;
    YogError error;
    const char *json = "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"match\"}}";
    char *text;
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(yog_check_json(yog, json, strlen(json), false, &result, &error));
    text = yog_result_to_json(yog, &result);
    TEST_CHECK(text != NULL);
    if (text != NULL) {
        TEST_CHECK(strstr(text, "\"decision\":\"ALLOW\"") != NULL);
        TEST_CHECK(strstr(text, "\"policy_version\":2") != NULL);
        TEST_CHECK(strstr(text, "\"obligations\":[{\"name\":\"saw\",\"args\":[\"match\"]}]") != NULL);
        TEST_CHECK(strstr(text, "\"trace\"") == NULL);
        yog_string_free(text);
    }
    yog_result_free(&result);

    TEST_CHECK(!yog_check_json(yog, "{", 1, false, &result, &error));
    text = yog_error_to_json(&error);
    TEST_CHECK(text != NULL && strstr(text, "\"error\":{\"message\":\"json:") != NULL);
    yog_string_free(text);
    yog_result_free(&result);

    /* escaping: control characters and quotes in obligation text */
    {
        static const char escaping[] =
            "input arg(text, any)\n"
            "allow act(U, R):\n    arg(\"q\", V)\n    obligation say(V)\n";
        YogError e2;
        Yog *other = yog_compile(escaping, strlen(escaping), &e2);
        const char *req = "{\"actor\":\"u\",\"action\":\"act\",\"resource\":\"r\",\"args\":{\"q\":\"a\\\"b\\\\c\\n\\u0001\"}}";
        TEST_CHECK(other != NULL);
        if (other != NULL) {
            TEST_CHECK(yog_check_json(other, req, strlen(req), false, &result, &e2));
            text = yog_result_to_json(other, &result);
            TEST_CHECK(text != NULL && strstr(text, "\"a\\\"b\\\\c\\n\\u0001\"") != NULL);
            yog_string_free(text);
            yog_result_free(&result);
            yog_free(other);
        }
    }
    yog_free(yog);
}

static void test_null_arguments(void)
{
    YogResult result;
    YogError error;
    Yog *yog = policy();
    TEST_CHECK(yog != NULL);
    if (yog == NULL) return;
    TEST_CHECK(!yog_check_json(NULL, "{}", 2, false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(!yog_check_json(yog, NULL, 0, false, &result, &error));
    TEST_CHECK(result.decision == YOG_DENY);
    TEST_CHECK(!yog_check_json(yog, "{}", 2, false, NULL, &error));
    yog_free(yog);
}

int main(void)
{
    test_basic_and_flattening();
    test_values_cannot_forge_facts();
    test_unicode();
    test_malformed_json_is_rejected();
    test_depth_and_size_limits();
    test_numbers();
    test_request_shape_errors();
    test_input_types_apply_to_json_facts();
    test_result_json();
    test_null_arguments();
    return test_report("test_json");
}
