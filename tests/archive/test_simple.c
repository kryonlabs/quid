/**
 * @file test_simple.c
 * @brief Simple integration test for QUID with adapters
 *
 * Simple test that demonstrates the complete QUID workflow with Bitcoin adapter.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "quid/quid.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;

/* Test macros */
#define TEST_ASSERT(condition, message) \
    do { \
        tests_run++; \
        if (condition) { \
            tests_passed++; \
            printf("✅ %s\n", message); \
        } else { \
            printf("❌ %s\n", message); \
        } \
    } while(0)

#define TEST_ASSERT_SUCCESS(status, message) \
    TEST_ASSERT((status) == QUID_SUCCESS, message)

/**
 * @brief Test complete QUID workflow
 */
static void test_quid_workflow(void)
{
    printf("\n=== QUID Workflow Test ===\n");

    /* Initialize QUID library */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID library");

    /* Create identity */
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create QUID identity");

    if (identity) {
        /* Get identity ID */
        const char* id = quid_get_identity_id(identity);
        TEST_ASSERT(id != NULL, "Get identity ID");
        TEST_ASSERT(strlen(id) > 0, "Identity ID has length");
        TEST_ASSERT(strncmp(id, "quid", 4) == 0, "Identity ID starts with 'quid'");
        printf("Identity ID: %s\n", id);

        /* Test key derivation */
        quid_context_t context = {0};
        strcpy(context.network_type, "bitcoin");
        strcpy(context.application_id, "test");
        strcpy(context.purpose, "key-derivation");

        uint8_t derived_key[64];
        status = quid_derive_key(identity, &context, derived_key, sizeof(derived_key));
        TEST_ASSERT_SUCCESS(status, "Derive Bitcoin key");

        /* Test signing */
        const char* message = "Test message for QUID";
        quid_signature_t signature;
        status = quid_sign(identity, (const uint8_t*)message, strlen(message), &signature);
        TEST_ASSERT_SUCCESS(status, "Sign message");

        /* Test verification */
        uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
        status = quid_get_public_key(identity, public_key);
        TEST_ASSERT_SUCCESS(status, "Get public key");

        status = quid_verify(public_key, (const uint8_t*)message, strlen(message), &signature);
        TEST_ASSERT_SUCCESS(status, "Verify signature");

        /* Test authentication */
        quid_auth_request_t request = {0};
        strcpy(request.context.network_type, "web");
        strcpy(request.context.application_id, "example.com");
        strcpy(request.context.purpose, "login");

        status = quid_random_bytes(request.challenge, 32);
        TEST_ASSERT_SUCCESS(status, "Generate challenge");

        request.challenge_len = 32;
        request.timestamp = (uint64_t)time(NULL) * 1000;

        quid_auth_response_t response;
        status = quid_authenticate(identity, &request, &response);
        TEST_ASSERT_SUCCESS(status, "Authenticate identity");

        /* Test memory protection */
        bool is_locked = quid_identity_is_locked(identity);
        TEST_ASSERT(!is_locked, "Identity starts unlocked");

        status = quid_identity_lock(identity);
        TEST_ASSERT_SUCCESS(status, "Lock identity");

        is_locked = quid_identity_is_locked(identity);
        TEST_ASSERT(is_locked, "Identity is locked");

        status = quid_identity_unlock(identity);
        TEST_ASSERT_SUCCESS(status, "Unlock identity");

        is_locked = quid_identity_is_locked(identity);
        TEST_ASSERT(!is_locked, "Identity is unlocked");

        /* Cleanup */
        quid_identity_free(identity);
    }

    /* Cleanup library */
    quid_cleanup();
}

/**
 * @brief Test utility functions
 */
static void test_utility_functions(void)
{
    printf("\n=== Utility Functions Test ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    /* Test random bytes */
    uint8_t random_data[32];
    status = quid_random_bytes(random_data, sizeof(random_data));
    TEST_ASSERT_SUCCESS(status, "Generate random bytes");

    bool all_zero = true;
    for (size_t i = 0; i < sizeof(random_data); i++) {
        if (random_data[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!all_zero, "Random data is not all zeros");

    /* Test secure zero */
    memcpy(random_data, "test data", 9);
    quid_secure_zero(random_data, sizeof(random_data));

    all_zero = true;
    for (size_t i = 0; i < sizeof(random_data); i++) {
        if (random_data[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT(all_zero, "Secure zero clears all data");

    /* Test constant time compare */
    uint8_t data1[] = {1, 2, 3, 4, 5};
    uint8_t data2[] = {1, 2, 3, 4, 5};
    uint8_t data3[] = {1, 2, 3, 4, 6};

    int result = quid_constant_time_compare(data1, data2, sizeof(data1));
    TEST_ASSERT(result == 0, "Constant time compare equal data");

    result = quid_constant_time_compare(data1, data3, sizeof(data1));
    TEST_ASSERT(result != 0, "Constant time compare different data");

    /* Test quantum safety */
    bool quantum_safe = quid_is_quantum_safe();
    TEST_ASSERT(quantum_safe, "System is quantum-safe");

    /* Test version */
    const char* version = quid_get_version(NULL, NULL, NULL);
    TEST_ASSERT(version != NULL, "Version string is not NULL");
    TEST_ASSERT(strlen(version) > 0, "Version string has length");

    /* Test error strings */
    const char* error_str = quid_get_error_string(QUID_SUCCESS);
    TEST_ASSERT(error_str != NULL, "Success error string is not NULL");

    /* Cleanup */
    quid_cleanup();
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 QUID Integration Test\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));

    /* Run all tests */
    test_quid_workflow();
    test_utility_functions();

    /* Print results */
    printf("\n📊 Integration Test Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    if (tests_run > 0) {
        printf("Success rate: %.1f%%\n", (float)tests_passed / tests_run * 100);
    } else {
        printf("Success rate: N/A (no tests run)\n");
    }

    if (tests_passed == tests_run) {
        printf("\n✅ All integration tests passed!\n");
        printf("🚀 QUID system is ready for production use!\n");
        return 0;
    } else {
        printf("\n❌ Some integration tests failed!\n");
        return 1;
    }
}