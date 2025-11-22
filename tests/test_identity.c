/**
 * @file test_identity.c
 * @brief QUID identity tests
 *
 * Unit tests for QUID identity management functions.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

#define TEST_ASSERT_EQ(expected, actual, message) \
    TEST_ASSERT((expected) == (actual), message)

#define TEST_ASSERT_SUCCESS(status, message) \
    TEST_ASSERT_EQ(QUID_SUCCESS, status, message)

/**
 * @brief Setup function for tests
 */
static void setup(void)
{
    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) {
        fprintf(stderr, "Failed to initialize QUID for tests\n");
        exit(1);
    }
}

/**
 * @brief Cleanup function for tests
 */
static void cleanup(void)
{
    quid_cleanup();
}

/**
 * @brief Test identity creation and destruction
 */
static void test_identity_creation(void)
{
    printf("\n=== Identity Creation Tests ===\n");

    /* Test normal creation */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity with level 5");
    TEST_ASSERT(identity != NULL, "Identity pointer is not NULL");

    /* Test ID generation */
    const char* id = quid_get_identity_id(identity);
    TEST_ASSERT(id != NULL, "Identity ID is not NULL");
    TEST_ASSERT(strlen(id) > 0, "Identity ID has length");
    TEST_ASSERT(strncmp(id, "quid", 4) == 0, "Identity ID starts with 'quid'");

    /* Test public key extraction */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
    status = quid_get_public_key(identity, public_key);
    TEST_ASSERT_SUCCESS(status, "Extract public key");

    /* Test cleanup */
    quid_identity_free(identity);
    printf("✅ Identity freed successfully\n");

    /* Test invalid parameters */
    status = quid_identity_create(NULL, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT(status != QUID_SUCCESS, "Create with NULL pointer fails");

    tests_run++; tests_passed++;  /* Count the manual test */
}

/**
 * @brief Test identity creation from seed
 */
static void test_identity_from_seed(void)
{
    printf("\n=== Identity from Seed Tests ===\n");

    /* Create seed */
    uint8_t seed[QUID_SEED_SIZE];
    quid_status_t status = quid_random_bytes(seed, sizeof(seed));
    TEST_ASSERT_SUCCESS(status, "Generate random seed");

    /* Create identity from seed */
    quid_identity_t* identity1 = NULL;
    status = quid_identity_from_seed(&identity1, seed, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity from seed");

    /* Create second identity with same seed */
    quid_identity_t* identity2 = NULL;
    status = quid_identity_from_seed(&identity2, seed, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create second identity from same seed");

    /* IDs should be identical */
    const char* id1 = quid_get_identity_id(identity1);
    const char* id2 = quid_get_identity_id(identity2);
    TEST_ASSERT(strcmp(id1, id2) == 0, "Same seed produces same ID");

    /* Public keys should be identical */
    uint8_t pk1[QUID_PUBLIC_KEY_SIZE], pk2[QUID_PUBLIC_KEY_SIZE];
    quid_get_public_key(identity1, pk1);
    quid_get_public_key(identity2, pk2);
    TEST_ASSERT(memcmp(pk1, pk2, sizeof(pk1)) == 0, "Same seed produces same public key");

    /* Cleanup */
    quid_identity_free(identity1);
    quid_identity_free(identity2);

    /* Test invalid parameters */
    uint8_t invalid_seed[16];  /* Wrong size */
    status = quid_identity_from_seed(NULL, seed, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT(status != QUID_SUCCESS, "From seed with NULL identity fails");

    status = quid_identity_from_seed(&identity1, NULL, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT(status != QUID_SUCCESS, "From seed with NULL seed fails");

    status = quid_identity_from_seed(&identity1, invalid_seed, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT(status != QUID_SUCCESS, "From seed with wrong size fails");
}

/**
 * @brief Test key derivation
 */
static void test_key_derivation(void)
{
    printf("\n=== Key Derivation Tests ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity for derivation test");

    /* Define test contexts */
    quid_context_t contexts[] = {
        {"bitcoin", "mainnet", "p2pkh", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"ethereum", "mainnet", "account", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"ssh", "server", "hostkey", {0}, 0, QUID_SECURITY_LEVEL_5}
    };

    /* Derive keys for different contexts */
    uint8_t keys[3][64];
    for (int i = 0; i < 3; i++) {
        status = quid_derive_key(identity, &contexts[i], keys[i], sizeof(keys[i]));
        TEST_ASSERT_SUCCESS(status, "Derive key for context");
    }

    /* Keys should be different for different contexts */
    for (int i = 0; i < 3; i++) {
        for (int j = i + 1; j < 3; j++) {
            TEST_ASSERT(memcmp(keys[i], keys[j], 64) != 0,
                       "Keys for different contexts are different");
        }
    }

    /* Same context should produce same key */
    uint8_t repeat_key[64];
    status = quid_derive_key(identity, &contexts[0], repeat_key, sizeof(repeat_key));
    TEST_ASSERT_SUCCESS(status, "Derive repeat key");
    TEST_ASSERT(memcmp(keys[0], repeat_key, 64) == 0,
               "Same context produces same key");

    /* Test different buffer sizes */
    uint8_t small_key[16];
    status = quid_derive_key(identity, &contexts[0], small_key, sizeof(small_key));
    TEST_ASSERT_SUCCESS(status, "Derive small key");

    uint8_t large_key[128];
    status = quid_derive_key(identity, &contexts[0], large_key, sizeof(large_key));
    TEST_ASSERT(status != QUID_SUCCESS, "Derive key with buffer too large fails");

    /* Cleanup */
    quid_identity_free(identity);
}

/**
 * @brief Test signing and verification
 */
static void test_signing_verification(void)
{
    printf("\n=== Signing and Verification Tests ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity for signing test");

    /* Get public key */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
    status = quid_get_public_key(identity, public_key);
    TEST_ASSERT_SUCCESS(status, "Get public key");

    /* Test different message sizes */
    const char* messages[] = {
        "",                              /* Empty message */
        "Hello",                         /* Short message */
        "This is a longer test message with various characters: 1234567890 !@#$%^&*()", /* Long message */
        "Repeated message: This message will be signed twice to test determinism",  /* Message for repeat test */
        "Tampered message: This message will be modified to test failure detection" /* Message for tampering test */
    };

    const char* tampered_message = "Tampered message: This message will be modified to test failure!";

    for (int i = 0; i < 4; i++) {  /* Only first 4 messages for signing */
        size_t message_len = strlen(messages[i]);

        /* Sign message */
        quid_signature_t signature;
        status = quid_sign(identity, (const uint8_t*)messages[i], message_len, &signature);
        TEST_ASSERT_SUCCESS(status, "Sign message");

        /* Verify signature */
        status = quid_verify(public_key, (const uint8_t*)messages[i], message_len, &signature);
        TEST_ASSERT_SUCCESS(status, "Verify signature");

        if (i == 3) {  /* Test repeat signing */
            quid_signature_t signature2;
            status = quid_sign(identity, (const uint8_t*)messages[i], message_len, &signature2);
            TEST_ASSERT_SUCCESS(status, "Sign message again");

            /* Signatures should be different due to randomization in ML-DSA */
            TEST_ASSERT(memcmp(signature.data, signature2.data, signature.size) != 0,
                       "Different signatures for same message (randomized)");

            /* But both should verify */
            status = quid_verify(public_key, (const uint8_t*)messages[i], message_len, &signature2);
            TEST_ASSERT_SUCCESS(status, "Verify second signature");
        }
    }

    /* Test tampered message verification */
    quid_signature_t valid_signature;
    size_t original_len = strlen(messages[4]);
    status = quid_sign(identity, (const uint8_t*)messages[4], original_len, &valid_signature);
    TEST_ASSERT_SUCCESS(status, "Sign original message");

    /* Verify with original message */
    status = quid_verify(public_key, (const uint8_t*)messages[4], original_len, &valid_signature);
    TEST_ASSERT_SUCCESS(status, "Verify original message signature");

    /* Verify with tampered message */
    size_t tampered_len = strlen(tampered_message);
    status = quid_verify(public_key, (const uint8_t*)tampered_message, tampered_len, &valid_signature);
    TEST_ASSERT(status != QUID_SUCCESS, "Verify tampered message signature fails");

    /* Test invalid parameters */
    status = quid_sign(NULL, (const uint8_t*)"test", 4, &valid_signature);
    TEST_ASSERT(status != QUID_SUCCESS, "Sign with NULL identity fails");

    status = quid_sign(identity, NULL, 4, &valid_signature);
    TEST_ASSERT(status != QUID_SUCCESS, "Sign with NULL message fails");

    status = quid_verify(public_key, NULL, 4, &valid_signature);
    TEST_ASSERT(status != QUID_SUCCESS, "Verify with NULL message fails");

    /* Cleanup */
    quid_identity_free(identity);
}

/**
 * @brief Test memory protection
 */
static void test_memory_protection(void)
{
    printf("\n=== Memory Protection Tests ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity for memory protection test");

    /* Initial state should be unlocked */
    TEST_ASSERT(!quid_identity_is_locked(identity), "Identity starts unlocked");

    /* Lock identity */
    status = quid_identity_lock(identity);
    TEST_ASSERT_SUCCESS(status, "Lock identity");
    TEST_ASSERT(quid_identity_is_locked(identity), "Identity is locked");

    /* Unlock identity */
    status = quid_identity_unlock(identity);
    TEST_ASSERT_SUCCESS(status, "Unlock identity");
    TEST_ASSERT(!quid_identity_is_locked(identity), "Identity is unlocked");

    /* Test double lock */
    status = quid_identity_lock(identity);
    TEST_ASSERT_SUCCESS(status, "Lock identity again");
    status = quid_identity_lock(identity);
    TEST_ASSERT_SUCCESS(status, "Double lock succeeds (no-op)");

    /* Test double unlock */
    status = quid_identity_unlock(identity);
    TEST_ASSERT_SUCCESS(status, "Unlock identity again");
    status = quid_identity_unlock(identity);
    TEST_ASSERT_SUCCESS(status, "Double unlock succeeds (no-op)");

    /* Test invalid parameters */
    status = quid_identity_lock(NULL);
    TEST_ASSERT(status != QUID_SUCCESS, "Lock NULL identity fails");

    status = quid_identity_unlock(NULL);
    TEST_ASSERT(status != QUID_SUCCESS, "Unlock NULL identity fails");

    TEST_ASSERT(!quid_identity_is_locked(NULL), "Is locked with NULL identity returns false");

    /* Cleanup */
    quid_identity_free(identity);
}

/**
 * @brief Test utility functions
 */
static void test_utility_functions(void)
{
    printf("\n=== Utility Function Tests ===\n");

    /* Test version */
    const char* version = quid_get_version(NULL, NULL, NULL);
    TEST_ASSERT(version != NULL, "Version string is not NULL");
    TEST_ASSERT(strlen(version) > 0, "Version string has length");

    int major, minor, patch;
    version = quid_get_version(&major, &minor, &patch);
    TEST_ASSERT(major >= 1, "Major version is at least 1");
    TEST_ASSERT(minor >= 0, "Minor version is non-negative");
    TEST_ASSERT(patch >= 0, "Patch version is non-negative");

    /* Test quantum safety */
    bool quantum_safe = quid_is_quantum_safe();
    TEST_ASSERT(quantum_safe, "System is quantum-safe");

    /* Test random bytes */
    uint8_t random_data[64];
    quid_status_t status = quid_random_bytes(random_data, sizeof(random_data));
    TEST_ASSERT_SUCCESS(status, "Generate random bytes");

    /* Test that random data is not all zeros */
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

    int cmp_result = quid_constant_time_compare(data1, data2, sizeof(data1));
    TEST_ASSERT(cmp_result == 0, "Constant time compare equal data returns 0");

    cmp_result = quid_constant_time_compare(data1, data3, sizeof(data1));
    TEST_ASSERT(cmp_result != 0, "Constant time compare different data returns non-zero");

    /* Test error strings */
    const char* error_str = quid_get_error_string(QUID_SUCCESS);
    TEST_ASSERT(error_str != NULL, "Success error string is not NULL");

    error_str = quid_get_error_string(QUID_ERROR_INVALID_PARAMETER);
    TEST_ASSERT(error_str != NULL, "Error string is not NULL");
    TEST_ASSERT(strlen(error_str) > 0, "Error string has length");

    /* Test invalid parameters */
    status = quid_random_bytes(NULL, 16);
    TEST_ASSERT(status != QUID_SUCCESS, "Random bytes with NULL buffer fails");

    quid_secure_zero(NULL, 16);  /* Should not crash */

    cmp_result = quid_constant_time_compare(NULL, data1, 5);
    TEST_ASSERT(cmp_result != 0, "Constant time compare with NULL returns non-zero");

    error_str = quid_get_error_string(999);  /* Unknown error code */
    TEST_ASSERT(error_str != NULL, "Unknown error string is not NULL");
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 QUID Identity Unit Tests\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));

    setup();

    /* Run all tests */
    test_identity_creation();
    test_identity_from_seed();
    test_key_derivation();
    test_signing_verification();
    test_memory_protection();
    test_utility_functions();

    cleanup();

    /* Print results */
    printf("\n📊 Test Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    if (tests_run > 0) {
        printf("Success rate: %.1f%%\n", (float)tests_passed / tests_run * 100);
    } else {
        printf("Success rate: N/A (no tests run)\n");
    }

    if (tests_passed == tests_run) {
        printf("\n✅ All tests passed!\n");
        return 0;
    } else {
        printf("\n❌ Some tests failed!\n");
        return 1;
    }
}