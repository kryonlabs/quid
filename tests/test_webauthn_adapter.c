/**
 * @file test_webauthn_adapter.c
 * @brief WebAuthn Adapter Unit Tests
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "quid/quid.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_START(name) \
    do { \
        tests_run++; \
        printf("  Test %d: %s...", tests_run, name); \
    } while(0)

#define TEST_PASS() \
    do { \
        tests_passed++; \
        printf(" ✅\n"); \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        printf(" ❌ (%s)\n", msg); \
    } while(0)

#define ASSERT_TRUE(cond, msg) \
    do { \
        if (!(cond)) { \
            TEST_FAIL(msg); \
            return; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr, msg) \
    ASSERT_TRUE((ptr) != NULL, msg)

#define ASSERT_EQ(a, b, msg) \
    ASSERT_TRUE((a) == (b), msg)

/**
 * @brief Test WebAuthn key derivation for different RPs
 */
static void test_webauthn_key_derivation(void)
{
    TEST_START("WebAuthn key derivation for different RPs");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t keys[4][64];
        const char* rps[] = {"google.com", "github.com", "facebook.com", "twitter.com"};

        for (int i = 0; i < 4; i++) {
            quid_context_t ctx = {0};
            strcpy(ctx.network_type, "webauthn");
            strcpy(ctx.application_id, rps[i]);
            strcpy(ctx.purpose, "testuser");

            status = quid_derive_key(identity, &ctx, keys[i], sizeof(keys[i]));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");
        }

        /* All keys should be different */
        for (int i = 0; i < 4; i++) {
            for (int j = i + 1; j < 4; j++) {
                int different = memcmp(keys[i], keys[j], 64) != 0;
                ASSERT_TRUE(different, "WebAuthn keys are not unique");
            }
        }

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test WebAuthn keys for different users
 */
static void test_webauthn_different_users(void)
{
    TEST_START("Different users get different WebAuthn keys");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t keys[3][64];
        const char* users[] = {"alice@example.com", "bob@example.com", "charlie@example.com"};

        for (int i = 0; i < 3; i++) {
            quid_context_t ctx = {0};
            strcpy(ctx.network_type, "webauthn");
            strcpy(ctx.application_id, users[i]);

            status = quid_derive_key(identity, &ctx, keys[i], sizeof(keys[i]));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");
        }

        /* All keys should be different */
        for (int i = 0; i < 3; i++) {
            for (int j = i + 1; j < 3; j++) {
                int different = memcmp(keys[i], keys[j], 64) != 0;
                ASSERT_TRUE(different, "User keys are not unique");
            }
        }

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test WebAuthn deterministic derivation
 */
static void test_webauthn_deterministic(void)
{
    TEST_START("Same WebAuthn context produces same key");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t key1[64], key2[64];
        quid_context_t ctx = {0};
        strcpy(ctx.network_type, "webauthn");
        strcpy(ctx.application_id, "deterministic.com");
        strcpy(ctx.purpose, "testuser");

        status = quid_derive_key(identity, &ctx, key1, sizeof(key1));
        ASSERT_EQ(status, QUID_SUCCESS, "First derivation failed");

        status = quid_derive_key(identity, &ctx, key2, sizeof(key2));
        ASSERT_EQ(status, QUID_SUCCESS, "Second derivation failed");

        int keys_equal = memcmp(key1, key2, 64) == 0;
        ASSERT_TRUE(keys_equal, "Deterministic derivation failed");

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test WebAuthn signing
 */
static void test_webauthn_signing(void)
{
    TEST_START("Sign message with WebAuthn-derived context");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        quid_context_t ctx = {0};
        strcpy(ctx.network_type, "webauthn");
        strcpy(ctx.application_id, "example.com");
        strcpy(ctx.purpose, "testuser");

        uint8_t derived_key[64];
        status = quid_derive_key(identity, &ctx, derived_key, sizeof(derived_key));
        ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");

        /* Get public key */
        uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
        status = quid_get_public_key(identity, public_key);
        ASSERT_EQ(status, QUID_SUCCESS, "Get public key failed");

        /* Sign a WebAuthn-like challenge */
        const uint8_t challenge[] = "{\"challenge\":\"test-challenge\",\"origin\":\"https://example.com\"}";
        quid_signature_t signature;

        status = quid_sign(identity, challenge, sizeof(challenge) - 1, &signature);
        ASSERT_EQ(status, QUID_SUCCESS, "Signing failed");

        /* Verify signature */
        status = quid_verify(public_key, challenge, sizeof(challenge) - 1, &signature);
        ASSERT_EQ(status, QUID_SUCCESS, "Signature verification failed");

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test WebAuthn with different security levels
 */
static void test_webauthn_security_levels(void)
{
    TEST_START("WebAuthn keys at different security levels");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_security_level_t levels[] = {
        QUID_SECURITY_LEVEL_1,
        QUID_SECURITY_LEVEL_3,
        QUID_SECURITY_LEVEL_5
    };

    for (int i = 0; i < 3; i++) {
        quid_identity_t* identity = NULL;
        status = quid_identity_create(&identity, levels[i]);
        ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

        if (identity) {
            quid_context_t ctx = {0};
            strcpy(ctx.network_type, "webauthn");
            strcpy(ctx.application_id, "security-test");

            uint8_t key[64];
            status = quid_derive_key(identity, &ctx, key, sizeof(key));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");

            quid_identity_free(identity);
        }
    }

    TEST_PASS();
    quid_cleanup();
}

/**
 * @brief Test WebAuthn purpose field
 */
static void test_webauthn_purpose(void)
{
    TEST_START("Different purposes produce different keys");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t keys[3][64];
        const char* purposes[] = {"authentication", "signing", "encryption"};

        for (int i = 0; i < 3; i++) {
            quid_context_t ctx = {0};
            strcpy(ctx.network_type, "webauthn");
            strcpy(ctx.application_id, "example.com");
            strcpy(ctx.purpose, purposes[i]);

            status = quid_derive_key(identity, &ctx, keys[i], sizeof(keys[i]));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");
        }

        /* All keys should be different */
        for (int i = 0; i < 3; i++) {
            for (int j = i + 1; j < 3; j++) {
                int different = memcmp(keys[i], keys[j], 64) != 0;
                ASSERT_TRUE(different, "Purpose keys are not unique");
            }
        }

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

int main(void)
{
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║        QUID WebAuthn Adapter Unit Tests                   ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    printf("=== Key Derivation Tests ===\n");
    test_webauthn_key_derivation();
    test_webauthn_different_users();
    test_webauthn_deterministic();
    test_webauthn_security_levels();
    test_webauthn_purpose();

    printf("\n=== Signing Tests ===\n");
    test_webauthn_signing();

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    Test Results                            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Tests run:    %3d                                         ║\n", tests_run);
    printf("║  Tests passed: %3d                                         ║\n", tests_passed);
    printf("║  Tests failed: %3d                                         ║\n", tests_run - tests_passed);
    printf("║  Success rate: %.1f%%                                     ║\n",
           tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0);
    printf("╚════════════════════════════════════════════════════════════╝\n");

    if (tests_passed == tests_run) {
        printf("\n✅ All WebAuthn adapter tests passed!\n");
        return 0;
    } else {
        printf("\n❌ Some tests failed!\n");
        return 1;
    }
}
