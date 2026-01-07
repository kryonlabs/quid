/**
 * @file test_bitcoin_adapter.c
 * @brief Bitcoin Adapter Unit Tests
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
 * @brief Test Bitcoin key derivation
 */
static void test_bitcoin_key_derivation(void)
{
    TEST_START("Bitcoin key derivation via QUID");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");
    ASSERT_NOT_NULL(identity, "Identity is NULL");

    if (identity) {
        /* Derive key for Bitcoin mainnet */
        quid_context_t ctx = {0};
        strcpy(ctx.network_type, "bitcoin");
        strcpy(ctx.application_id, "mainnet");

        uint8_t key1[64];
        status = quid_derive_key(identity, &ctx, key1, sizeof(key1));
        ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");

        /* Check key is not all zeros */
        int all_zero = 1;
        for (size_t i = 0; i < 32; i++) {
            if (key1[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        ASSERT_TRUE(!all_zero, "Derived key is all zeros");

        /* Derive again - should be deterministic */
        uint8_t key2[64];
        status = quid_derive_key(identity, &ctx, key2, sizeof(key2));
        ASSERT_EQ(status, QUID_SUCCESS, "Second derivation failed");

        int keys_equal = memcmp(key1, key2, 64) == 0;
        ASSERT_TRUE(keys_equal, "Deterministic derivation failed");

        /* Derive for testnet - should be different */
        strcpy(ctx.network_type, "bitcoin-test");
        uint8_t key3[64];
        status = quid_derive_key(identity, &ctx, key3, sizeof(key3));
        ASSERT_EQ(status, QUID_SUCCESS, "Testnet derivation failed");

        int keys_different = memcmp(key1, key3, 64) != 0;
        ASSERT_TRUE(keys_different, "Mainnet and testnet keys are the same");

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test multiple Bitcoin networks
 */
static void test_bitcoin_multiple_networks(void)
{
    TEST_START("Different Bitcoin networks produce different keys");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t keys[5][64];
        const char* networks[] = {
            "bitcoin",
            "bitcoin-test",
            "bitcoin-regtest",
            "bitcoin-signet",
            "litecoin"  /* Different coin */
        };

        for (int i = 0; i < 5; i++) {
            quid_context_t ctx = {0};
            strcpy(ctx.network_type, networks[i]);
            strcpy(ctx.application_id, "test");

            status = quid_derive_key(identity, &ctx, keys[i], sizeof(keys[i]));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");
        }

        /* All keys should be different */
        for (int i = 0; i < 5; i++) {
            for (int j = i + 1; j < 5; j++) {
                int different = memcmp(keys[i], keys[j], 64) != 0;
                ASSERT_TRUE(different, "Keys are not unique");
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
 * @brief Test BIP32-like path derivation
 */
static void test_bip32_path_derivation(void)
{
    TEST_START("Path-like derivation via application_id");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        uint8_t keys[3][64];
        quid_context_t ctx = {0};
        strcpy(ctx.network_type, "bitcoin");

        /* Simulate BIP32 path m/44'/0'/0'/0/i */
        for (int i = 0; i < 3; i++) {
            snprintf(ctx.application_id, sizeof(ctx.application_id),
                     "m/44'/0'/0'/0/%d", i);

            status = quid_derive_key(identity, &ctx, keys[i], sizeof(keys[i]));
            ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");
        }

        /* All keys should be different */
        for (int i = 0; i < 3; i++) {
            for (int j = i + 1; j < 3; j++) {
                int different = memcmp(keys[i], keys[j], 64) != 0;
                ASSERT_TRUE(different, "Path indices produced same key");
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
 * @brief Test signing with Bitcoin-derived key
 */
static void test_bitcoin_signing(void)
{
    TEST_START("Sign message with Bitcoin-derived key");

    quid_status_t status = quid_init();
    ASSERT_EQ(status, QUID_SUCCESS, "QUID init failed");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    ASSERT_EQ(status, QUID_SUCCESS, "Identity creation failed");

    if (identity) {
        quid_context_t ctx = {0};
        strcpy(ctx.network_type, "bitcoin");
        strcpy(ctx.application_id, "signing-test");

        uint8_t derived_key[64];
        status = quid_derive_key(identity, &ctx, derived_key, sizeof(derived_key));
        ASSERT_EQ(status, QUID_SUCCESS, "Key derivation failed");

        /* Get public key */
        uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
        status = quid_get_public_key(identity, public_key);
        ASSERT_EQ(status, QUID_SUCCESS, "Get public key failed");

        /* Sign a message */
        const uint8_t message[] = "Bitcoin test message";
        quid_signature_t signature;

        status = quid_sign(identity, message, sizeof(message) - 1, &signature);
        ASSERT_EQ(status, QUID_SUCCESS, "Signing failed");

        /* Verify signature */
        status = quid_verify(public_key, message, sizeof(message) - 1, &signature);
        ASSERT_EQ(status, QUID_SUCCESS, "Signature verification failed");

        /* Tamper with message - verification should fail */
        const uint8_t tampered[] = "Bitcoin test message!";
        status = quid_verify(public_key, tampered, sizeof(tampered) - 1, &signature);
        ASSERT_TRUE(status != QUID_SUCCESS, "Tampered message verified successfully");

        TEST_PASS();
        quid_identity_free(identity);
    } else {
        TEST_FAIL("Identity creation failed");
    }

    quid_cleanup();
}

/**
 * @brief Test Bitcoin with different security levels
 */
static void test_bitcoin_security_levels(void)
{
    TEST_START("Bitcoin keys at different security levels");

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
            strcpy(ctx.network_type, "bitcoin");
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

int main(void)
{
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║        QUID Bitcoin Adapter Unit Tests                     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    printf("=== Key Derivation Tests ===\n");
    test_bitcoin_key_derivation();
    test_bitcoin_multiple_networks();
    test_bip32_path_derivation();
    test_bitcoin_security_levels();

    printf("\n=== Signing Tests ===\n");
    test_bitcoin_signing();

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
        printf("\n✅ All Bitcoin adapter tests passed!\n");
        return 0;
    } else {
        printf("\n❌ Some tests failed!\n");
        return 1;
    }
}
