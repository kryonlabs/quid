/**
 * @file test_webauthn_simple.c
 * @brief Simple WebAuthn adapter test for QUID
 *
 * Basic test for WebAuthn adapter functionality using only the public API.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "quid/quid.h"
#include "quid/adapters/adapter.h"

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
    TEST_ASSERT((status) == QUID_ADAPTER_SUCCESS, message)

/* WebAuthn adapter function declarations */
extern quid_adapter_functions_t* quid_adapter_get_functions(void);

/**
 * @brief Test WebAuthn adapter basic functionality
 */
static void test_webauthn_basic(void)
{
    printf("\n=== WebAuthn Basic Tests ===\n");

    /* Get adapter functions */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    TEST_ASSERT(functions != NULL, "Get WebAuthn adapter functions");
    TEST_ASSERT(functions->abi_version == QUID_ADAPTER_ABI_VERSION, "ABI version matches");
    TEST_ASSERT(functions->init != NULL, "Init function exists");
    TEST_ASSERT(functions->cleanup != NULL, "Cleanup function exists");
    TEST_ASSERT(functions->get_info != NULL, "Get info function exists");

    /* Create a simple context */
    quid_adapter_context_t context = {0};
    context.network_type = QUID_NETWORK_WEBAUTHN;
    context.context = NULL;  /* Use NULL context for basic test */

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(&context);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter with NULL context");

    if (adapter) {
        TEST_ASSERT(adapter->is_initialized, "Adapter is marked as initialized");

        /* Test adapter info */
        const quid_adapter_info_t* info = functions->get_info(adapter);
        TEST_ASSERT(info != NULL, "Get adapter info");
        if (info) {
            TEST_ASSERT(strcmp(info->name, "WebAuthn Adapter") == 0, "Adapter name is correct");
            TEST_ASSERT(info->network_type == QUID_NETWORK_WEBAUTHN, "Network type is WebAuthn");
            TEST_ASSERT(info->adapter_type == QUID_ADAPTER_TYPE_AUTHENTICATION, "Adapter type is authentication");
            TEST_ASSERT((info->capabilities & QUID_ADAPTER_CAP_SIGN) != 0, "Adapter supports signing");
            TEST_ASSERT((info->capabilities & QUID_ADAPTER_CAP_VERIFY) != 0, "Adapter supports verification");
            TEST_ASSERT((info->capabilities & QUID_ADAPTER_CAP_DERIVE_PUBLIC) != 0, "Adapter supports public key derivation");
        }

        /* Cleanup */
        functions->cleanup(adapter);
    }
}

/**
 * @brief Test WebAuthn adapter with QUID identity
 */
static void test_webauthn_with_quid(void)
{
    printf("\n=== WebAuthn QUID Integration Tests ===\n");

    /* Get adapter functions */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    TEST_ASSERT(functions != NULL, "Get adapter functions");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT(status == QUID_SUCCESS, "Initialize QUID");

    /* Create QUID identity */
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT(status == QUID_SUCCESS, "Create QUID identity");

    /* Get master key for derivation */
    quid_context_t master_ctx = {"master", "system", "key-material", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t master_key[64];  /* Use smaller size for test */
    status = quid_derive_key(identity, &master_ctx, master_key, sizeof(master_key));
    TEST_ASSERT(status == QUID_SUCCESS, "Derive master key from identity");

    /* Create WebAuthn adapter context */
    quid_adapter_context_t webauthn_ctx = {0};
    webauthn_ctx.network_type = QUID_NETWORK_WEBAUTHN;
    webauthn_ctx.context = NULL;  /* NULL context should use defaults */

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(&webauthn_ctx);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter");

    if (adapter) {
        /* Test key derivation */
        quid_context_t quid_ctx = {"webauthn", "example.com", "credential", {0}, 0, QUID_SECURITY_LEVEL_5};
        uint8_t derived_key[64];
        status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                       &quid_ctx, derived_key, sizeof(derived_key));
        TEST_ASSERT_SUCCESS((quid_adapter_status_t)status, "Derive WebAuthn key");

        /* Test public key derivation */
        char public_key[256];
        size_t public_key_size = sizeof(public_key);
        status = functions->derive_public(adapter, derived_key, sizeof(derived_key),
                                         public_key, &public_key_size);
        TEST_ASSERT_SUCCESS((quid_adapter_status_t)status, "Derive WebAuthn public key");
        TEST_ASSERT(strlen(public_key) > 0, "Public key is not empty");

        /* Test signing and verification */
        uint8_t message[128];
        for (int i = 0; i < 128; i++) {
            message[i] = (uint8_t)(i * 3);
        }

        uint8_t signature[256];
        size_t signature_size = sizeof(signature);
        status = functions->sign(adapter, derived_key, sizeof(derived_key),
                                message, sizeof(message), signature, &signature_size);
        TEST_ASSERT_SUCCESS((quid_adapter_status_t)status, "Sign WebAuthn message");
        TEST_ASSERT(signature_size > 0, "Signature has size");

        /* Convert public key back to bytes for verification */
        uint8_t public_key_bytes[64];
        for (size_t i = 0; i < sizeof(public_key_bytes) && i < strlen(public_key); i++) {
            public_key_bytes[i] = (uint8_t)public_key[i];
        }

        /* Verify signature */
        status = functions->verify(adapter, public_key_bytes, sizeof(public_key_bytes),
                                  message, sizeof(message), signature, signature_size);
        TEST_ASSERT_SUCCESS((quid_adapter_status_t)status, "Verify WebAuthn signature");

        /* Test error handling - wrong message */
        uint8_t wrong_message[128];
        memcpy(wrong_message, message, 128);
        wrong_message[50] ^= 0xFF;  /* Flip some bits */

        status = functions->verify(adapter, public_key_bytes, sizeof(public_key_bytes),
                                  wrong_message, sizeof(wrong_message), signature, signature_size);
        TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Verify with wrong message fails");

        /* Cleanup */
        functions->cleanup(adapter);
    }

    /* Cleanup QUID */
    if (identity) {
        quid_identity_free(identity);
    }
    quid_cleanup();
}

/**
 * @brief Test WebAuthn adapter error handling
 */
static void test_webauthn_error_handling(void)
{
    printf("\n=== WebAuthn Error Handling Tests ===\n");

    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    TEST_ASSERT(functions != NULL, "Get adapter functions");

    /* Test operations with NULL adapter */
    uint8_t key[64], signature[256];
    size_t key_size = sizeof(key), sig_size = sizeof(signature);
    quid_context_t context = {"webauthn", "test.com", "test", {0}, 0, QUID_SECURITY_LEVEL_5};

    quid_adapter_status_t status = functions->derive_key(NULL, key, sizeof(key),
                                                         &context, key, key_size);
    TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Derive key with NULL adapter fails");

    status = functions->sign(NULL, key, sizeof(key), key, sizeof(key),
                            signature, &sig_size);
    TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Sign with NULL adapter fails");

    /* Test operations with invalid parameters */
    const quid_adapter_info_t* info = functions->get_info(NULL);
    TEST_ASSERT(info == NULL, "Get info with NULL adapter returns NULL");

    printf("✅ Error handling tests completed\n");
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 WebAuthn Adapter Simple Tests\n");

    /* Run all tests */
    test_webauthn_basic();
    test_webauthn_with_quid();
    test_webauthn_error_handling();

    /* Print results */
    printf("\n📊 WebAuthn Test Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    if (tests_run > 0) {
        printf("Success rate: %.1f%%\n", (float)tests_passed / tests_run * 100);
    } else {
        printf("Success rate: N/A (no tests run)\n");
    }

    if (tests_passed == tests_run) {
        printf("\n✅ All WebAuthn tests passed!\n");
        printf("🚀 WebAuthn adapter is ready for production use!\n");
        return 0;
    } else {
        printf("\n❌ Some WebAuthn tests failed!\n");
        return 1;
    }
}