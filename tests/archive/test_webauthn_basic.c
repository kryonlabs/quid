/**
 * @file test_webauthn_basic.c
 * @brief Basic WebAuthn adapter test for QUID
 *
 * Minimal test for WebAuthn adapter functionality using only the standard adapter API.
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
static void test_webauthn_adapter_info(void)
{
    printf("\n=== WebAuthn Adapter Info Tests ===\n");

    /* Get adapter functions */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    TEST_ASSERT(functions != NULL, "Get WebAuthn adapter functions");
    TEST_ASSERT(functions->abi_version == QUID_ADAPTER_ABI_VERSION, "ABI version matches");
    TEST_ASSERT(functions->init != NULL, "Init function exists");
    TEST_ASSERT(functions->cleanup != NULL, "Cleanup function exists");
    TEST_ASSERT(functions->get_info != NULL, "Get info function exists");
    TEST_ASSERT(functions->derive_key != NULL, "Derive key function exists");

    /* Create a minimal context */
    quid_adapter_context_t context = {0};
    strcpy(context.network_name, "webauthn");
    strcpy(context.network_version, "1.0");

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(&context);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter");

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
            printf("   Adapter: %s v%s\n", info->name, info->version);
            printf("   Network: %s (%s)\n", info->network_name, info->description);
        }

        /* Cleanup */
        functions->cleanup(adapter);
    }
}

/**
 * @brief Test WebAuthn key derivation with QUID
 */
static void test_webauthn_key_derivation(void)
{
    printf("\n=== WebAuthn Key Derivation Tests ===\n");

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
    strcpy(webauthn_ctx.network_name, "webauthn");
    strcpy(webauthn_ctx.network_version, "1.0");

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(&webauthn_ctx);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter");

    if (adapter) {
        /* Test key derivation for different contexts */
        quid_context_t contexts[] = {
            {"webauthn", "example.com", "login", {0}, 0, QUID_SECURITY_LEVEL_5},
            {"webauthn", "example.com", "signup", {0}, 0, QUID_SECURITY_LEVEL_5},
            {"webauthn", "test.example.com", "2fa", {0}, 0, QUID_SECURITY_LEVEL_5}
        };

        uint8_t derived_keys[3][64];
        bool derivation_success[3] = {false};

        for (int i = 0; i < 3; i++) {
            quid_adapter_status_t adapter_status = functions->derive_key(
                adapter, master_key, sizeof(master_key),
                &contexts[i], derived_keys[i], sizeof(derived_keys[i]));

            TEST_ASSERT_SUCCESS(adapter_status, "Derive WebAuthn key");
            derivation_success[i] = (adapter_status == QUID_ADAPTER_SUCCESS);
        }

        /* Verify keys are different for different contexts */
        if (derivation_success[0] && derivation_success[1]) {
            TEST_ASSERT(memcmp(derived_keys[0], derived_keys[1], 64) != 0,
                       "Keys for different contexts are different");
        }

        /* Test same context produces same key */
        if (derivation_success[0]) {
            uint8_t repeat_key[64];
            quid_adapter_status_t adapter_status = functions->derive_key(
                adapter, master_key, sizeof(master_key),
                &contexts[0], repeat_key, sizeof(repeat_key));

            TEST_ASSERT_SUCCESS(adapter_status, "Derive repeat key");
            TEST_ASSERT(memcmp(derived_keys[0], repeat_key, 64) == 0,
                       "Same context produces same key");
        }

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
 * @brief Test WebAuthn signing and verification
 */
static void test_webauthn_signing_verification(void)
{
    printf("\n=== WebAuthn Signing Tests ===\n");

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
    uint8_t master_key[64];
    status = quid_derive_key(identity, &master_ctx, master_key, sizeof(master_key));
    TEST_ASSERT(status == QUID_SUCCESS, "Derive master key from identity");

    /* Create WebAuthn adapter context */
    quid_adapter_context_t webauthn_ctx = {0};
    strcpy(webauthn_ctx.network_name, "webauthn");
    strcpy(webauthn_ctx.network_version, "1.0");

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(&webauthn_ctx);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter");

    if (adapter) {
        /* Derive signing key */
        quid_context_t signing_ctx = {"webauthn", "example.com", "assertion", {0}, 0, QUID_SECURITY_LEVEL_5};
        uint8_t signing_key[64];
        quid_adapter_status_t adapter_status = functions->derive_key(
            adapter, master_key, sizeof(master_key),
            &signing_ctx, signing_key, sizeof(signing_key));

        TEST_ASSERT_SUCCESS(adapter_status, "Derive signing key");

        if (adapter_status == QUID_ADAPTER_SUCCESS) {
            /* Test message signing */
            uint8_t message[] = "Test WebAuthn assertion message";
            uint8_t signature[256];
            size_t signature_size = sizeof(signature);

            adapter_status = functions->sign(adapter, signing_key, sizeof(signing_key),
                                            message, strlen((char*)message), signature, &signature_size);
            TEST_ASSERT_SUCCESS(adapter_status, "Sign WebAuthn message");
            TEST_ASSERT(signature_size > 0, "Signature has size");

            /* Test verification */
            adapter_status = functions->verify(adapter, signing_key, sizeof(signing_key),
                                              message, strlen((char*)message), signature, signature_size);
            TEST_ASSERT_SUCCESS(adapter_status, "Verify WebAuthn signature");

            /* Test verification with wrong message fails */
            uint8_t wrong_message[] = "Wrong WebAuthn assertion message";
            adapter_status = functions->verify(adapter, signing_key, sizeof(signing_key),
                                              wrong_message, strlen((char*)wrong_message), signature, signature_size);
            TEST_ASSERT(adapter_status != QUID_ADAPTER_SUCCESS, "Verify wrong message fails");
        }

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
 * @brief Test WebAuthn error handling
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

    /* Test invalid context */
    quid_adapter_context_t invalid_ctx = {0};
    quid_adapter_t* adapter = functions->init(&invalid_ctx);

    /* Adapter should still initialize but maybe with limited functionality */
    if (adapter) {
        functions->cleanup(adapter);
    }

    printf("✅ Error handling tests completed\n");
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 WebAuthn Adapter Basic Tests\n");

    /* Run all tests */
    test_webauthn_adapter_info();
    test_webauthn_key_derivation();
    test_webauthn_signing_verification();
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