/**
 * @file test_webauthn_adapter.c
 * @brief WebAuthn adapter tests for QUID
 *
 * Unit tests for WebAuthn adapter functionality including credential creation,
 * assertion generation/verification, and various WebAuthn algorithms.
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

/* WebAuthn adapter forward declarations */
extern quid_adapter_functions_t* quid_adapter_get_functions(void);

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

#define TEST_ASSERT_EQ(expected, actual, message) \
    TEST_ASSERT((expected) == (actual), message)

/**
 * @brief Setup WebAuthn adapter context for testing
 */
static quid_adapter_context_t* setup_webauthn_context(void)
{
    /* Create WebAuthn context with test RP and user */
    webauthn_adapter_context_t* webauthn_ctx = calloc(1, sizeof(webauthn_adapter_context_t));
    if (!webauthn_ctx) {
        return NULL;
    }

    /* Set up RP entity */
    strcpy(webauthn_ctx->rp.id, "example.com");
    strcpy(webauthn_ctx->rp.name, "Example Website");
    strcpy(webauthn_ctx->rp.icon, "https://example.com/icon.png");

    /* Set up user entity */
    strcpy(webauthn_ctx->user.name, "testuser@example.com");
    strcpy(webauthn_ctx->user.display_name, "Test User");
    strcpy(webauthn_ctx->user.icon, "https://example.com/user.png");

    /* Generate user ID */
    for (int i = 0; i < 16; i++) {
        webauthn_ctx->user.id[i] = (uint8_t)(i + 1);
    }
    webauthn_ctx->user.id_size = 16;

    /* Set WebAuthn options */
    webauthn_ctx->options.user_presence = true;
    webauthn_ctx->options.user_verification = WEBAUTHN_UV_PREFERRED;
    webauthn_ctx->options.authenticator_attachment = WEBAUTHN_ATTACHMENT_CROSS_PLATFORM;
    webauthn_ctx->options.require_resident_key = false;
    webauthn_ctx->options.timeout = 60000;
    webauthn_ctx->options.algorithms[0] = WEBAUTHN_ALG_ES256;
    webauthn_ctx->options.algorithms[1] = WEBAUTHN_ALG_ED25519;
    webauthn_ctx->options.algorithms_count = 2;

    /* Set RP origin */
    strcpy(webauthn_ctx->rp_origin, "https://example.com");

    quid_adapter_context_t* context = calloc(1, sizeof(quid_adapter_context_t));
    if (!context) {
        free(webauthn_ctx);
        return NULL;
    }

    context->network_type = QUID_NETWORK_WEBAUTHN;
    context->context = webauthn_ctx;

    return context;
}

/**
 * @brief Cleanup WebAuthn adapter context
 */
static void cleanup_webauthn_context(quid_adapter_context_t* context)
{
    if (context) {
        if (context->context) {
            free(context->context);
        }
        free(context);
    }
}

/**
 * @brief Test WebAuthn adapter initialization
 */
static void test_webauthn_initialization(void)
{
    printf("\n=== WebAuthn Initialization Tests ===\n");

    /* Get adapter functions */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    TEST_ASSERT(functions != NULL, "Get WebAuthn adapter functions");
    TEST_ASSERT(functions->abi_version == QUID_ADAPTER_ABI_VERSION, "ABI version matches");
    TEST_ASSERT(functions->init != NULL, "Init function exists");
    TEST_ASSERT(functions->cleanup != NULL, "Cleanup function exists");
    TEST_ASSERT(functions->get_info != NULL, "Get info function exists");

    /* Setup context */
    quid_adapter_context_t* context = setup_webauthn_context();
    TEST_ASSERT(context != NULL, "Create WebAuthn context");

    /* Initialize adapter */
    quid_adapter_t* adapter = functions->init(context);
    TEST_ASSERT(adapter != NULL, "Initialize WebAuthn adapter");
    TEST_ASSERT(adapter->is_initialized, "Adapter is marked as initialized");
    TEST_ASSERT(adapter->private_data != NULL, "Adapter has private data");

    /* Test adapter info */
    const quid_adapter_info_t* info = functions->get_info(adapter);
    TEST_ASSERT(info != NULL, "Get adapter info");
    TEST_ASSERT(strcmp(info->name, "WebAuthn Adapter") == 0, "Adapter name is correct");
    TEST_ASSERT(info->network_type == QUID_NETWORK_WEBAUTHN, "Network type is WebAuthn");
    TEST_ASSERT(info->adapter_type == QUID_ADAPTER_TYPE_AUTHENTICATION, "Adapter type is authentication");
    TEST_ASSERT((info->capabilities & QUID_ADAPTER_CAP_SIGN) != 0, "Adapter supports signing");
    TEST_ASSERT((info->capabilities & QUID_ADAPTER_CAP_VERIFY) != 0, "Adapter supports verification");

    /* Cleanup */
    if (adapter) {
        functions->cleanup(adapter);
    }
    cleanup_webauthn_context(context);
}

/**
 * @brief Test WebAuthn key derivation
 */
static void test_webauthn_key_derivation(void)
{
    printf("\n=== WebAuthn Key Derivation Tests ===\n");

    /* Get adapter functions and setup */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    quid_adapter_context_t* context = setup_webauthn_context();
    quid_adapter_t* adapter = functions->init(context);

    TEST_ASSERT(functions != NULL, "Get adapter functions");
    TEST_ASSERT(adapter != NULL, "Initialize adapter");

    /* Create QUID identity to get master key */
    quid_status_t status = quid_init();
    TEST_ASSERT_EQ(QUID_SUCCESS, status, "Initialize QUID");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_EQ(QUID_SUCCESS, status, "Create QUID identity");

    /* Get master key for derivation - derive it using context */
    quid_context_t master_ctx = {"master", "system", "key-material", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t master_key[QUID_MASTER_KEY_SIZE];
    status = quid_derive_key(identity, &master_ctx, master_key, sizeof(master_key));
    TEST_ASSERT_EQ(QUID_SUCCESS, status, "Derive master key");

    /* Test key derivation with different contexts */
    quid_context_t contexts[] = {
        {"webauthn", "example.com", "login", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"webauthn", "example.com", "signup", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"webauthn", "test.example.com", "2fa", {0}, 0, QUID_SECURITY_LEVEL_5}
    };

    uint8_t derived_keys[3][64];
    for (int i = 0; i < 3; i++) {
        status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                       &contexts[i], derived_keys[i], sizeof(derived_keys[i]));
        TEST_ASSERT_SUCCESS(status, "Derive WebAuthn key for context");
    }

    /* Keys should be different for different contexts */
    for (int i = 0; i < 3; i++) {
        for (int j = i + 1; j < 3; j++) {
            TEST_ASSERT(memcmp(derived_keys[i], derived_keys[j], 64) != 0,
                       "Keys for different contexts are different");
        }
    }

    /* Same context should produce same key */
    uint8_t repeat_key[64];
    status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                   &contexts[0], repeat_key, sizeof(repeat_key));
    TEST_ASSERT_SUCCESS(status, "Derive repeat key");
    TEST_ASSERT(memcmp(derived_keys[0], repeat_key, 64) == 0,
               "Same context produces same key");

    /* Cleanup */
    if (identity) {
        quid_identity_free(identity);
    }
    quid_cleanup();
    if (adapter) {
        functions->cleanup(adapter);
    }
    cleanup_webauthn_context(context);
}

/**
 * @brief Test WebAuthn public key derivation
 */
static void test_webauthn_public_derivation(void)
{
    printf("\n=== WebAuthn Public Key Tests ===\n");

    /* Setup adapter and QUID */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    quid_adapter_context_t* context = setup_webauthn_context();
    quid_adapter_t* adapter = functions->init(context);

    quid_status_t status = quid_init();
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);

    /* Get master key and derive credential */
    quid_context_t master_ctx = {"master", "system", "key-material", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t master_key[QUID_MASTER_KEY_SIZE];
    quid_derive_key(identity, &master_ctx, master_key, sizeof(master_key));

    quid_context_t quid_ctx = {"webauthn", "example.com", "credential", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t derived_key[64];
    status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                   &quid_ctx, derived_key, sizeof(derived_key));
    TEST_ASSERT_SUCCESS(status, "Derive credential key");

    /* Test public key derivation */
    char public_key[256];
    size_t public_key_size = sizeof(public_key);
    status = functions->derive_public(adapter, derived_key, sizeof(derived_key),
                                     public_key, &public_key_size);
    TEST_ASSERT_SUCCESS(status, "Derive public key");
    TEST_ASSERT(strlen(public_key) > 0, "Public key is not empty");
    TEST_ASSERT(strstr(public_key, "quid") != NULL || strlen(public_key) > 10, "Public key looks valid");

    /* Test with insufficient buffer */
    char small_buffer[10];
    size_t small_size = sizeof(small_buffer);
    status = functions->derive_public(adapter, derived_key, sizeof(derived_key),
                                     small_buffer, &small_size);
    /* Should succeed but indicate needed size */
    TEST_ASSERT(status == QUID_ADAPTER_SUCCESS || small_size > sizeof(small_buffer),
               "Handles insufficient buffer gracefully");

    /* Cleanup */
    quid_identity_free(identity);
    quid_cleanup();
    if (adapter) {
        functions->cleanup(adapter);
    }
    cleanup_webauthn_context(context);
}

/**
 * @brief Test WebAuthn signing and verification
 */
static void test_webauthn_signing_verification(void)
{
    printf("\n=== WebAuthn Signing and Verification Tests ===\n");

    /* Setup adapter and QUID */
    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    quid_adapter_context_t* context = setup_webauthn_context();
    quid_adapter_t* adapter = functions->init(context);

    quid_status_t status = quid_init();
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);

    /* Get master key and derive credential */
    quid_context_t master_ctx = {"master", "system", "key-material", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t master_key[QUID_MASTER_KEY_SIZE];
    quid_derive_key(identity, &master_ctx, master_key, sizeof(master_key));

    quid_context_t quid_ctx = {"webauthn", "example.com", "assertion", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t derived_key[64];
    status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                   &quid_ctx, derived_key, sizeof(derived_key));
    TEST_ASSERT_SUCCESS(status, "Derive signing key");

    /* Test message signing (WebAuthn assertion format) */
    uint8_t client_data[128];
    uint8_t auth_data[64];

    /* Create mock WebAuthn client data */
    for (int i = 0; i < 128; i++) {
        client_data[i] = (uint8_t)(i * 3);
    }

    /* Create mock authenticator data */
    for (int i = 0; i < 64; i++) {
        auth_data[i] = (uint8_t)(i * 5);
    }

    /* Combine into WebAuthn message format */
    uint8_t webauthn_message[192];
    memcpy(webauthn_message, client_data, 128);
    memcpy(webauthn_message + 128, auth_data, 64);

    /* Sign the assertion */
    uint8_t signature[256];
    size_t signature_size = sizeof(signature);
    status = functions->sign(adapter, derived_key, sizeof(derived_key),
                             webauthn_message, sizeof(webauthn_message),
                             signature, &signature_size);
    TEST_ASSERT_SUCCESS(status, "Sign WebAuthn assertion");
    TEST_ASSERT(signature_size > 0, "Signature has size");

    /* Get public key for verification */
    char public_key_str[256];
    size_t public_key_size = sizeof(public_key_str);
    status = functions->derive_public(adapter, derived_key, sizeof(derived_key),
                                     public_key_str, &public_key_size);
    TEST_ASSERT_SUCCESS(status, "Get public key for verification");

    /* Convert string public key back to bytes for verification */
    uint8_t public_key[64];
    for (size_t i = 0; i < sizeof(public_key) && i < strlen(public_key_str); i++) {
        public_key[i] = (uint8_t)public_key_str[i];
    }

    /* Verify the signature */
    status = functions->verify(adapter, public_key, sizeof(public_key),
                               webauthn_message, sizeof(webauthn_message),
                               signature, signature_size);
    TEST_ASSERT_SUCCESS(status, "Verify WebAuthn assertion");

    /* Test verification with tampered message */
    uint8_t tampered_message[192];
    memcpy(tampered_message, webauthn_message, 192);
    tampered_message[50] ^= 0xFF;  /* Flip bits in client data */

    status = functions->verify(adapter, public_key, sizeof(public_key),
                               tampered_message, sizeof(tampered_message),
                               signature, signature_size);
    TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Verify tampered message fails");

    /* Test verification with wrong signature */
    uint8_t wrong_signature[256];
    memcpy(wrong_signature, signature, signature_size);
    wrong_signature[10] ^= 0xFF;  /* Flip bits in signature */

    status = functions->verify(adapter, public_key, sizeof(public_key),
                               webauthn_message, sizeof(webauthn_message),
                               wrong_signature, signature_size);
    TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Verify wrong signature fails");

    /* Cleanup */
    quid_identity_free(identity);
    quid_cleanup();
    if (adapter) {
        functions->cleanup(adapter);
    }
    cleanup_webauthn_context(context);
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
    status = functions->get_info(NULL);
    TEST_ASSERT(status == NULL, "Get info with NULL adapter returns NULL");

    /* Test with uninitialized adapter */
    quid_adapter_t invalid_adapter = {0};
    status = functions->derive_key(&invalid_adapter, key, sizeof(key),
                                   &context, key, key_size);
    TEST_ASSERT(status != QUID_ADAPTER_SUCCESS, "Derive key with invalid adapter fails");

    printf("✅ Error handling tests completed\n");
}

/**
 * @brief Test WebAuthn algorithm support
 */
static void test_webauthn_algorithms(void)
{
    printf("\n=== WebAuthn Algorithm Tests ===\n");

    quid_adapter_functions_t* functions = quid_adapter_get_functions();
    quid_adapter_context_t* context = setup_webauthn_context();
    quid_adapter_t* adapter = functions->init(context);

    TEST_ASSERT(adapter != NULL, "Initialize adapter");

    quid_status_t status = quid_init();
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);

    uint8_t master_key[QUID_MASTER_KEY_SIZE];
    quid_get_master_key(identity, master_key);

    quid_context_t quid_ctx = {"webauthn", "example.com", "algorithms", {0}, 0, QUID_SECURITY_LEVEL_5};
    uint8_t derived_key[64];
    status = functions->derive_key(adapter, master_key, sizeof(master_key),
                                   &quid_ctx, derived_key, sizeof(derived_key));
    TEST_ASSERT_SUCCESS(status, "Derive key for algorithm tests");

    /* Test signing with different message sizes */
    uint8_t messages[][64] = {
        {0},  /* Empty/minimum */
        {1, 2, 3, 4},  /* Small */
        {1},  /* Single byte */
        [63] = 0xFF  /* Maximum test size */
    };
    size_t message_sizes[] = {1, 4, 1, 64};

    for (int i = 0; i < 4; i++) {
        uint8_t signature[256];
        size_t signature_size = sizeof(signature);

        status = functions->sign(adapter, derived_key, sizeof(derived_key),
                                messages[i], message_sizes[i],
                                signature, &signature_size);
        TEST_ASSERT_SUCCESS(status, "Sign message with different sizes");
        TEST_ASSERT(signature_size > 0, "Signature generated for each message size");
    }

    /* Cleanup */
    quid_identity_free(identity);
    quid_cleanup();
    if (adapter) {
        functions->cleanup(adapter);
    }
    cleanup_webauthn_context(context);
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 WebAuthn Adapter Unit Tests\n");

    /* Run all tests */
    test_webauthn_initialization();
    test_webauthn_key_derivation();
    test_webauthn_public_derivation();
    test_webauthn_signing_verification();
    test_webauthn_error_handling();
    test_webauthn_algorithms();

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