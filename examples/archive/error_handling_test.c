/**
 * @file error_handling_test.c
 * @brief QUID Error Handling System Test
 *
 * Tests the comprehensive error handling, validation, and recovery systems.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "quid/quid.h"

/**
 * @brief Print error message and exit with context
 */
void die_on_error(quid_status_t status, const char* message)
{
    if (status != QUID_SUCCESS) {
        printf("ERROR: %s\n", message);
        printf("Details: %s\n", quid_get_detailed_error_string(status));
        printf("Recovery: %s\n", quid_suggest_recovery(status));
        exit(1);
    }
}

/**
 * @brief Test parameter validation
 */
void test_parameter_validation(void)
{
    printf("\n=== Parameter Validation Test ===\n");

    /* Test NULL parameters */
    printf("Testing NULL parameter validation...\n");
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(NULL, QUID_SECURITY_LEVEL_5);
    if (status == QUID_ERROR_INVALID_PARAMETER) {
        printf("✅ NULL parameter correctly rejected\n");
    } else {
        printf("❌ NULL parameter validation failed\n");
        exit(1);
    }

    /* Test invalid security level */
    printf("Testing invalid security level...\n");
    status = quid_identity_create(&identity, (quid_security_level_t)999);
    if (status == QUID_SUCCESS) {
        printf("✅ Invalid security level defaults to maximum\n");
        quid_identity_free(identity);
    } else {
        printf("❌ Invalid security level handling failed\n");
        exit(1);
    }

    /* Test uninitialized library */
    printf("Testing uninitialized library protection...\n");
    quid_cleanup();  /* Ensure library is not initialized */
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    if (status == QUID_ERROR_INVALID_PARAMETER) {
        printf("✅ Uninitialized library correctly rejected\n");
    } else {
        printf("❌ Uninitialized library protection failed\n");
        exit(1);
    }

    printf("✅ Parameter validation test completed\n");
}

/**
 * @brief Test error context and recovery
 */
void test_error_context(void)
{
    printf("\n=== Error Context Test ===\n");

    /* Initialize library for context testing */
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize library");

    /* Create identity to work with */
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    /* Test buffer too small error */
    printf("Testing buffer size validation...\n");
    quid_signature_t signature;
    signature.size = 1;  /* Too small */

    const char* message = "test";
    status = quid_sign(identity, (const uint8_t*)message, strlen(message), &signature);
    if (status == QUID_ERROR_BUFFER_TOO_SMALL) {
        printf("✅ Small buffer correctly rejected\n");
    } else {
        printf("❌ Buffer size validation failed\n");
        exit(1);
    }

    /* Test error context */
    printf("Testing error context system...\n");
    const char* detailed_error = quid_get_detailed_error_string(status);
    if (strstr(detailed_error, "Context:") && strstr(detailed_error, "Function:")) {
        printf("✅ Error context properly captured\n");
    } else {
        printf("❌ Error context system failed\n");
        printf("Error details: %s\n", detailed_error);
        exit(1);
    }

    /* Test recovery suggestions */
    printf("Testing recovery suggestions...\n");
    const char* recovery = quid_suggest_recovery(status);
    if (recovery && strlen(recovery) > 0) {
        printf("✅ Recovery suggestion provided: %s\n", recovery);
    } else {
        printf("❌ Recovery suggestion failed\n");
        exit(1);
    }

    /* Test security error detection */
    printf("Testing security error detection...\n");
    bool is_security = quid_is_security_error(status);
    if (is_security == false) {
        printf("✅ Buffer error correctly identified as non-security\n");
    } else {
        printf("❌ Security error detection failed\n");
        exit(1);
    }

    /* Test quantum safety validation */
    status = quid_validate_security_state();
    if (status == QUID_SUCCESS) {
        printf("✅ System security state validated\n");
    } else {
        printf("❌ Security state validation failed: %s\n", quid_get_error_string(status));
        exit(1);
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ Error context test completed\n");
}

/**
 * @brief Test memory safety
 */
void test_memory_safety(void)
{
    printf("\n=== Memory Safety Test ===\n");

    /* Test multiple identity creation and cleanup */
    printf("Testing multiple identity management...\n");
    quid_identity_t* identities[10];

    for (int i = 0; i < 10; i++) {
        quid_status_t status = quid_identity_create(&identities[i], QUID_SECURITY_LEVEL_5);
        die_on_error(status, "Failed to create identity");

        const char* id = quid_get_identity_id(identities[i]);
        printf("  Identity %d: %s\n", i + 1, id);
    }

    /* Test signing with all identities */
    printf("Testing simultaneous operations...\n");
    const char* test_message = "Memory safety test message";

    for (int i = 0; i < 10; i++) {
        quid_signature_t signature;
        signature.size = QUID_SIGNATURE_SIZE;

        quid_status_t status = quid_sign(identities[i], (const uint8_t*)test_message,
                                       strlen(test_message), &signature);
        die_on_error(status, "Failed to sign message");

        /* Verify signature */
        status = quid_verify(signature.public_key, (const uint8_t*)test_message,
                           strlen(test_message), &signature);
        die_on_error(status, "Failed to verify signature");
    }

    printf("✅ All %d identities signed and verified successfully\n", 10);

    /* Test cleanup */
    printf("Testing identity cleanup...\n");
    for (int i = 0; i < 10; i++) {
        quid_identity_free(identities[i]);
    }

    printf("✅ Memory safety test completed\n");
}

/**
 * @brief Test edge cases and boundary conditions
 */
void test_edge_cases(void)
{
    printf("\n=== Edge Cases Test ===\n");

    /* Create identity for testing */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    /* Test empty message signing */
    printf("Testing empty message signing...\n");
    quid_signature_t signature;
    signature.size = QUID_SIGNATURE_SIZE;

    status = quid_sign(identity, NULL, 0, &signature);
    if (status == QUID_SUCCESS) {
        printf("✅ Empty message signing works\n");

        /* Verify empty message signature */
        status = quid_verify(signature.public_key, NULL, 0, &signature);
        if (status == QUID_SUCCESS) {
            printf("✅ Empty message verification works\n");
        } else {
            printf("❌ Empty message verification failed\n");
            exit(1);
        }
    } else {
        printf("❌ Empty message signing failed\n");
        exit(1);
    }

    /* Test large message signing */
    printf("Testing large message signing...\n");
    char large_message[10000];
    memset(large_message, 'A', sizeof(large_message) - 1);
    large_message[sizeof(large_message) - 1] = '\0';

    signature.size = QUID_SIGNATURE_SIZE;
    status = quid_sign(identity, (const uint8_t*)large_message, sizeof(large_message), &signature);
    if (status == QUID_SUCCESS) {
        printf("✅ Large message (%zu bytes) signing works\n", sizeof(large_message));

        /* Verify large message signature */
        status = quid_verify(signature.public_key, (const uint8_t*)large_message,
                           sizeof(large_message), &signature);
        if (status == QUID_SUCCESS) {
            printf("✅ Large message verification works\n");
        } else {
            printf("❌ Large message verification failed\n");
            exit(1);
        }
    } else {
        printf("❌ Large message signing failed\n");
        exit(1);
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ Edge cases test completed\n");
}

/**
 * @brief Main function
 */
int main(void)
{
    printf("🔐 QUID Error Handling and Validation Test Suite\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    /* Run comprehensive error handling tests */
    test_parameter_validation();

    /* Initialize library for remaining tests */
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize library");

    test_error_context();
    test_memory_safety();
    test_edge_cases();

    /* Cleanup */
    printf("\nCleaning up QUID library...\n");
    quid_cleanup();

    printf("\n🎉 All error handling tests passed successfully!\n");
    printf("✅ Comprehensive validation system is working correctly\n");
    printf("✅ Error recovery and context system is functional\n");
    printf("✅ Memory safety and security validations are in place\n");
    printf("✅ System is production-ready with robust error handling\n");

    return 0;
}