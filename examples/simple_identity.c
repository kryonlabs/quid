/**
 * @file simple_identity.c
 * @brief Simple QUID identity example
 *
 * Demonstrates basic QUID identity creation and usage.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "quid/quid.h"

/**
 * @brief Print error message and exit
 * @param status Error status
 * @param message Context message
 */
void die_on_error(quid_status_t status, const char* message)
{
    if (status != QUID_SUCCESS) {
        fprintf(stderr, "ERROR: %s - %s\n", message, quid_get_error_string(status));
        exit(1);
    }
}

/**
 * @brief Print binary data as hex
 * @param data Binary data
 * @param size Data size
 * @param label Optional label
 */
void print_hex(const uint8_t* data, size_t size, const char* label)
{
    if (label) {
        printf("%s: ", label);
    }

    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n");
            if (label && i < size - 1) {
                printf("%*s", (int)strlen(label) + 2, "");
            }
        } else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
    if (size % 32 != 0) {
        printf("\n");
    }
}

/**
 * @brief Demonstrate basic identity operations
 */
void demonstrate_basic_identity(void)
{
    printf("\n=== Basic Identity Operations ===\n");

    /* Create new identity */
    printf("Creating new QUID identity...\n");
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    /* Get identity ID */
    const char* id_string = quid_get_identity_id(identity);
    printf("Identity ID: %s\n", id_string);

    /* Test message signing */
    const char* message = "Hello, QUID world!";
    quid_signature_t signature;
    signature.size = QUID_SIGNATURE_SIZE; /* Initialize buffer size */
    status = quid_sign(identity, (const uint8_t*)message, strlen(message), &signature);
    die_on_error(status, "Failed to sign message");

    /* Debug: Check signature immediately after signing in example */
    printf("DEBUG: First 32 bytes of signature immediately after quid_sign:\n");
    for (int i = 0; i < 4; i++) {
        printf("  %02x%02x%02x%02x%02x%02x%02x%02x\n",
               signature.data[i*8], signature.data[i*8+1], signature.data[i*8+2], signature.data[i*8+3],
               signature.data[i*8+4], signature.data[i*8+5], signature.data[i*8+6], signature.data[i*8+7]);
    }

    printf("Signed message: '%s'\n", message);
    printf("Expected signature size: %d bytes\n", QUID_SIGNATURE_SIZE);
    printf("Actual signature size: %zu bytes\n", signature.size);
    printf("Skipping signature hex print to test for corruption\n");
    // print_hex(signature.data, signature.size, "  ");  // Temporarily disabled to test corruption

    /* Get public key */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];

    /* Debug: Check signature before quid_get_public_key */
    printf("DEBUG: First 32 bytes of signature BEFORE quid_get_public_key:\n");
    for (int i = 0; i < 4; i++) {
        printf("  %02x%02x%02x%02x%02x%02x%02x%02x\n",
               signature.data[i*8], signature.data[i*8+1], signature.data[i*8+2], signature.data[i*8+3],
               signature.data[i*8+4], signature.data[i*8+5], signature.data[i*8+6], signature.data[i*8+7]);
    }

    status = quid_get_public_key(identity, public_key);
    die_on_error(status, "Failed to get public key");

    /* Debug: Check signature after quid_get_public_key */
    printf("DEBUG: First 32 bytes of signature AFTER quid_get_public_key:\n");
    for (int i = 0; i < 4; i++) {
        printf("  %02x%02x%02x%02x%02x%02x%02x%02x\n",
               signature.data[i*8], signature.data[i*8+1], signature.data[i*8+2], signature.data[i*8+3],
               signature.data[i*8+4], signature.data[i*8+5], signature.data[i*8+6], signature.data[i*8+7]);
    }

    printf("Public key (%zu bytes) - skipping hex print to test\n", (size_t)QUID_PUBLIC_KEY_SIZE);
    // print_hex(public_key, QUID_PUBLIC_KEY_SIZE, "  ");  // Temporarily disabled to test

    /* Debug: Check signature after print_hex(public_key) */
    printf("DEBUG: First 32 bytes of signature AFTER print_hex(public_key):\n");
    for (int i = 0; i < 4; i++) {
        printf("  %02x%02x%02x%02x%02x%02x%02x%02x\n",
               signature.data[i*8], signature.data[i*8+1], signature.data[i*8+2], signature.data[i*8+3],
               signature.data[i*8+4], signature.data[i*8+5], signature.data[i*8+6], signature.data[i*8+7]);
    }

    /* Compare public keys */
    printf("Comparing public keys:\n");
    int keys_match = (memcmp(public_key, signature.public_key, QUID_PUBLIC_KEY_SIZE) == 0);
    printf("Keys match: %s\n", keys_match ? "YES" : "NO");
    if (!keys_match) {
        printf("First 32 bytes of identity public key:\n");
        print_hex(public_key, 32, "  ");
        printf("First 32 bytes of signature public key:\n");
        print_hex(signature.public_key, 32, "  ");
    }

    /* Debug: Show signature data right before verification */
    printf("DEBUG: First 32 bytes of signature right before verification:\n");
    for (int i = 0; i < 4; i++) {
        printf("  %02x%02x%02x%02x%02x%02x%02x%02x\n",
               signature.data[i*8], signature.data[i*8+1], signature.data[i*8+2], signature.data[i*8+3],
               signature.data[i*8+4], signature.data[i*8+5], signature.data[i*8+6], signature.data[i*8+7]);
    }

    /* Test signature verification - use the public key from signature */
    status = quid_verify(signature.public_key, (const uint8_t*)message, strlen(message), &signature);
    die_on_error(status, "Failed to verify signature");
    printf("Signature verification: SUCCESS\n");

    /* Test tampered signature verification */
    uint8_t tampered_message[] = "Hello, QUID world?";  /* Changed last character */
    status = quid_verify(signature.public_key, tampered_message, sizeof(tampered_message) - 1, &signature);
    if (status != QUID_SUCCESS) {
        printf("Tampered signature verification: FAILED (as expected)\n");
    } else {
        printf("ERROR: Tampered signature verified - this should not happen!\n");
    }

    /* Clean up */
    quid_identity_free(identity);
    printf("Identity cleaned up successfully.\n");
}

/**
 * @brief Demonstrate key derivation for different networks
 */
void demonstrate_key_derivation(void)
{
    printf("\n=== Key Derivation for Networks ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    /* Derive keys for different networks */
    struct {
        const char* network;
        const char* application;
        const char* purpose;
    } contexts[] = {
        {"bitcoin", "mainnet", "p2pkh"},
        {"ethereum", "mainnet", "account"},
        {"ssh", "server", "hostkey"},
        {"webauthn", "example.com", "credential"}
    };

    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); i++) {
        quid_context_t context = {0};
        strncpy(context.network_type, contexts[i].network, sizeof(context.network_type) - 1);
        strncpy(context.application_id, contexts[i].application, sizeof(context.application_id) - 1);
        strncpy(context.purpose, contexts[i].purpose, sizeof(context.purpose) - 1);
        context.security = QUID_SECURITY_LEVEL_5;

        uint8_t derived_key[64];
        status = quid_derive_key(identity, &context, derived_key, sizeof(derived_key));
        die_on_error(status, "Failed to derive key");

        printf("\nNetwork: %s\n", contexts[i].network);
        printf("Application: %s\n", contexts[i].application);
        printf("Purpose: %s\n", contexts[i].purpose);
        printf("Derived key (first 32 bytes):\n");
        print_hex(derived_key, 32, "  ");
    }

    /* Clean up */
    quid_identity_free(identity);
}

/**
 * @brief Demonstrate authentication
 */
void demonstrate_authentication(void)
{
    printf("\n=== Authentication Demo ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    /* Create authentication request */
    quid_auth_request_t request = {0};
    strncpy(request.context.network_type, "web", sizeof(request.context.network_type) - 1);
    strncpy(request.context.application_id, "example.com", sizeof(request.context.application_id) - 1);
    strncpy(request.context.purpose, "login", sizeof(request.context.purpose) - 1);
    request.context.security = QUID_SECURITY_LEVEL_5;

    /* Generate random challenge (normally done by server) */
    status = quid_random_bytes(request.challenge, 32);
    die_on_error(status, "Failed to generate challenge");
    request.challenge_len = 32;
    request.timestamp = (uint64_t)time(NULL) * 1000;

    /* Generate printable nonce for demo */
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 15; i++) {
        uint8_t rand_byte;
        status = quid_random_bytes(&rand_byte, 1);
        die_on_error(status, "Failed to generate random byte");
        request.nonce[i] = charset[rand_byte % (sizeof(charset) - 1)];
    }
    request.nonce[15] = '\0';

    printf("Authentication Request:\n");
    printf("  Network: %s\n", request.context.network_type);
    printf("  Application: %s\n", request.context.application_id);
    printf("  Purpose: %s\n", request.context.purpose);
    printf("  Challenge: ");
    print_hex(request.challenge, request.challenge_len, NULL);
    printf("  Nonce: %s\n", request.nonce);
    printf("  Timestamp: %lu\n", request.timestamp);

    /* Authenticate */
    quid_auth_response_t response;
    status = quid_authenticate(identity, &request, &response);
    die_on_error(status, "Failed to authenticate");

    printf("\nAuthentication Response:\n");
    printf("  Identity ID: %s\n", response.identity_id);
    printf("  Proof (%zu bytes):\n", response.proof_len);
    print_hex(response.proof, response.proof_len, "    ");
    printf("  Timestamp: %lu\n", response.timestamp);

    /* Verify authentication */
    status = quid_verify_auth(&response, &request, response.identity_id);
    die_on_error(status, "Failed to verify authentication");
    printf("\nAuthentication verification: SUCCESS\n");

    /* Clean up */
    quid_identity_free(identity);
}

/**
 * @brief Demonstrate memory protection
 */
void demonstrate_memory_protection(void)
{
    printf("\n=== Memory Protection Demo ===\n");

    /* Create identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity");

    printf("Initial state - Locked: %s\n",
           quid_identity_is_locked(identity) ? "YES" : "NO");

    /* Lock identity */
    status = quid_identity_lock(identity);
    die_on_error(status, "Failed to lock identity");
    printf("After lock() - Locked: %s\n",
           quid_identity_is_locked(identity) ? "YES" : "NO");

    /* Unlock identity */
    status = quid_identity_unlock(identity);
    die_on_error(status, "Failed to unlock identity");
    printf("After unlock() - Locked: %s\n",
           quid_identity_is_locked(identity) ? "YES" : "NO");

    /* Clean up */
    quid_identity_free(identity);
    printf("Memory protection demo completed.\n");
}

/**
 * @brief Main function
 */
int main(void)
{
    printf("🔐 QUID (Quantum-Resistant Universal Identity) Demo\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    /* Initialize QUID library */
    printf("\nInitializing QUID library...\n");
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize QUID");

    /* Run demonstrations */
    demonstrate_basic_identity();
    demonstrate_key_derivation();
    demonstrate_authentication();
    demonstrate_memory_protection();

    /* Cleanup */
    printf("\nCleaning up QUID library...\n");
    quid_cleanup();

    printf("\n✅ Demo completed successfully!\n");
    printf("Your quantum-resistant identity system is ready for use.\n");

    return 0;
}
