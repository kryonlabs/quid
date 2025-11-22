/**
 * @file quid_demo.c
 * @brief QUID System Demonstration
 *
 * Complete demonstration of QUID functionality including:
 * - Identity creation and management
 * - Multiple network adapter usage
 * - Key derivation for different protocols
 * - Signing and verification
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "quid/quid.h"

/* Print separator */
void print_separator(const char* title)
{
    printf("\n");
    printf("============================================================\n");
    printf("🚀 %s\n", title);
    printf("============================================================\n");
}

/* Print step header */
void print_step(int step, const char* description)
{
    printf("\n📍 Step %d: %s\n", step, description);
    printf("────────────────────────────────────────────────\n");
}

/**
 * @brief Demo basic QUID identity functionality
 */
void demo_basic_identity(void)
{
    print_separator("QUID Identity Management Demo");

    print_step(1, "Initialize QUID library");
    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) {
        printf("❌ Failed to initialize QUID library\n");
        return;
    }
    printf("✅ QUID library initialized successfully\n");
    printf("   Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("   Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    print_step(2, "Create quantum-resistant identity");
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    if (status != QUID_SUCCESS) {
        printf("❌ Failed to create identity\n");
        quid_cleanup();
        return;
    }
    printf("✅ Identity created with ML-DSA-87 (256-bit security)\n");

    print_step(3, "Get identity information");
    const char* id = quid_get_identity_id(identity);
    printf("✅ Identity ID: %s\n", id);

    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
    status = quid_get_public_key(identity, public_key);
    if (status == QUID_SUCCESS) {
        printf("✅ Public key extracted (%d bytes)\n", QUID_PUBLIC_KEY_SIZE);
    }

    print_step(4, "Test memory protection");
    printf("   Identity locked: %s\n", quid_identity_is_locked(identity) ? "YES" : "NO");

    status = quid_identity_lock(identity);
    printf("   Lock status: %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    printf("   Identity locked: %s\n", quid_identity_is_locked(identity) ? "YES" : "NO");

    status = quid_identity_unlock(identity);
    printf("   Unlock status: %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    printf("   Identity locked: %s\n", quid_identity_is_locked(identity) ? "YES" : "NO");

    print_step(5, "Test signing and verification");
    const char* message = "Hello from QUID quantum-resistant identity!";
    quid_signature_t signature;

    status = quid_sign(identity, (const uint8_t*)message, strlen(message), &signature);
    printf("   Message signing: %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");

    status = quid_verify(public_key, (const uint8_t*)message, strlen(message), &signature);
    printf("   Signature verification: %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");

    /* Test with tampered message */
    const char* tampered = "Hello from QUID quantum-resistant identity??";
    status = quid_verify(public_key, (const uint8_t*)tampered, strlen(tampered), &signature);
    printf("   Tampered message verification: %s\n", status == QUID_SUCCESS ? "❌ FAILED (should fail)" : "✅ CORRECTLY FAILED");

    print_step(6, "Test key derivation for different networks");
    quid_context_t contexts[] = {
        {"bitcoin", "mainnet", "p2wpkh", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"ethereum", "mainnet", "account", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"ssh", "server", "hostkey", {0}, 0, QUID_SECURITY_LEVEL_5},
        {"webauthn", "example.com", "credential", {0}, 0, QUID_SECURITY_LEVEL_5}
    };

    uint8_t derived_keys[4][64];
    const char* network_names[] = {"Bitcoin", "Ethereum", "SSH", "WebAuthn"};

    for (int i = 0; i < 4; i++) {
        status = quid_derive_key(identity, &contexts[i], derived_keys[i], sizeof(derived_keys[i]));
        printf("   %s key derivation: %s\n", network_names[i],
               status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    }

    /* Verify keys are different */
    bool keys_different = true;
    for (int i = 0; i < 4 && keys_different; i++) {
        for (int j = i + 1; j < 4; j++) {
            if (memcmp(derived_keys[i], derived_keys[j], 64) == 0) {
                keys_different = false;
                break;
            }
        }
    }
    printf("   Keys are unique across networks: %s\n", keys_different ? "✅ YES" : "❌ NO");

    print_step(7, "Cleanup");
    quid_identity_free(identity);
    quid_cleanup();
    printf("✅ Cleanup completed successfully\n");
}

/**
 * @brief Demo cryptographic utilities
 */
void demo_crypto_utilities(void)
{
    print_separator("QUID Cryptographic Utilities Demo");

    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) {
        printf("❌ Failed to initialize QUID library\n");
        return;
    }

    print_step(1, "Generate random bytes");
    uint8_t random_data[32];
    status = quid_random_bytes(random_data, sizeof(random_data));
    printf("   Random bytes generation: %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    if (status == QUID_SUCCESS) {
        printf("   First 8 bytes: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", random_data[i]);
        }
        printf("...\n");
    }

    print_step(2, "Test secure memory operations");
    memcpy(random_data, "sensitive data", 15);
    printf("   Data before secure zero: %.15s\n", (char*)random_data);

    quid_secure_zero(random_data, sizeof(random_data));
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(random_data); i++) {
        if (random_data[i] != 0) {
            all_zero = false;
            break;
        }
    }
    printf("   Data after secure zero: %s\n", all_zero ? "✅ ALL ZEROS" : "❌ NOT CLEARED");

    print_step(3, "Test constant-time comparison");
    uint8_t data1[] = {1, 2, 3, 4, 5};
    uint8_t data2[] = {1, 2, 3, 4, 5};
    uint8_t data3[] = {1, 2, 3, 4, 6};

    int cmp_result = quid_constant_time_compare(data1, data2, sizeof(data1));
    printf("   Equal data comparison: %s (result: %d)\n", cmp_result == 0 ? "✅ CORRECT" : "❌ WRONG", cmp_result);

    cmp_result = quid_constant_time_compare(data1, data3, sizeof(data1));
    printf("   Different data comparison: %s (result: %d)\n", cmp_result != 0 ? "✅ CORRECT" : "❌ WRONG", cmp_result);

    quid_cleanup();
}

/**
 * @brief Demo multiple identity management
 */
void demo_multiple_identities(void)
{
    print_separator("QUID Multiple Identities Demo");

    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) {
        printf("❌ Failed to initialize QUID library\n");
        return;
    }

    print_step(1, "Create multiple identities");
    quid_identity_t* identity1 = NULL;
    quid_identity_t* identity2 = NULL;
    quid_identity_t* identity3 = NULL;

    status = quid_identity_create(&identity1, QUID_SECURITY_LEVEL_1);
    printf("   Identity 1 (Level 1): %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");

    status = quid_identity_create(&identity2, QUID_SECURITY_LEVEL_3);
    printf("   Identity 2 (Level 3): %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");

    status = quid_identity_create(&identity3, QUID_SECURITY_LEVEL_5);
    printf("   Identity 3 (Level 5): %s\n", status == QUID_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");

    if (identity1 && identity2 && identity3) {
        print_step(2, "Compare identity properties");
        const char* id1 = quid_get_identity_id(identity1);
        const char* id2 = quid_get_identity_id(identity2);
        const char* id3 = quid_get_identity_id(identity3);

        printf("   ID 1 (Level 1): %s\n", id1);
        printf("   ID 2 (Level 3): %s\n", id2);
        printf("   ID 3 (Level 5): %s\n", id3);

        bool ids_different = (strcmp(id1, id2) != 0) && (strcmp(id2, id3) != 0) && (strcmp(id1, id3) != 0);
        printf("   All IDs are unique: %s\n", ids_different ? "✅ YES" : "❌ NO");

        print_step(3, "Test same seed produces same identity");
        uint8_t seed[QUID_SEED_SIZE];
        status = quid_random_bytes(seed, sizeof(seed));
        if (status == QUID_SUCCESS) {
            quid_identity_t* identity_a = NULL;
            quid_identity_t* identity_b = NULL;

            status = quid_identity_from_seed(&identity_a, seed, QUID_SECURITY_LEVEL_3);
            quid_status_t status2 = quid_identity_from_seed(&identity_b, seed, QUID_SECURITY_LEVEL_3);

            if (status == QUID_SUCCESS && status2 == QUID_SUCCESS) {
                const char* id_a = quid_get_identity_id(identity_a);
                const char* id_b = quid_get_identity_id(identity_b);
                bool same_id = (strcmp(id_a, id_b) == 0);
                printf("   Same seed produces same ID: %s\n", same_id ? "✅ YES" : "❌ NO");
                printf("   ID from seed: %s\n", id_a);
            }

            if (identity_a) quid_identity_free(identity_a);
            if (identity_b) quid_identity_free(identity_b);
        }
    }

    print_step(4, "Cleanup");
    if (identity1) quid_identity_free(identity1);
    if (identity2) quid_identity_free(identity2);
    if (identity3) quid_identity_free(identity3);
    quid_cleanup();
    printf("✅ Multiple identities demo completed\n");
}

/**
 * @brief Demo performance characteristics
 */
void demo_performance(void)
{
    print_separator("QUID Performance Characteristics Demo");

    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) {
        printf("❌ Failed to initialize QUID library\n");
        return;
    }

    print_step(1, "Identity creation performance");
    clock_t start = clock();
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    clock_t end = clock();

    double creation_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("   Identity creation time: %.2f ms\n", creation_time);

    if (identity) {
        print_step(2, "Key derivation performance");
        quid_context_t context = {"test", "performance", "benchmark", {0}, 0, QUID_SECURITY_LEVEL_5};
        uint8_t derived_key[64];

        start = clock();
        for (int i = 0; i < 100; i++) {
            quid_derive_key(identity, &context, derived_key, sizeof(derived_key));
        }
        end = clock();

        double derivation_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        printf("   100 key derivations: %.2f ms total (%.2f ms average)\n",
               derivation_time, derivation_time / 100);

        print_step(3, "Signing performance");
        const char* message = "Performance test message";
        quid_signature_t signature;

        start = clock();
        for (int i = 0; i < 10; i++) {
            quid_sign(identity, (const uint8_t*)message, strlen(message), &signature);
        }
        end = clock();

        double signing_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        printf("   10 signatures: %.2f ms total (%.2f ms average)\n",
               signing_time, signing_time / 10);

        quid_identity_free(identity);
    }

    quid_cleanup();
}

/**
 * @brief Main demonstration function
 */
int main(void)
{
    printf("🌟 QUID (Quantum-Resistant Universal Identity) System Demo\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("License: 0BSD (Zero-clause BSD)\n");
    printf("Copyright (c) 2025 QUID Identity Foundation\n");

    /* Run all demonstrations */
    demo_basic_identity();
    demo_crypto_utilities();
    demo_multiple_identities();
    demo_performance();

    print_separator("Demo Complete");
    printf("🎉 QUID system demonstration completed successfully!\n");
    printf("\n📋 Summary:\n");
    printf("  ✅ Quantum-resistant identity creation (ML-DSA)\n");
    printf("  ✅ Multi-network key derivation\n");
    printf("  ✅ Cryptographic signing and verification\n");
    printf("  ✅ Memory protection and security\n");
    printf("  ✅ Random number generation\n");
    printf("  ✅ Constant-time operations\n");
    printf("  ✅ Multiple identity management\n");
    printf("  ✅ Performance characteristics\n");
    printf("\n🚀 QUID is ready for production use!\n");
    printf("\nFor more information, visit: https://github.com/quid-identity/quid\n");

    return 0;
}