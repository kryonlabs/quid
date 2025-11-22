/**
 * @file backup_crypto_test.c
 * @brief QUID Backup Cryptography Test
 *
 * Tests the cryptographic components of the backup system (encryption,
 * password-based key derivation, base64 encoding) without requiring
 * private key access.
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
 * @brief Test backup cryptography components
 */
void test_backup_cryptography(void)
{
    printf("\n=== Backup Cryptography Test ===\n");

    /* Create test data to encrypt */
    uint8_t test_data[256];
    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)(i & 0xFF);
    }
    printf("Created %zu bytes of test data\n", sizeof(test_data));

    /* Test password-based key derivation */
    printf("\nTesting password-based key derivation...\n");
    const char* password = "test_quantum_safe_password";
    uint8_t salt[32];
    uint8_t derived_key[32];

    /* Generate random salt */
    quid_status_t status = quid_random_bytes(salt, sizeof(salt));
    die_on_error(status, "Failed to generate salt");

    printf("Generated salt (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", salt[i]);
    }
    printf("\n");

    /* Derive key using PBKDF */
    if (!quid_crypto_pbkdf(password, strlen(password),
                           salt, 1000, 64, 1, derived_key, sizeof(derived_key))) {
        printf("ERROR: PBKDF failed\n");
        exit(1);
    }

    printf("Derived key (32 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", derived_key[i]);
    }
    printf("...\n");

    /* Test AEAD encryption */
    printf("\nTesting AES-256-GCM encryption...\n");
    uint8_t iv[16];
    uint8_t tag[16];
    uint8_t ciphertext[sizeof(test_data) + 16];
    size_t ciphertext_size;

    /* Generate random IV */
    status = quid_random_bytes(iv, sizeof(iv));
    die_on_error(status, "Failed to generate IV");

    printf("Generated IV (16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    /* Encrypt test data */
    if (!quid_crypto_aead_encrypt(derived_key, iv,
                                  test_data, sizeof(test_data),
                                  NULL, 0,  /* No additional data */
                                  ciphertext, &ciphertext_size, tag)) {
        printf("ERROR: AEAD encryption failed\n");
        exit(1);
    }

    printf("Encryption successful: %zu bytes ciphertext\n", ciphertext_size);
    printf("Authentication tag (16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    /* Test AEAD decryption */
    printf("\nTesting AES-256-GCM decryption...\n");
    uint8_t decrypted_data[sizeof(test_data)];
    size_t decrypted_size;

    if (!quid_crypto_aead_decrypt(derived_key, iv,
                                  ciphertext, ciphertext_size,
                                  NULL, 0,  /* No additional data */
                                  tag, decrypted_data, &decrypted_size)) {
        printf("ERROR: AEAD decryption failed\n");
        exit(1);
    }

    printf("Decryption successful: %zu bytes\n", decrypted_size);

    /* Verify data integrity */
    if (decrypted_size != sizeof(test_data) ||
        memcmp(decrypted_data, test_data, sizeof(test_data)) != 0) {
        printf("ERROR: Decrypted data doesn't match original!\n");
        exit(1);
    }
    printf("Data integrity verification: SUCCESS\n");

    /* Test with wrong key (should fail) */
    printf("\nTesting wrong key protection...\n");
    uint8_t wrong_key[32];
    memset(wrong_key, 0xAA, sizeof(wrong_key));

    uint8_t bad_decrypted[sizeof(test_data)];
    size_t bad_decrypted_size;

    if (quid_crypto_aead_decrypt(wrong_key, iv,
                                ciphertext, ciphertext_size,
                                NULL, 0, tag, bad_decrypted, &bad_decrypted_size)) {
        printf("ERROR: Decryption with wrong key should have failed!\n");
        exit(1);
    }
    printf("Wrong key protection: WORKING (decryption correctly failed)\n");

    /* Test base64 encoding/decoding */
    printf("\nTesting base64 encoding/decoding...\n");

    /* Create test backup-like structure */
    uint8_t backup_data[512];
    size_t backup_pos = 0;

    /* Add header */
    strcpy((char*)backup_data + backup_pos, "QUID");
    backup_pos += 4;

    /* Add salt */
    memcpy(backup_data + backup_pos, salt, sizeof(salt));
    backup_pos += sizeof(salt);

    /* Add IV */
    memcpy(backup_data + backup_pos, iv, sizeof(iv));
    backup_pos += sizeof(iv);

    /* Add ciphertext and tag */
    memcpy(backup_data + backup_pos, ciphertext, ciphertext_size);
    backup_pos += ciphertext_size;
    memcpy(backup_data + backup_pos, tag, sizeof(tag));
    backup_pos += sizeof(tag);

    printf("Created test backup structure (%zu bytes)\n", backup_pos);

    /* Test base64 encoding */
    char base64_output[1024];
    size_t base64_size = sizeof(base64_output);

    status = quid_backup_export_base64(backup_data, backup_pos, base64_output, &base64_size);
    die_on_error(status, "Failed to encode to base64");
    printf("Base64 encoding successful (%zu bytes)\n", base64_size);
    printf("Base64 output (first 100 chars): %.100s%s\n", base64_output, base64_size > 100 ? "..." : "");

    /* Test base64 decoding */
    uint8_t decoded_backup[512];
    size_t decoded_size = sizeof(decoded_backup);

    status = quid_backup_import_base64(base64_output, decoded_backup, &decoded_size);
    die_on_error(status, "Failed to decode from base64");
    printf("Base64 decoding successful (%zu bytes)\n", decoded_size);

    /* Verify round-trip integrity */
    if (decoded_size != backup_pos || memcmp(decoded_backup, backup_data, backup_pos) != 0) {
        printf("ERROR: Base64 round-trip failed!\n");
        exit(1);
    }
    printf("Base64 round-trip verification: SUCCESS\n");

    /* Test backup verification */
    printf("\nTesting backup format verification...\n");

    /* Test valid backup */
    status = quid_backup_verify(backup_data, backup_pos, NULL);
    die_on_error(status, "Failed to verify valid backup");
    printf("Valid backup verification: SUCCESS\n");

    /* Test invalid backup (wrong magic) */
    uint8_t invalid_backup[backup_pos];
    memcpy(invalid_backup, backup_data, backup_pos);
    invalid_backup[0] = 'X';  /* Corrupt magic number */

    status = quid_backup_verify(invalid_backup, backup_pos, NULL);
    if (status != QUID_ERROR_INVALID_FORMAT) {
        printf("ERROR: Invalid backup verification should have failed!\n");
        exit(1);
    }
    printf("Invalid backup detection: WORKING (verification correctly failed)\n");

    printf("\n✅ All backup cryptography tests passed!\n");
    printf("✅ Quantum-resistant backup infrastructure is ready\n");
}

/**
 * @brief Main function
 */
int main(void)
{
    printf("🔐 QUID Backup Cryptography Test Suite\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    /* Initialize QUID library */
    printf("\nInitializing QUID library...\n");
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize QUID");

    /* Run cryptography tests */
    test_backup_cryptography();

    /* Cleanup */
    printf("\nCleaning up QUID library...\n");
    quid_cleanup();

    printf("\n🎉 Backup cryptography validation complete!\n");
    printf("The quantum-resistant backup infrastructure is working correctly.\n");

    return 0;
}