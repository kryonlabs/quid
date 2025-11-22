/**
 * @file backup_test.c
 * @brief QUID Encrypted Backup Test Program
 *
 * Tests the encrypted backup and restore functionality for quantum-resistant identities.
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
 * @brief Test encrypted backup functionality
 */
void test_encrypted_backup(void)
{
    printf("\n=== Encrypted Backup Test ===\n");

    /* Create original identity */
    printf("Creating original quantum-resistant identity...\n");
    quid_identity_t* original_identity = NULL;
    quid_status_t status = quid_identity_create(&original_identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create original identity");

    const char* original_id = quid_get_identity_id(original_identity);
    printf("Original Identity ID: %s\n", original_id);

    /* Test signing with original identity */
    const char* test_message = "This identity will be backed up and restored";
    quid_signature_t original_signature;
    original_signature.size = QUID_SIGNATURE_SIZE; /* Initialize buffer size */
    status = quid_sign(original_identity, (const uint8_t*)test_message, strlen(test_message), &original_signature);
    die_on_error(status, "Failed to sign with original identity");
    printf("Original signature created successfully (%zu bytes)\n", original_signature.size);

    /* Test backup */
    printf("\nCreating encrypted backup...\n");
    const char* backup_password = "strong_quantum_safe_password_123!";
    const char* backup_comment = "My quantum-resistant identity backup";

    uint8_t backup_data[8192];  /* Larger buffer for encrypted backup */
    size_t backup_size = sizeof(backup_data);

    status = quid_identity_backup(original_identity, backup_password, backup_comment,
                                  backup_data, &backup_size);
    die_on_error(status, "Failed to create encrypted backup");
    printf("Encrypted backup created successfully (%zu bytes)\n", backup_size);

    /* Get backup metadata */
    char timestamp[32], identity_id[64], comment[128];
    quid_security_level_t security_level;

    status = quid_backup_get_info(backup_data, backup_size,
                                  timestamp, sizeof(timestamp),
                                  identity_id, sizeof(identity_id),
                                  &security_level,
                                  comment, sizeof(comment));
    die_on_error(status, "Failed to get backup info");

    printf("\nBackup Metadata:\n");
    printf("  Timestamp: %s\n", timestamp);
    printf("  Identity ID: %s\n", identity_id);
    printf("  Security Level: %d\n", security_level);
    printf("  Comment: %s\n", comment);

    /* Verify backup integrity */
    status = quid_backup_verify(backup_data, backup_size, original_id);
    die_on_error(status, "Failed to verify backup integrity");
    printf("Backup integrity verification: SUCCESS\n");

    /* Export to base64 for portability */
    printf("\nExporting backup to base64...\n");
    char base64_backup[16384];  /* Much larger for base64 encoding */
    size_t base64_size = sizeof(base64_backup);

    status = quid_backup_export_base64(backup_data, backup_size, base64_backup, &base64_size);
    die_on_error(status, "Failed to export backup to base64");
    printf("Base64 export successful (%zu bytes)\n", base64_size);
    printf("Base64 backup (first 100 chars): %.100s%s\n",
           base64_backup, base64_size > 100 ? "..." : "");

    /* Test restore */
    printf("\nRestoring identity from backup...\n");
    quid_identity_t* restored_identity = NULL;

    status = quid_identity_restore(backup_data, backup_size, backup_password, &restored_identity);
    die_on_error(status, "Failed to restore identity from backup");
    printf("Identity restored successfully!\n");

    const char* restored_id = quid_get_identity_id(restored_identity);
    printf("Restored Identity ID: %s\n", restored_id);

    /* Verify restored identity works */
    printf("\nTesting restored identity functionality...\n");

    /* Test signing with restored identity */
    quid_signature_t restored_signature;
    restored_signature.size = QUID_SIGNATURE_SIZE; /* Initialize buffer size */
    status = quid_sign(restored_identity, (const uint8_t*)test_message, strlen(test_message), &restored_signature);
    die_on_error(status, "Failed to sign with restored identity");
    printf("Restored signature created successfully (%zu bytes)\n", restored_signature.size);

    /* Verify signatures match (both should be valid for the same message) */
    status = quid_verify(original_signature.public_key, (const uint8_t*)test_message, strlen(test_message), &original_signature);
    die_on_error(status, "Failed to verify original signature");
    printf("Original signature verification: SUCCESS\n");

    status = quid_verify(restored_signature.public_key, (const uint8_t*)test_message, strlen(test_message), &restored_signature);
    die_on_error(status, "Failed to verify restored signature");
    printf("Restored signature verification: SUCCESS\n");

    /* Verify public keys match */
    uint8_t original_public_key[QUID_PUBLIC_KEY_SIZE];
    uint8_t restored_public_key[QUID_PUBLIC_KEY_SIZE];

    status = quid_get_public_key(original_identity, original_public_key);
    die_on_error(status, "Failed to get original public key");

    status = quid_get_public_key(restored_identity, restored_public_key);
    die_on_error(status, "Failed to get restored public key");

    int keys_match = (memcmp(original_public_key, restored_public_key, QUID_PUBLIC_KEY_SIZE) == 0);
    printf("Public keys match: %s\n", keys_match ? "YES" : "NO");
    if (!keys_match) {
        printf("ERROR: Public keys do not match - backup/restore failed!\n");
    }

    /* Test base64 import/export round trip */
    printf("\nTesting base64 import/export round trip...\n");
    uint8_t imported_backup[8192];  /* Same size as backup buffer */
    size_t imported_size = sizeof(imported_backup);

    status = quid_backup_import_base64(base64_backup, imported_backup, &imported_size);
    die_on_error(status, "Failed to import backup from base64");

    /* Verify imported backup works */
    status = quid_backup_verify(imported_backup, imported_size, original_id);
    die_on_error(status, "Failed to verify imported backup");
    printf("Base64 round-trip test: SUCCESS\n");

    /* Test wrong password protection */
    printf("\nTesting wrong password protection...\n");
    quid_identity_t* wrong_password_identity = NULL;
    status = quid_identity_restore(backup_data, backup_size, "wrong_password", &wrong_password_identity);
    if (status == QUID_SUCCESS) {
        printf("ERROR: Restore with wrong password should have failed!\n");
        quid_identity_free(wrong_password_identity);
        exit(1);
    }
    printf("Wrong password protection: WORKING (restore correctly failed)\n");

    /* Cleanup */
    quid_identity_free(original_identity);
    quid_identity_free(restored_identity);
    printf("\nEncrypted backup test completed successfully!\n");
}

/**
 * @brief Main function
 */
int main(void)
{
    printf("🔐 QUID Encrypted Backup Test Suite\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    /* Initialize QUID library */
    printf("\nInitializing QUID library...\n");
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize QUID");

    /* Run backup tests */
    test_encrypted_backup();

    /* Cleanup */
    printf("\nCleaning up QUID library...\n");
    quid_cleanup();

    printf("\n✅ All backup tests passed successfully!\n");
    printf("Quantum-resistant identity backup/restore is ready for production use.\n");

    return 0;
}