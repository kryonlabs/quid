/**
 * @file test_backup.c
 * @brief QUID Identity Backup and Restore Tests
 *
 * Comprehensive test suite for identity backup and restore functionality
 * including encryption, decryption, metadata extraction, and base64 encoding.
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
    TEST_ASSERT((status) == QUID_SUCCESS, message)

/**
 * @brief Test basic backup and restore functionality
 */
static void test_basic_backup_restore(void)
{
    printf("\n=== Basic Backup/Restore Tests ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    /* Create original identity */
    quid_identity_t* original = NULL;
    status = quid_identity_create(&original, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create original identity");

    if (original) {
        const char* original_id = quid_get_identity_id(original);
        TEST_ASSERT(original_id != NULL, "Get original identity ID");
        printf("   Original ID: %s\n", original_id);

        /* Test backup creation */
        const char* password = "test_backup_password_123";
        const char* comment = "Test backup created by unit test";

        uint8_t backup_data[QUID_BACKUP_MAX_SIZE];
        size_t backup_size = sizeof(backup_data);

        status = quid_identity_backup(original, password, comment,
                                     backup_data, &backup_size);
        TEST_ASSERT_SUCCESS(status, "Create identity backup");
        TEST_ASSERT(backup_size > 128, "Backup has reasonable size (greater than header)");
        printf("   Backup size: %zu bytes\n", backup_size);

        /* Test backup verification */
        status = quid_backup_verify(backup_data, backup_size, original_id);
        TEST_ASSERT_SUCCESS(status, "Verify backup integrity");

        /* Test backup metadata extraction */
        char timestamp[64], extracted_id[QUID_ID_ID_SIZE], extracted_comment[256];
        quid_security_level_t extracted_level;

        status = quid_backup_get_info(backup_data, backup_size,
                                     timestamp, sizeof(timestamp),
                                     extracted_id, sizeof(extracted_id),
                                     &extracted_level,
                                     extracted_comment, sizeof(extracted_comment));
        TEST_ASSERT_SUCCESS(status, "Extract backup metadata");
        TEST_ASSERT(strlen(timestamp) > 0, "Timestamp extracted");
        TEST_ASSERT(strcmp(extracted_id, original_id) == 0, "Identity ID matches");
        TEST_ASSERT(extracted_level == QUID_SECURITY_LEVEL_5, "Security level matches");
        TEST_ASSERT(strcmp(extracted_comment, comment) == 0, "Comment matches");
        printf("   Backup timestamp: %s\n", timestamp);
        printf("   Extracted ID: %s\n", extracted_id);
        printf("   Security level: %d\n", extracted_level);

        /* Test identity restoration */
        quid_identity_t* restored = NULL;
        status = quid_identity_restore(backup_data, backup_size,
                                      password, &restored);
        TEST_ASSERT_SUCCESS(status, "Restore identity from backup");
        TEST_ASSERT(restored != NULL, "Restored identity is not NULL");

        if (restored) {
            const char* restored_id = quid_get_identity_id(restored);
            TEST_ASSERT(restored_id != NULL, "Get restored identity ID");
            TEST_ASSERT(strcmp(original_id, restored_id) == 0, "Restored ID matches original");
            printf("   Restored ID: %s\n", restored_id);

            /* Test derived keys match */
            quid_context_t test_ctx = {"test", "backup", "comparison", {0}, 0, QUID_SECURITY_LEVEL_5};
            uint8_t original_key[64], restored_key[64];

            status = quid_derive_key(original, &test_ctx, original_key, sizeof(original_key));
            TEST_ASSERT_SUCCESS(status, "Derive key from original identity");

            status = quid_derive_key(restored, &test_ctx, restored_key, sizeof(restored_key));
            TEST_ASSERT_SUCCESS(status, "Derive key from restored identity");

            TEST_ASSERT(memcmp(original_key, restored_key, 64) == 0,
                       "Derived keys from original and restored identities match");

            /* Cleanup restored identity */
            quid_identity_free(restored);
        }

        /* Cleanup original identity */
        quid_identity_free(original);
    }

    /* Cleanup QUID */
    quid_cleanup();
}

/**
 * @brief Test backup with wrong password
 */
static void test_backup_wrong_password(void)
{
    printf("\n=== Backup Wrong Password Tests ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    /* Create identity and backup */
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_3);
    TEST_ASSERT_SUCCESS(status, "Create identity");

    if (identity) {
        const char* correct_password = "correct_password_123";
        const char* wrong_password = "wrong_password_456";

        /* Create backup with correct password */
        uint8_t backup_data[QUID_BACKUP_MAX_SIZE];
        size_t backup_size = sizeof(backup_data);

        status = quid_identity_backup(identity, correct_password, "Test backup",
                                     backup_data, &backup_size);
        TEST_ASSERT_SUCCESS(status, "Create backup with correct password");

        /* Try to restore with wrong password */
        quid_identity_t* restored = NULL;
        status = quid_identity_restore(backup_data, backup_size,
                                      wrong_password, &restored);
        TEST_ASSERT(status != QUID_SUCCESS, "Restore with wrong password fails");
        TEST_ASSERT(restored == NULL, "No identity restored with wrong password");

        /* Try to restore with correct password (should succeed) */
        status = quid_identity_restore(backup_data, backup_size,
                                      correct_password, &restored);
        TEST_ASSERT_SUCCESS(status, "Restore with correct password succeeds");
        TEST_ASSERT(restored != NULL, "Identity successfully restored");

        if (restored) {
            quid_identity_free(restored);
        }

        /* Cleanup */
        quid_identity_free(identity);
    }

    quid_cleanup();
}

/**
 * @brief Test backup base64 encoding and decoding
 */
static void test_backup_base64(void)
{
    printf("\n=== Backup Base64 Tests ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    /* Create identity and backup */
    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_1);
    TEST_ASSERT_SUCCESS(status, "Create identity");

    if (identity) {
        const char* password = "base64_test_password";

        /* Create binary backup */
        uint8_t binary_backup[QUID_BACKUP_MAX_SIZE];
        size_t binary_size = sizeof(binary_backup);

        status = quid_identity_backup(identity, password, "Base64 test backup",
                                     binary_backup, &binary_size);
        TEST_ASSERT_SUCCESS(status, "Create binary backup");

        /* Export to base64 */
        char base64_backup[QUID_BACKUP_BASE64_MAX_SIZE];
        size_t base64_size = sizeof(base64_backup);

        status = quid_backup_export_base64(binary_backup, binary_size,
                                         base64_backup, &base64_size);
        TEST_ASSERT_SUCCESS(status, "Export backup to base64");
        TEST_ASSERT(strlen(base64_backup) > 0, "Base64 string is not empty");
        TEST_ASSERT(base64_size > 0, "Base64 size is valid");
        printf("   Base64 backup size: %zu bytes\n", base64_size);
        printf("   Base64 backup (first 60 chars): %.60s...\n", base64_backup);

        /* Import from base64 */
        uint8_t imported_backup[QUID_BACKUP_MAX_SIZE];
        size_t imported_size = sizeof(imported_backup);

        status = quid_backup_import_base64(base64_backup,
                                         imported_backup, &imported_size);
        TEST_ASSERT_SUCCESS(status, "Import backup from base64");
        TEST_ASSERT(imported_size == binary_size, "Imported size matches original");

        /* Verify imported backup matches original */
        TEST_ASSERT(memcmp(binary_backup, imported_backup, binary_size) == 0,
                   "Imported backup data matches original");

        /* Test restoring from base64-imported backup */
        quid_identity_t* restored = NULL;
        status = quid_identity_restore(imported_backup, imported_size,
                                      password, &restored);
        TEST_ASSERT_SUCCESS(status, "Restore from base64-imported backup");
        TEST_ASSERT(restored != NULL, "Identity successfully restored");

        if (restored) {
            const char* original_id = quid_get_identity_id(identity);
            const char* restored_id = quid_get_identity_id(restored);
            TEST_ASSERT(strcmp(original_id, restored_id) == 0, "Base64 round-trip ID matches");
            printf("   Round-trip successful: %s\n", restored_id);
            quid_identity_free(restored);
        }

        /* Cleanup */
        quid_identity_free(identity);
    }

    quid_cleanup();
}

/**
 * @brief Test backup with different security levels
 */
static void test_backup_security_levels(void)
{
    printf("\n=== Backup Security Level Tests ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    /* Test all security levels */
    quid_security_level_t levels[] = {QUID_SECURITY_LEVEL_1, QUID_SECURITY_LEVEL_3, QUID_SECURITY_LEVEL_5};
    const char* level_names[] = {"Level 1 (128-bit)", "Level 3 (192-bit)", "Level 5 (256-bit)"};

    const char* password = "security_level_test_password";
    uint8_t backups[3][QUID_BACKUP_MAX_SIZE];
    size_t backup_sizes[3];

    for (int i = 0; i < 3; i++) {
        printf("   Testing %s...\n", level_names[i]);

        /* Create identity with specific security level */
        quid_identity_t* identity = NULL;
        status = quid_identity_create(&identity, levels[i]);
        TEST_ASSERT_SUCCESS(status, "Create identity with specific level");

        if (identity) {
            /* Backup the identity */
            backup_sizes[i] = sizeof(backups[i]);
            status = quid_identity_backup(identity, password, "Security level test",
                                         backups[i], &backup_sizes[i]);
            TEST_ASSERT_SUCCESS(status, "Backup identity with security level");
            printf("     Backup size: %zu bytes\n", backup_sizes[i]);

            /* Verify backup metadata */
            quid_security_level_t extracted_level;
            status = quid_backup_get_info(backups[i], backup_sizes[i],
                                         NULL, 0, NULL, 0, &extracted_level, NULL, 0);
            TEST_ASSERT_SUCCESS(status, "Extract security level from backup");
            TEST_ASSERT(extracted_level == levels[i], "Security level matches in backup");

            /* Restore and verify */
            quid_identity_t* restored = NULL;
            status = quid_identity_restore(backups[i], backup_sizes[i],
                                          password, &restored);
            TEST_ASSERT_SUCCESS(status, "Restore identity with security level");
            TEST_ASSERT(restored != NULL, "Identity restored successfully");

            if (restored) {
                const char* original_id = quid_get_identity_id(identity);
                const char* restored_id = quid_get_identity_id(restored);
                TEST_ASSERT(strcmp(original_id, restored_id) == 0, "ID matches after restore");

                quid_identity_free(restored);
            }

            quid_identity_free(identity);
        }
    }

    /* Verify all backups have different sizes (security levels should affect key sizes) */
    bool different_sizes = (backup_sizes[0] != backup_sizes[1]) &&
                         (backup_sizes[1] != backup_sizes[2]) &&
                         (backup_sizes[0] != backup_sizes[2]);
    TEST_ASSERT(different_sizes, "Different security levels produce different backup sizes");

    quid_cleanup();
}

/**
 * @brief Test backup error handling
 */
static void test_backup_error_handling(void)
{
    printf("\n=== Backup Error Handling Tests ===\n");

    /* Initialize QUID */
    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_3);
    TEST_ASSERT_SUCCESS(status, "Create identity");

    if (identity) {
        const char* password = "error_test_password";

        /* Test backup with NULL parameters */
        uint8_t backup_data[QUID_BACKUP_MAX_SIZE];
        size_t backup_size = sizeof(backup_data);

        status = quid_identity_backup(NULL, password, "test", backup_data, &backup_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Backup with NULL identity fails");

        status = quid_identity_backup(identity, NULL, "test", backup_data, &backup_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Backup with NULL password fails");

        status = quid_identity_backup(identity, password, "test", NULL, &backup_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Backup with NULL buffer fails");

        /* Test backup with insufficient buffer */
        backup_size = 10;  /* Too small */
        status = quid_identity_backup(identity, password, "test", backup_data, &backup_size);
        TEST_ASSERT(status == QUID_ERROR_BUFFER_TOO_SMALL, "Backup detects insufficient buffer");
        TEST_ASSERT(backup_size > 10, "Returns required buffer size");

        /* Create a valid backup for restore error tests */
        backup_size = sizeof(backup_data);
        status = quid_identity_backup(identity, password, "test", backup_data, &backup_size);
        TEST_ASSERT_SUCCESS(status, "Create valid backup for error tests");

        /* Test restore with NULL parameters */
        quid_identity_t* restored = NULL;
        status = quid_identity_restore(NULL, backup_size, password, &restored);
        TEST_ASSERT(status != QUID_SUCCESS, "Restore with NULL data fails");

        status = quid_identity_restore(backup_data, backup_size, NULL, &restored);
        TEST_ASSERT(status != QUID_SUCCESS, "Restore with NULL password fails");

        status = quid_identity_restore(backup_data, backup_size, password, NULL);
        TEST_ASSERT(status != QUID_SUCCESS, "Restore with NULL output fails");

        /* Test restore with corrupted data */
        uint8_t corrupted_data[QUID_BACKUP_MAX_SIZE];
        memcpy(corrupted_data, backup_data, backup_size);
        corrupted_data[50] ^= 0xFF;  /* Corrupt some bytes */

        status = quid_identity_restore(corrupted_data, backup_size, password, &restored);
        TEST_ASSERT(status != QUID_SUCCESS, "Restore with corrupted data fails");

        /* Test backup verification with invalid data */
        uint8_t invalid_data[] = {0x00, 0x01, 0x02, 0x03};  /* Too small and wrong format */
        status = quid_backup_verify(invalid_data, sizeof(invalid_data), NULL);
        TEST_ASSERT(status != QUID_SUCCESS, "Verify invalid backup fails");

        /* Test base64 error handling */
        char base64_output[100];
        size_t base64_size = sizeof(base64_output);
        status = quid_backup_export_base64(NULL, 0, base64_output, &base64_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Export base64 with NULL data fails");

        status = quid_backup_export_base64(backup_data, backup_size, NULL, &base64_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Export base64 with NULL output fails");

        char invalid_base64[] = "!!!invalid_base64!!!";
        uint8_t imported_data[QUID_BACKUP_MAX_SIZE];
        size_t imported_size = sizeof(imported_data);
        status = quid_backup_import_base64(invalid_base64, imported_data, &imported_size);
        TEST_ASSERT(status != QUID_SUCCESS, "Import invalid base64 fails");

        /* Cleanup */
        quid_identity_free(identity);
    }

    quid_cleanup();
}

/**
 * @brief Main test runner
 */
int main(void)
{
    printf("🧪 QUID Backup and Restore Tests\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));

    /* Run all tests */
    test_basic_backup_restore();
    test_backup_wrong_password();
    test_backup_base64();
    test_backup_security_levels();
    test_backup_error_handling();

    /* Print results */
    printf("\n📊 Backup Test Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    if (tests_run > 0) {
        printf("Success rate: %.1f%%\n", (float)tests_passed / tests_run * 100);
    } else {
        printf("Success rate: N/A (no tests run)\n");
    }

    if (tests_passed == tests_run) {
        printf("\n✅ All backup tests passed!\n");
        printf("🚀 QUID backup/restore system is ready for production use!\n");
        return 0;
    } else {
        printf("\n❌ Some backup tests failed!\n");
        return 1;
    }
}
