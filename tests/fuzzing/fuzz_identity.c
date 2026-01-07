/**
 * @file fuzz_identity.c
 * @brief Fuzzing Harness for QUID Identity Operations
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 *
 * This is a basic fuzzing harness that can be used with AFL++ or libFuzzer.
 * It tests the core identity operations with randomized inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "quid/quid.h"

/* AFL++ persistent mode */
#ifdef __AFL_COMPILER
#include < AFL/afl-fuzz.h>
#endif

/* libFuzzer interface */
#ifdef __cplusplus
extern "C"
#endif

/* Maximum input size for fuzzing */
#define MAX_INPUT_SIZE 4096

/**
 * @brief Fuzz test for identity creation with various parameters
 */
static int fuzz_identity_create(const uint8_t* data, size_t size)
{
    /* Use input data to determine security level */
    quid_security_level_t level = QUID_SECURITY_LEVEL_5;
    if (size >= 1) {
        switch (data[0] % 3) {
            case 0: level = QUID_SECURITY_LEVEL_1; break;
            case 1: level = QUID_SECURITY_LEVEL_3; break;
            case 2: level = QUID_SECURITY_LEVEL_5; break;
        }
    }

    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, level);

    if (status == QUID_SUCCESS && identity != NULL) {
        /* Try to get public key */
        uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
        quid_get_public_key(identity, public_key);

        /* Try to sign a message derived from fuzz input */
        if (size > 1) {
            size_t msg_len = (size_t)data[1] % 256;
            if (msg_len > size - 2) msg_len = size - 2;

            if (msg_len > 0) {
                quid_signature_t signature;
                quid_sign(identity, data + 2, msg_len, &signature);

                /* Verify signature */
                quid_verify(public_key, data + 2, msg_len, &signature);
            }
        }

        /* Try key derivation with various contexts */
        if (size > 4) {
            quid_context_t ctx = {0};
            size_t network_len = (size_t)data[2] % 32;
            size_t app_len = (size_t)data[3] % 64;

            if (network_len > 0 && network_len < 32) {
                memcpy(ctx.network_type, data + 4, network_len);
            } else {
                strcpy(ctx.network_type, "bitcoin");
            }

            if (app_len > 0 && 4 + network_len + app_len < size) {
                memcpy(ctx.application_id, data + 4 + network_len, app_len);
            } else {
                strcpy(ctx.application_id, "test-app");
            }

            uint8_t derived_key[64];
            quid_derive_key(identity, &ctx, derived_key, sizeof(derived_key));
        }

        quid_identity_free(identity);
    }

    return 0;
}

/**
 * @brief Fuzz test for authentication operations
 */
static int fuzz_auth(const uint8_t* data, size_t size)
{
    if (size < 32) return 0;

    /* Create identity */
    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) return 0;

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    if (status != QUID_SUCCESS || identity == NULL) {
        quid_cleanup();
        return 0;
    }

    /* Create auth request from fuzz input */
    quid_auth_request_t request = {0};
    request.challenge_len = sizeof(request.challenge);
    if (size < sizeof(request.challenge)) {
        request.challenge_len = size;
    }
    memcpy(request.challenge, data, request.challenge_len);

    request.timestamp = 0;

    /* Set network type from fuzz input if available */
    if (size > sizeof(request.challenge)) {
        size_t network_len = data[sizeof(request.challenge)] % 16;
        if (network_len > 0 && network_len < sizeof(request.context.network_type)) {
            if (size > sizeof(request.challenge) + 1 + network_len) {
                memcpy(request.context.network_type, data + sizeof(request.challenge) + 1, network_len);
            }
        }
    }

    /* Create and verify auth proof */
    quid_auth_response_t response;
    status = quid_authenticate(identity, &request, &response);

    if (status == QUID_SUCCESS) {
        uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
        quid_get_public_key(identity, public_key);

        quid_verify_auth(&response, &request, NULL);
    }

    quid_identity_free(identity);
    quid_cleanup();
    return 0;
}

/**
 * @brief Fuzz test for backup operations
 */
static int fuzz_backup(const uint8_t* data, size_t size)
{
    if (size < 16) return 0;

    quid_status_t status = quid_init();
    if (status != QUID_SUCCESS) return 0;

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_3);
    if (status != QUID_SUCCESS || identity == NULL) {
        quid_cleanup();
        return 0;
    }

    /* Derive password from fuzz input */
    char password[256];
    size_t pwd_len = size < sizeof(password) ? size : sizeof(password) - 1;
    memcpy(password, data, pwd_len);
    password[pwd_len] = '\0';

    /* Try export */
    uint8_t backup_data[8192];
    size_t backup_size = sizeof(backup_data);
    status = quid_identity_export(identity, backup_data, &backup_size, password);

    /* Try import if export succeeded */
    if (status == QUID_SUCCESS && backup_size > 0) {
        quid_identity_t* imported = NULL;
        quid_identity_import(&imported, backup_data, backup_size, password);
        if (imported != NULL) {
            quid_identity_free(imported);
        }
    }

    quid_identity_free(identity);
    quid_cleanup();
    return 0;
}

/**
 * @brief Entry point for AFL++ */
#ifdef __AFL_HAVE_MANUAL_CONTROL

int main(int argc, char** argv)
{
    __AFL_INIT();
    uint8_t buffer[MAX_INPUT_SIZE];

    while (__AFL_LOOP(10000)) {
        size_t len = fread(buffer, 1, sizeof(buffer), stdin);
        fuzz_identity_create(buffer, len);
        fuzz_auth(buffer, len);
        fuzz_backup(buffer, len);
    }

    return 0;
}

/**
 * @brief Entry point for libFuzzer
 */
#elif defined(__cplusplus)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > MAX_INPUT_SIZE) size = MAX_INPUT_SIZE;

    fuzz_identity_create(data, size);
    fuzz_auth(data, size);
    fuzz_backup(data, size);

    return 0;
}

/**
 * @brief Standalone test mode (for quick verification)
 */
#else

int main(int argc, char** argv)
{
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║        QUID Fuzzing Harness (Standalone Mode)              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    printf("This is a basic fuzzing harness for QUID.\n\n");
    printf("Usage:\n");
    printf("  With AFL++:  afl-gcc -o fuzz_identity fuzz_identity.c -lquid\n");
    printf("               afl-fuzz -i in -o out -- ./fuzz_identity\n\n");
    printf("  With libFuzzer: clang -fsanitize=fuzzer,address -o fuzz_identity \\\n");
    printf("                   fuzz_identity.c -lquid\n\n");

    printf("Running quick verification test...\n");

    /* Quick test with sample data */
    uint8_t sample_data[] = {
        0x01, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
        0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        /* Fill with test data */
        'T', 'e', 's', 't', 'P', 'a', 's', 's', 'w', 'o', 'r', 'd'
    };

    fuzz_identity_create(sample_data, sizeof(sample_data));
    fuzz_auth(sample_data, sizeof(sample_data));
    fuzz_backup(sample_data, sizeof(sample_data));

    printf("✅ Fuzzing harness verification complete (no crashes)\n\n");

    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Fuzzing Recommendations:                                   ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  1. Run for at least 1 hour per fuzzing target             ║\n");
    printf("║  2. Use with ASAN/MSAN for memory error detection          ║\n");
    printf("║  3. Provide good corpus seeds in the input directory       ║\n");
    printf("║  4. Test with dictionary for structured inputs             ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    return 0;
}

#endif
