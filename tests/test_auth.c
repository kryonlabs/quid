/**
 * @file test_auth.c
 * @brief Authentication proof and verification tests
 *
 * Verifies challenge/response authentication succeeds with valid data
 * and fails when proofs are tampered.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "quid/quid.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        tests_run++; \
        if (cond) { \
            tests_passed++; \
            printf("✅ %s\n", msg); \
        } else { \
            printf("❌ %s\n", msg); \
        } \
    } while (0)

#define TEST_ASSERT_SUCCESS(status, msg) \
    TEST_ASSERT((status) == QUID_SUCCESS, msg)

static void test_auth_success_and_tamper(void)
{
    printf("\n=== Authentication Proof Tests ===\n");

    quid_status_t status = quid_init();
    TEST_ASSERT_SUCCESS(status, "Initialize QUID");

    quid_identity_t* identity = NULL;
    status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    TEST_ASSERT_SUCCESS(status, "Create identity");

    quid_auth_request_t request = {0};
    strcpy(request.context.network_type, "testnet");
    strcpy(request.context.application_id, "auth-demo");
    strcpy(request.context.purpose, "login");
    request.context.security = QUID_SECURITY_LEVEL_5;
    request.timestamp = (uint64_t)time(NULL) * 1000;

    /* Caller-supplied challenge/nonce */
    quid_random_bytes(request.challenge, QUID_CHALLENGE_SIZE);
    request.challenge_len = QUID_CHALLENGE_SIZE;
    uint8_t nonce_bytes[QUID_NONCE_SIZE - 1];
    quid_random_bytes(nonce_bytes, sizeof(nonce_bytes));
    memcpy(request.nonce, nonce_bytes, sizeof(nonce_bytes));
    request.nonce[QUID_NONCE_SIZE - 1] = '\0';

    quid_auth_response_t response = {0};
    status = quid_authenticate(identity, &request, &response);
    TEST_ASSERT_SUCCESS(status, "Authenticate and generate response");

    status = quid_verify_auth(&response, &request, quid_get_identity_id(identity));
    TEST_ASSERT_SUCCESS(status, "Verify authentication response");

    /* Tamper with proof and expect failure */
    quid_auth_response_t tampered = response;
    tampered.proof[0] ^= 0xFF;
    status = quid_verify_auth(&tampered, &request, quid_get_identity_id(identity));
    TEST_ASSERT(status != QUID_SUCCESS, "Tampered proof fails verification");

    if (identity) {
        quid_identity_free(identity);
    }
    quid_cleanup();
}

int main(void)
{
    test_auth_success_and_tamper();
    printf("\nAuth tests passed %d/%d\n", tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}
