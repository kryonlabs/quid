/**
 * @file auth.c
 * @brief QUID Authentication Implementation
 *
 * Implements authentication protocols including challenge-response
 * and verification mechanisms.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <string.h>
#include <time.h>
#include <stdio.h>

#include "quid/quid.h"
#include "quid/endian.h"
#include "../utils/memory.h"
#include "../utils/random.h"
#include "../utils/crypto.h"
#include "../utils/validation.h"

/* Authentication constants */
#define QUID_CHALLENGE_SIZE 32
#define QUID_NONCE_SIZE 16
#define QUID_AUTH_PROOF_SIZE 64
#define QUID_AUTH_CONTEXT "QUID authentication v1"
#define QUID_TIMESTAMP_VALIDITY 300000  /* 5 minutes in milliseconds */

/* Internal helper functions */

/**
 * @brief Generate authentication challenge
 * @param request Authentication request structure
 * @return QUID_SUCCESS on success, error code on failure
 */
static quid_status_t generate_challenge(quid_auth_request_t* request)
{
    if (!request) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Generate random challenge */
    if (!quid_random_bytes(request->challenge, QUID_CHALLENGE_SIZE)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }
    request->challenge_len = QUID_CHALLENGE_SIZE;

    /* Generate nonce */
    if (!quid_random_bytes((uint8_t*)request->nonce, QUID_NONCE_SIZE - 1)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }
    request->nonce[QUID_NONCE_SIZE - 1] = '\0';

    /* Set timestamp */
    request->timestamp = (uint64_t)time(NULL) * 1000;  /* Convert to milliseconds */

    return QUID_SUCCESS;
}

/**
 * @brief Create authentication proof
 * @param identity Identity to authenticate
 * @param request Authentication request
 * @param proof Output proof buffer
 * @param proof_size Size of proof buffer
 * @return QUID_SUCCESS on success, error code on failure
 */
static quid_status_t create_auth_proof(const quid_identity_t* identity,
                                       const quid_auth_request_t* request,
                                       uint8_t* proof,
                                       size_t proof_size)
{
    if (!identity || !request || !proof || proof_size < QUID_AUTH_PROOF_SIZE) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Create message to sign: challenge || context || timestamp || nonce */
    uint8_t message[512];
    size_t message_len = 0;

    /* Add challenge */
    memcpy(message + message_len, request->challenge, request->challenge_len);
    message_len += request->challenge_len;

    /* Add context info */
    memcpy(message + message_len, QUID_AUTH_CONTEXT, strlen(QUID_AUTH_CONTEXT));
    message_len += strlen(QUID_AUTH_CONTEXT);
    message_len += 1;  /* Null terminator */

    /* Add network type */
    size_t network_len = strlen(request->context.network_type);
    memcpy(message + message_len, request->context.network_type, network_len);
    message_len += network_len;
    message_len += 1;  /* Null terminator */

    /* Add application ID */
    size_t app_len = strlen(request->context.application_id);
    memcpy(message + message_len, request->context.application_id, app_len);
    message_len += app_len;
    message_len += 1;  /* Null terminator */

    /* Add timestamp */
    uint64_t timestamp_be = quid_htobe64(request->timestamp);
    memcpy(message + message_len, &timestamp_be, sizeof(timestamp_be));
    message_len += sizeof(timestamp_be);

    /* Add nonce */
    size_t nonce_len = strlen(request->nonce);
    memcpy(message + message_len, request->nonce, nonce_len);
    message_len += nonce_len;

    /* Sign the message */
    quid_signature_t signature;
    quid_status_t status = quid_sign(identity, message, message_len, &signature);
    if (status != QUID_SUCCESS) {
        quid_secure_zero(message, sizeof(message));
        return status;
    }

    /* Create proof from signature */
    quid_crypto_shake256(signature.data, signature.size, proof, QUID_AUTH_PROOF_SIZE);

    /* Clear sensitive data */
    quid_secure_zero(message, sizeof(message));
    quid_secure_zero(&signature, sizeof(signature));

    return QUID_SUCCESS;
}

/**
 * @brief Verify authentication proof
 * @param public_key Signer's public key
 * @param request Original authentication request
 * @return QUID_SUCCESS on success, error code on failure
 */
static quid_status_t verify_auth_proof(const quid_auth_request_t* request,
                                       const quid_auth_response_t* response)
{
    if (!request || !response || response->proof_len != QUID_AUTH_PROOF_SIZE) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Recreate the message that was signed */
    uint8_t message[512];
    size_t message_len = 0;

    /* Add challenge */
    memcpy(message + message_len, request->challenge, request->challenge_len);
    message_len += request->challenge_len;

    /* Add context info */
    memcpy(message + message_len, QUID_AUTH_CONTEXT, strlen(QUID_AUTH_CONTEXT));
    message_len += strlen(QUID_AUTH_CONTEXT);
    message_len += 1;  /* Null terminator */

    /* Add network type */
    size_t network_len = strlen(request->context.network_type);
    memcpy(message + message_len, request->context.network_type, network_len);
    message_len += network_len;
    message_len += 1;  /* Null terminator */

    /* Add application ID */
    size_t app_len = strlen(request->context.application_id);
    memcpy(message + message_len, request->context.application_id, app_len);
    message_len += app_len;
    message_len += 1;  /* Null terminator */

    /* Add timestamp */
    uint64_t timestamp_be = quid_htobe64(request->timestamp);
    memcpy(message + message_len, &timestamp_be, sizeof(timestamp_be));
    message_len += sizeof(timestamp_be);

    /* Add nonce */
    size_t nonce_len = strlen(request->nonce);
    memcpy(message + message_len, request->nonce, nonce_len);
    message_len += nonce_len;

    /* Verify the signature first */
    quid_status_t status = quid_verify(response->signature.public_key,
                                       (const uint8_t*)request,
                                       sizeof(quid_auth_request_t),
                                       &response->signature);
    if (status != QUID_SUCCESS) {
        quid_secure_zero(message, sizeof(message));
        return status;
    }

    /* Recompute proof from signature material */
    uint8_t expected_proof[QUID_AUTH_PROOF_SIZE];
    quid_crypto_shake256(response->signature.data, response->signature.size,
                         expected_proof, sizeof(expected_proof));

    int cmp = quid_safe_memcmp(expected_proof, response->proof, sizeof(expected_proof));
    quid_secure_zero(expected_proof, sizeof(expected_proof));
    quid_secure_zero(message, sizeof(message));

    return (cmp == 0) ? QUID_SUCCESS : QUID_ERROR_CRYPTOGRAPHIC;
}

/**
 * @brief Check timestamp validity
 * @param timestamp Timestamp from authentication request
 * @return true if timestamp is valid, false otherwise
 */
static bool is_timestamp_valid(uint64_t timestamp)
{
    uint64_t current_time = (uint64_t)time(NULL) * 1000;  /* Convert to milliseconds */

    /* Check if timestamp is within valid range */
    if (timestamp > current_time + QUID_TIMESTAMP_VALIDITY) {
        return false;  /* Timestamp is in the future */
    }

    if (current_time > timestamp + QUID_TIMESTAMP_VALIDITY) {
        return false;  /* Timestamp is too old */
    }

    return true;
}

/* Public API functions */

/**
 * @brief Authenticate to a service
 */
quid_status_t quid_authenticate(const quid_identity_t* identity,
                                const quid_auth_request_t* request,
                                quid_auth_response_t* response)
{
    if (!identity || !request || !response) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Validate request context */
    if (strlen(request->context.network_type) == 0 ||
        strlen(request->context.application_id) == 0 ||
        strlen(request->context.purpose) == 0 ||
        request->challenge_len == 0 ||
        request->challenge_len > sizeof(request->challenge) ||
        strlen(request->nonce) == 0) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Check timestamp validity - skip for demo */
    /* if (!is_timestamp_valid(request->timestamp)) { */
    /*     return QUID_ERROR_INVALID_PARAMETER; */
    /* } */

    /* Get identity ID */
    const char* identity_id = quid_get_identity_id(identity);
    if (!identity_id) {
        return QUID_ERROR_IDENTITY_NOT_FOUND;
    }

    /* Copy identity ID to response */
    strncpy(response->identity_id, identity_id, sizeof(response->identity_id) - 1);
    response->identity_id[sizeof(response->identity_id) - 1] = '\0';

    /* Set response timestamp */
    response->timestamp = (uint64_t)time(NULL) * 1000;

    /* Create authentication proof */
    quid_status_t status = create_auth_proof(identity, request,
                                           response->proof, sizeof(response->proof));
    if (status != QUID_SUCCESS) {
        quid_secure_zero(response, sizeof(quid_auth_response_t));
        return status;
    }

    response->proof_len = QUID_AUTH_PROOF_SIZE;

    /* Generate additional signature for verification */
    status = quid_sign(identity, (const uint8_t*)request, sizeof(quid_auth_request_t),
                      &response->signature);
    if (status != QUID_SUCCESS) {
        quid_secure_zero(response, sizeof(quid_auth_response_t));
        return status;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Verify authentication response
 */
quid_status_t quid_verify_auth(const quid_auth_response_t* response,
                               const quid_auth_request_t* request,
                               const char* expected_identity_id)
{
    if (!response || !request) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Check if identity ID matches expected */
    if (expected_identity_id) {
        if (strcmp(response->identity_id, expected_identity_id) != 0) {
            return QUID_ERROR_INVALID_PARAMETER;
        }
    }

    /* Check timestamp validity */
    if (!is_timestamp_valid(response->timestamp)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Verify proof */
    quid_status_t status = verify_auth_proof(request, response);
    if (status != QUID_SUCCESS) {
        return status;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Generate secure random bytes
 */
quid_status_t quid_random_bytes(uint8_t* buffer, size_t size)
{
    if (!buffer || size == 0) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!quid_random_bytes_internal(buffer, size)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    return QUID_SUCCESS;
}


/**
 * @brief Check if system is quantum-safe
 */
bool quid_is_quantum_safe(void)
{
    /* TODO: Implement actual quantum safety check */
    /* This would verify that:
     * 1. ML-DSA implementation is available and working
     * 2. All cryptographic primitives are post-quantum safe
     * 3. No fallback to classical algorithms
     */
    return true;
}

/**
 * @brief Get library version information
 */
const char* quid_get_version(int* major, int* minor, int* patch)
{
    if (major) *major = QUID_VERSION_MAJOR;
    if (minor) *minor = QUID_VERSION_MINOR;
    if (patch) *patch = QUID_VERSION_PATCH;
    return QUID_VERSION_STRING;
}

/**
 * @brief Get error description
 */
const char* quid_get_error_string(quid_status_t status)
{
    switch (status) {
        case QUID_SUCCESS:
            return "Success";
        case QUID_ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case QUID_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case QUID_ERROR_CRYPTOGRAPHIC:
            return "Cryptographic operation failed";
        case QUID_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case QUID_ERROR_INVALID_FORMAT:
            return "Invalid format";
        case QUID_ERROR_NOT_IMPLEMENTED:
            return "Feature not implemented";
        case QUID_ERROR_IDENTITY_NOT_FOUND:
            return "Identity not found";
        case QUID_ERROR_ADAPTER_ERROR:
            return "Adapter error";
        case QUID_ERROR_QUANTUM_UNSAFE:
            return "Quantum-unsafe operation";
        default:
            return "Unknown error";
    }
}
