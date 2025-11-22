/**
 * @file validation.c
 * @brief QUID Input Validation Functions
 *
 * Provides comprehensive input validation for all QUID functions
 * to prevent security vulnerabilities and ensure robust operation.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "quid/quid.h"

/**
 * @brief Validate security level parameter
 */
bool quid_validate_security_level(quid_security_level_t security_level)
{
    return (security_level == QUID_SECURITY_LEVEL_1 ||
            security_level == QUID_SECURITY_LEVEL_3 ||
            security_level == QUID_SECURITY_LEVEL_5);
}

/**
 * @brief Validate buffer parameters
 */
bool quid_validate_buffer(const void* buffer, size_t size)
{
    /* NULL check with size exception for zero-length operations */
    if (!buffer && size > 0) {
        return false;
    }

    /* Reasonable size limits to prevent denial of service */
    if (size > 10 * 1024 * 1024) {  /* 10MB limit */
        return false;
    }

    return true;
}

/**
 * @brief validate signature structure
 */
bool quid_validate_signature(const quid_signature_t* signature)
{
    if (!signature) {
        return false;
    }

    /* Check signature size is within reasonable bounds */
    if (signature->size == 0 || signature->size > QUID_SIGNATURE_SIZE) {
        return false;
    }

    /* Check that signature data is accessible */
    if (!quid_validate_buffer(signature->data, signature->size)) {
        return false;
    }

    /* Check public key data */
    if (!quid_validate_buffer(signature->public_key, QUID_PUBLIC_KEY_SIZE)) {
        return false;
    }

    return true;
}

/**
 * @brief Validate identity structure (basic checks)
 */
bool quid_validate_identity_structure(const quid_identity_t* identity)
{
    if (!identity) {
        return false;
    }

    /* Basic structure validation - more detailed validation happens in internal functions */
    return true;
}

/**
 * @brief Validate message and message length for signing/verification
 */
bool quid_validate_message(const uint8_t* message, size_t message_len)
{
    /* Allow NULL message for zero-length messages */
    if (!message && message_len > 0) {
        return false;
    }

    /* Reasonable message size limits */
    if (message_len > 1024 * 1024) {  /* 1MB limit for messages */
        return false;
    }

    return true;
}

/**
 * @brief Validate context for key derivation
 */
bool quid_validate_context(const quid_context_t* context)
{
    if (!context) {
        return false;
    }

    /* Validate security level */
    if (!quid_validate_security_level(context->security)) {
        return false;
    }

    /* Check additional data size is reasonable */
    if (context->additional_data_len > sizeof(context->additional_data)) {
        return false;
    }

    /* Validate string fields are properly terminated */
    if (context->network_type[0] != '\0' &&
        strlen(context->network_type) >= sizeof(context->network_type)) {
        return false;
    }

    if (context->application_id[0] != '\0' &&
        strlen(context->application_id) >= sizeof(context->application_id)) {
        return false;
    }

    if (context->purpose[0] != '\0' &&
        strlen(context->purpose) >= sizeof(context->purpose)) {
        return false;
    }

    return true;
}

/**
 * @brief Validate authentication request
 */
bool quid_validate_auth_request(const quid_auth_request_t* request)
{
    if (!request) {
        return false;
    }

    /* Validate context */
    if (!quid_validate_context(&request->context)) {
        return false;
    }

    /* Validate challenge */
    if (!quid_validate_buffer(request->challenge, request->challenge_len)) {
        return false;
    }

    /* Challenge size limits */
    if (request->challenge_len == 0 || request->challenge_len > sizeof(request->challenge)) {
        return false;
    }

    /* Validate nonce is properly terminated */
    if (request->nonce[0] != '\0' &&
        strlen(request->nonce) >= sizeof(request->nonce)) {
        return false;
    }

    /* Reasonable timestamp */
    if (request->timestamp == 0) {
        return false;
    }

    return true;
}

/**
 * @brief Validate authentication response
 */
bool quid_validate_auth_response(const quid_auth_response_t* response)
{
    if (!response) {
        return false;
    }

    /* Validate signature */
    if (!quid_validate_signature(&response->signature)) {
        return false;
    }

    /* Validate proof data */
    if (!quid_validate_buffer(response->proof, response->proof_len)) {
        return false;
    }

    /* Proof size limits */
    if (response->proof_len > sizeof(response->proof)) {
        return false;
    }

    /* Validate identity ID is properly terminated */
    if (response->identity_id[0] != '\0' &&
        strlen(response->identity_id) >= sizeof(response->identity_id)) {
        return false;
    }

    /* Reasonable timestamp */
    if (response->timestamp == 0) {
        return false;
    }

    return true;
}

/**
 * @brief Validate password parameters for backup operations
 */
bool quid_validate_password(const char* password, size_t min_length, size_t max_length)
{
    if (!password) {
        return false;
    }

    size_t password_len = strlen(password);

    /* Password length requirements */
    if (password_len < min_length || password_len > max_length) {
        return false;
    }

    /* Basic password strength checks (can be enhanced) */
    if (min_length >= 8) {
        bool has_upper = false, has_lower = false, has_digit = false;

        for (size_t i = 0; i < password_len; i++) {
            char c = password[i];
            if (c >= 'A' && c <= 'Z') has_upper = true;
            else if (c >= 'a' && c <= 'z') has_lower = true;
            else if (c >= '0' && c <= '9') has_digit = true;
        }

        /* Require mix of character types for strong passwords */
        if (!has_upper || !has_lower || !has_digit) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Safe string copy with null termination guarantee
 */
bool quid_safe_strcpy(char* dest, size_t dest_size, const char* src)
{
    if (!dest || !src || dest_size == 0) {
        return false;
    }

    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        return false;  /* Source too large */
    }

    strcpy(dest, src);
    return true;
}

/**
 * @brief Constant-time memory comparison to prevent timing attacks
 */
int quid_safe_memcmp(const void* a, const void* b, size_t size)
{
    if (!a || !b) {
        return -1;
    }

    const uint8_t* ua = (const uint8_t*)a;
    const uint8_t* ub = (const uint8_t*)b;

    int result = 0;
    for (size_t i = 0; i < size; i++) {
        result |= ua[i] ^ ub[i];
    }

    return result;
}