/**
 * @file validation.h
 * @brief QUID Input Validation Header
 *
 * Provides input validation functions for security and robustness.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_VALIDATION_H
#define QUID_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "quid/quid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Core validation functions */
bool quid_validate_security_level(quid_security_level_t security_level);
bool quid_validate_buffer(const void* buffer, size_t size);
bool quid_validate_message(const uint8_t* message, size_t message_len);

/* Structure validation */
bool quid_validate_signature(const quid_signature_t* signature);
bool quid_validate_identity_structure(const quid_identity_t* identity);
bool quid_validate_context(const quid_context_t* context);
bool quid_validate_auth_request(const quid_auth_request_t* request);
bool quid_validate_auth_response(const quid_auth_response_t* response);

/* Security parameter validation */
bool quid_validate_password(const char* password, size_t min_length, size_t max_length);

/* Safe utility functions */
bool quid_safe_strcpy(char* dest, size_t dest_size, const char* src);
int quid_safe_memcmp(const void* a, const void* b, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* QUID_VALIDATION_H */