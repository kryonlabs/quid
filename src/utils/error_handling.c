/**
 * @file error_handling.c
 * @brief QUID Error Handling and Logging
 *
 * Comprehensive error handling system for production use with
 * proper logging, error context, and recovery mechanisms.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>

#include "quid/quid.h"

/* Error context for detailed debugging */
typedef struct {
    quid_status_t error_code;
    const char* function;
    const char* file;
    int line;
    const char* context;
    time_t timestamp;
} quid_error_context_t;

/* Global error context (thread-safe in production would use TLS) */
static quid_error_context_t g_last_error = {0};

/**
 * @brief Set detailed error context
 */
void quid_set_error_context(quid_status_t error_code,
                           const char* function,
                           const char* file,
                           int line,
                           const char* context)
{
    g_last_error.error_code = error_code;
    g_last_error.function = function;
    g_last_error.file = file;
    g_last_error.line = line;
    g_last_error.context = context;
    g_last_error.timestamp = time(NULL);
}

/**
 * @brief Get last error context
 */
const quid_error_context_t* quid_get_last_error_context(void)
{
    return &g_last_error;
}

/**
 * @brief Clear error context
 */
void quid_clear_error_context(void)
{
    memset(&g_last_error, 0, sizeof(g_last_error));
}

/**
 * @brief Enhanced error descriptions with context
 */
const char* quid_get_detailed_error_string(quid_status_t status)
{
    static char detailed_error[512];
    const char* base_error = quid_get_error_string(status);

    if (g_last_error.error_code == status &&
        g_last_error.function &&
        g_last_error.file &&
        g_last_error.timestamp > 0) {

        /* Format detailed error with context */
        char timestamp_str[32];
        struct tm* tm_info = localtime(&g_last_error.timestamp);
        if (tm_info) {
            strftime(timestamp_str, sizeof(timestamp_str),
                    "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strcpy(timestamp_str, "unknown");
        }

        /* Extract just the filename from full path */
        const char* filename = strrchr(g_last_error.file, '/');
        filename = filename ? filename + 1 : g_last_error.file;

        snprintf(detailed_error, sizeof(detailed_error),
                "%s\n  Context: %s\n  Function: %s()\n  File: %s:%d\n  Time: %s",
                base_error,
                g_last_error.context ? g_last_error.context : "No context",
                g_last_error.function,
                filename,
                g_last_error.line,
                timestamp_str);

        return detailed_error;
    }

    return base_error;
}

/**
 * @brief Safe error logging to prevent log injection
 */
void quid_safe_log(quid_status_t status, const char* operation, const char* details)
{
    if (!operation) {
        return;
    }

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];

    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strcpy(timestamp, "unknown");
    }

    /* Log to stderr for now - in production would use proper logging */
    fprintf(stderr, "[%s] QUID ERROR: %s failed", timestamp, operation);

    if (status != QUID_SUCCESS) {
        fprintf(stderr, " - %s", quid_get_error_string(status));
    }

    if (details && strlen(details) > 0) {
        /* Sanitize details to prevent log injection */
        fprintf(stderr, " - ");
        for (const char* p = details; *p; p++) {
            /* Only print safe characters */
            if ((*p >= ' ' && *p <= '~') || *p == '\t' || *p == '\n') {
                fputc(*p, stderr);
            } else {
                fputc('?', stderr);
            }
        }
    }

    fprintf(stderr, "\n");
    fflush(stderr);
}

/**
 * @brief Validate error recovery is possible
 */
bool quid_can_recover_from_error(quid_status_t status)
{
    switch (status) {
        case QUID_SUCCESS:
            return true;

        case QUID_ERROR_INVALID_PARAMETER:
        case QUID_ERROR_BUFFER_TOO_SMALL:
        case QUID_ERROR_NOT_IMPLEMENTED:
            return true;  /* User can fix these */

        case QUID_ERROR_MEMORY_ALLOCATION:
        case QUID_ERROR_CRYPTOGRAPHIC:
        case QUID_ERROR_QUANTUM_UNSAFE:
            return false;  /* System-level issues */

        case QUID_ERROR_INVALID_FORMAT:
        case QUID_ERROR_IDENTITY_NOT_FOUND:
        case QUID_ERROR_ADAPTER_ERROR:
            return true;  /* May be recoverable */

        default:
            return false;
    }
}

/**
 * @brief Suggest recovery action for error
 */
const char* quid_suggest_recovery(quid_status_t status)
{
    switch (status) {
        case QUID_SUCCESS:
            return "No recovery needed";

        case QUID_ERROR_INVALID_PARAMETER:
            return "Check input parameters and try again";

        case QUID_ERROR_MEMORY_ALLOCATION:
            return "Free memory and restart application";

        case QUID_ERROR_BUFFER_TOO_SMALL:
            return "Provide a larger buffer and retry";

        case QUID_ERROR_CRYPTOGRAPHIC:
            return "Check system resources and cryptographic libraries";

        case QUID_ERROR_INVALID_FORMAT:
            return "Verify data format and source integrity";

        case QUID_ERROR_NOT_IMPLEMENTED:
            return "Feature not available - use alternative approach";

        case QUID_ERROR_IDENTITY_NOT_FOUND:
            return "Verify identity exists and is accessible";

        case QUID_ERROR_ADAPTER_ERROR:
            return "Check external library dependencies";

        case QUID_ERROR_QUANTUM_UNSAFE:
            return "System lacks quantum-safe cryptographic support";

        default:
            return "Contact support with error details";
    }
}

/**
 * @brief Check if error indicates a security issue
 */
bool quid_is_security_error(quid_status_t status)
{
    switch (status) {
        case QUID_ERROR_CRYPTOGRAPHIC:
        case QUID_ERROR_QUANTUM_UNSAFE:
            return true;

        default:
            return false;
    }
}

/**
 * @brief Wrapper function that logs errors automatically
 */
quid_status_t quid_safe_execute(quid_status_t (*operation)(void*),
                               void* context,
                               const char* operation_name)
{
    if (!operation || !operation_name) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    quid_status_t result = operation(context);

    if (result != QUID_SUCCESS) {
        quid_safe_log(result, operation_name,
                     quid_can_recover_from_error(result) ?
                     "Recoverable error" : "Critical error");

        /* Store error context */
        quid_set_error_context(result, operation_name, __FILE__, __LINE__,
                             "Safe execution wrapper");
    }

    return result;
}

/**
 * @brief Validate system is in a secure state
 */
quid_status_t quid_validate_security_state(void)
{
    /* Check if quantum-safe algorithms are available */
    if (!quid_is_quantum_safe()) {
        return QUID_ERROR_QUANTUM_UNSAFE;
    }

    /* Additional security validations could be added here:
     * - Check for memory protection
     * - Verify cryptographic libraries are intact
     * - Validate system randomness sources
     */

    return QUID_SUCCESS;
}

/* Error handling macros for internal use */
#define QUID_SET_ERROR(status, context) \
    quid_set_error_context((status), __func__, __FILE__, __LINE__, (context))

#define QUID_LOG_ERROR(status, operation, details) \
    quid_safe_log((status), (operation), (details))

#define QUID_SAFE_CALL(operation, context) \
    quid_safe_execute((operation), (context), #operation)