/**
 * @file constants.h
 * @brief QUID System Constants and Configuration
 *
 * Centralized constants for the QUID system to improve maintainability
 * and avoid hard-coded magic numbers throughout the codebase.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_CONSTANTS_H
#define QUID_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
   CRYPTOGRAPHIC CONSTANTS
   ============================================================================= */

/* ML-DSA Algorithm Sizes (from NIST standardization) */
#define QUID_MLDSA44_PUBLIC_KEY_SIZE    1312    /* ML-DSA-44 public key size */
#define QUID_MLDSA44_PRIVATE_KEY_SIZE   2560    /* ML-DSA-44 private key size */
#define QUID_MLDSA44_SIGNATURE_SIZE     2420    /* ML-DSA-44 signature size */

#define QUID_MLDSA65_PUBLIC_KEY_SIZE    1952    /* ML-DSA-65 public key size */
#define QUID_MLDSA65_PRIVATE_KEY_SIZE   4032    /* ML-DSA-65 private key size */
#define QUID_MLDSA65_SIGNATURE_SIZE     3293    /* ML-DSA-65 signature size */

#define QUID_MLDSA87_PUBLIC_KEY_SIZE    2592    /* ML-DSA-87 public key size */
#define QUID_MLDSA87_PRIVATE_KEY_SIZE   4896    /* ML-DSA-87 private key size */
#define QUID_MLDSA87_SIGNATURE_SIZE     4627    /* ML-DSA-87 signature size */

/* Maximum sizes (using ML-DSA-87 as reference) */
#define QUID_MAX_PUBLIC_KEY_SIZE        QUID_MLDSA87_PUBLIC_KEY_SIZE
#define QUID_MAX_PRIVATE_KEY_SIZE       QUID_MLDSA87_PRIVATE_KEY_SIZE
#define QUID_MAX_SIGNATURE_SIZE         QUID_MLDSA87_SIGNATURE_SIZE

/* Cryptographic operation constants */
#define QUID_DEFAULT_ITERATIONS        100000  /* Default PBKDF iterations */
#define QUID_MIN_ITERATIONS             10000   /* Minimum PBKDF iterations */
#define QUID_MAX_ITERATIONS            1000000  /* Maximum PBKDF iterations */

#define QUID_AEAD_KEY_SIZE              32      /* AEAD encryption key size */
#define QUID_AEAD_IV_SIZE               16      /* AEAD IV size */
#define QUID_AEAD_TAG_SIZE              16      /* AEAD tag size */

#define QUID_KDF_SALT_SIZE              32      /* Key derivation salt size */
#define QUID_DERIVED_KEY_SIZE           64      /* Derived key size for networks */
#define QUID_ARGON2_TIME_COST           2         /* Argon2 default iterations */
#define QUID_ARGON2_MEMORY_KIB          (1 << 15) /* Argon2 memory cost (32 MiB) */
#define QUID_ARGON2_PARALLELISM         1         /* Argon2 lanes (parallelism) */
#define QUID_ARGON2_MIN_TIME_COST       2         /* Minimum allowed iterations */
#define QUID_ARGON2_MIN_MEMORY_KIB      (1 << 15) /* Minimum memory (32 MiB) */
#define QUID_ARGON2_MAX_PARALLELISM     8         /* Maximum allowed lanes */

/* =============================================================================
   BUFFER AND MEMORY CONSTANTS
   ============================================================================= */

/* General buffer sizes */
#define QUID_SMALL_BUFFER_SIZE          32      /* Small operations */
#define QUID_MEDIUM_BUFFER_SIZE         256     /* Medium operations */
#define QUID_LARGE_BUFFER_SIZE          1024    /* Large operations */
#define QUID_HUGE_BUFFER_SIZE           4096    /* Very large operations */

/* Message and data sizes */
#define QUID_MAX_MESSAGE_SIZE           8192    /* Maximum message size */
#define QUID_MAX_CONTEXT_SIZE           512     /* Maximum context size */
#define QUID_MAX_COMMENT_SIZE           256     /* Maximum comment size */

/* Timestamp and identifier sizes */
#define QUID_TIMESTAMP_BUFFER_SIZE     32      /* Timestamp string buffer */
#define QUID_ID_BUFFER_SIZE             64      /* Identity ID buffer */
#define QUID_ERROR_BUFFER_SIZE          128     /* Error message buffer */

/* =============================================================================
   NETWORK AND PROTOCOL CONSTANTS
   ============================================================================= */

/* Network type limits */
#define QUID_MAX_NETWORK_TYPE_SIZE      32      /* Maximum network type length */
#define QUID_MAX_APPLICATION_ID_SIZE    128     /* Maximum application ID length */
#define QUID_MAX_PURPOSE_SIZE           64      /* Maximum purpose length */

/* Authentication constants */
#define QUID_CHALLENGE_SIZE             32      /* Authentication challenge size */
#define QUID_NONCE_SIZE                 16      /* Authentication nonce size */
#define QUID_MAX_NONCE_SIZE             32      /* Maximum nonce buffer size */

/* Timestamp validity (in milliseconds) */
#define QUID_TIMESTAMP_VALIDITY         300000  /* 5 minutes */
#define QUID_MAX_CLOCK_SKEW             60000   /* 1 minute max clock skew */

/* =============================================================================
   BACKUP AND RECOVERY CONSTANTS
   ============================================================================= */

/* Backup encryption */
#define QUID_BACKUP_KEY_SIZE            32      /* Backup encryption key */
#define QUID_BACKUP_IV_SIZE             16      /* Backup IV */
#define QUID_BACKUP_SALT_SIZE           16      /* Backup salt */

/* Backup data sizes */
#define QUID_BACKUP_HEADER_SIZE         128     /* Backup header size */
#define QUID_BACKUP_MAX_SIZE            16384   /* Maximum backup size */
#define QUID_BACKUP_BASE64_MAX_SIZE     (QUID_BACKUP_MAX_SIZE * 2)

/* =============================================================================
   TESTING AND DEBUGGING CONSTANTS
   ============================================================================= */

/* Test message sizes */
#define QUID_TEST_SMALL_MESSAGE_SIZE    64      /* Small test message */
#define QUID_TEST_MEDIUM_MESSAGE_SIZE   256     /* Medium test message */
#define QUID_TEST_LARGE_MESSAGE_SIZE    1024    /* Large test message */

/* Performance testing */
#define QUID_PERF_ITERATIONS           100     /* Performance test iterations */
#define QUID_PERF_IDENTITY_COUNT        10      /* Number of identities for testing */

/* =============================================================================
   COMPATIBILITY AND VERSION CONSTANTS
   ============================================================================= */

/* Adapter interface */
#define QUID_ADAPTER_ABI_VERSION        1       /* Current adapter ABI version */
#define QUID_ADAPTER_MAX_CAPS           8       /* Maximum adapter capabilities */

/* Protocol versions */
#define QUID_PROTOCOL_VERSION_MAJOR     1       /* Major version */
#define QUID_PROTOCOL_VERSION_MINOR     0       /* Minor version */
#define QUID_PROTOCOL_VERSION_PATCH     0       /* Patch version */

/* =============================================================================
   MACRO HELPER FUNCTIONS
   ============================================================================= */

/* Macro to get ML-DSA parameters for security level */
#define QUID_MLDSA_PARAMS(level, pk, sk, sig) do { \
    switch (level) { \
        case 1: *(pk) = QUID_MLDSA44_PUBLIC_KEY_SIZE; \
                 *(sk) = QUID_MLDSA44_PRIVATE_KEY_SIZE; \
                 *(sig) = QUID_MLDSA44_SIGNATURE_SIZE; \
                 break; \
        case 3: *(pk) = QUID_MLDSA65_PUBLIC_KEY_SIZE; \
                 *(sk) = QUID_MLDSA65_PRIVATE_KEY_SIZE; \
                 *(sig) = QUID_MLDSA65_SIGNATURE_SIZE; \
                 break; \
        case 5: *(pk) = QUID_MLDSA87_PUBLIC_KEY_SIZE; \
                 *(sk) = QUID_MLDSA87_PRIVATE_KEY_SIZE; \
                 *(sig) = QUID_MLDSA87_SIGNATURE_SIZE; \
                 break; \
        default: *(pk) = QUID_MLDSA87_PUBLIC_KEY_SIZE; \
                  *(sk) = QUID_MLDSA87_PRIVATE_KEY_SIZE; \
                  *(sig) = QUID_MLDSA87_SIGNATURE_SIZE; \
                  break; \
    } \
} while(0)

/* Safe buffer size macro */
#define QUID_SAFE_BUFFER_SIZE(required) \
    (((required) + (sizeof(size_t) - 1)) & ~(sizeof(size_t) - 1))

/* Array size macro */
#define QUID_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* =============================================================================
   VALIDATION CONSTANTS
   ============================================================================= */

/* Input validation limits */
#define QUID_MIN_PASSWORD_LENGTH        8       /* Minimum password length */
#define QUID_MAX_PASSWORD_LENGTH        1024    /* Maximum password length */
#define QUID_MAX_FILENAME_LENGTH        256     /* Maximum filename length */

/* Security validation */
#define QUID_MAX_FAILED_ATTEMPTS        5       /* Maximum failed attempts */
#define QUID_LOCKOUT_DURATION           300000  /* Lockout duration in ms */

#ifdef __cplusplus
}
#endif

#endif /* QUID_CONSTANTS_H */
