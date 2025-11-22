/**
 * @file quid.h
 * @brief QUID (Quantum-Resistant Universal Identity) Core Library
 *
 * QUID provides quantum-resistant, network-agnostic digital identity
 * using ML-DSA (CRYSTALS-Dilithium) cryptography.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_H
#define QUID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version Information */
#define QUID_VERSION_MAJOR 1
#define QUID_VERSION_MINOR 0
#define QUID_VERSION_PATCH 0
#define QUID_VERSION_STRING "1.0.0"

/* Error Codes */
typedef enum {
    QUID_SUCCESS = 0,
    QUID_ERROR_INVALID_PARAMETER = -1,
    QUID_ERROR_MEMORY_ALLOCATION = -2,
    QUID_ERROR_CRYPTOGRAPHIC = -3,
    QUID_ERROR_BUFFER_TOO_SMALL = -4,
    QUID_ERROR_INVALID_FORMAT = -5,
    QUID_ERROR_NOT_IMPLEMENTED = -6,
    QUID_ERROR_IDENTITY_NOT_FOUND = -7,
    QUID_ERROR_ADAPTER_ERROR = -8,
    QUID_ERROR_QUANTUM_UNSAFE = -9
} quid_status_t;

/* Cryptographic Parameters */
#define QUID_MASTER_KEY_SIZE 4896     /* ML-DSA-87 master key size */
#define QUID_SIGNATURE_SIZE 4627      /* ML-DSA-87 signature size */
#define QUID_PUBLIC_KEY_SIZE 2592     /* ML-DSA-87 public key size */
#define QUID_SEED_SIZE 48             /* Entropy seed for key generation */
#define QUID_CONTEXT_SIZE 256         /* Maximum context string size */
#define QUID_DERIVED_KEY_SIZE 64      /* Maximum derived key size */
#define QUID_ID_ID_SIZE 64            /* Identity ID string size */

/* Security Levels */
typedef enum {
    QUID_SECURITY_LEVEL_1 = 1,  /* ML-DSA-44 (128-bit security) */
    QUID_SECURITY_LEVEL_3 = 3,  /* ML-DSA-65 (192-bit security) */
    QUID_SECURITY_LEVEL_5 = 5   /* ML-DSA-87 (256-bit security) */
} quid_security_level_t;

/* Network Types */
typedef enum {
    QUID_NETWORK_BITCOIN = 1,
    QUID_NETWORK_ETHEREUM = 2,
    QUID_NETWORK_SSH = 3,
    QUID_NETWORK_WEBAUTHN = 4,
    QUID_NETWORK_CUSTOM = 255
} quid_network_type_t;

/* Forward Declarations */
typedef struct quid_identity quid_identity_t;
typedef struct quid_context quid_context_t;
typedef struct quid_signature quid_signature_t;

/**
 * @brief QUID context for key derivation
 */
struct quid_context {
    char network_type[32];           /* Network identifier */
    char application_id[128];        /* Application identifier */
    char purpose[64];                /* Derivation purpose */
    uint8_t additional_data[64];     /* Additional context data */
    size_t additional_data_len;      /* Length of additional data */
    quid_security_level_t security;  /* Security level */
};

/**
 * @brief QUID signature structure
 */
struct quid_signature {
    uint8_t data[QUID_SIGNATURE_SIZE];  /* Signature data */
    size_t size;                         /* Actual signature size */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE]; /* Signer's public key */
};

/**
 * @brief QUID identity structure
 */
struct quid_identity {
    uint8_t master_keypair[QUID_MASTER_KEY_SIZE]; /* ML-DSA master keypair */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];    /* Extracted public key */
    char id_string[QUID_ID_ID_SIZE];             /* Human-readable ID */
    quid_security_level_t security_level;        /* Security level */
    bool is_locked;                              /* Memory protection state */
    void* secure_memory;                         /* Secure memory region */
    size_t secure_size;                          /* Size of secure region */
};

/* Core Identity Functions */

/**
 * @brief Initialize the QUID library
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_init(void);

/**
 * @brief Cleanup the QUID library
 */
void quid_cleanup(void);

/**
 * @brief Create a new QUID identity
 * @param identity Output pointer for new identity
 * @param security_level Security level (default: QUID_SECURITY_LEVEL_5)
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_create(quid_identity_t** identity,
                                   quid_security_level_t security_level);

/**
 * @brief Create identity from seed
 * @param identity Output pointer for new identity
 * @param seed Entropy seed (must be QUID_SEED_SIZE bytes)
 * @param security_level Security level
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_from_seed(quid_identity_t** identity,
                                      const uint8_t* seed,
                                      quid_security_level_t security_level);

/**
 * @brief Import identity from encrypted backup
 * @param identity Output pointer for imported identity
 * @param data Encrypted identity data
 * @param data_len Length of encrypted data
 * @param password Decryption password
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_import(quid_identity_t** identity,
                                   const uint8_t* data,
                                   size_t data_len,
                                   const char* password);

/**
 * @brief Export identity to encrypted backup
 * @param identity Identity to export
 * @param data Output buffer for encrypted data
 * @param data_len Input/output length
 * @param password Encryption password
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_export(const quid_identity_t* identity,
                                   uint8_t* data,
                                   size_t* data_len,
                                   const char* password);

/**
 * @brief Free identity and secure memory
 * @param identity Identity to free
 */
void quid_identity_free(quid_identity_t* identity);

/**
 * @brief Get identity ID string
 * @param identity Identity
 * @return ID string (valid until identity is modified)
 */
const char* quid_get_identity_id(const quid_identity_t* identity);

/**
 * @brief Get public key
 * @param identity Identity
 * @param public_key Output buffer (must be QUID_PUBLIC_KEY_SIZE)
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_get_public_key(const quid_identity_t* identity,
                                  uint8_t* public_key);

/* Key Derivation Functions */

/**
 * @brief Derive key for specific network/context
 * @param identity Master identity
 * @param context Derivation context
 * @param derived_key Output buffer for derived key
 * @param key_size Size of derived key buffer
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_derive_key(const quid_identity_t* identity,
                              const quid_context_t* context,
                              uint8_t* derived_key,
                              size_t key_size);

/**
 * @brief Sign message using identity
 * @param identity Identity to sign with
 * @param message Message to sign
 * @param message_len Message length
 * @param signature Output signature
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_sign(const quid_identity_t* identity,
                        const uint8_t* message,
                        size_t message_len,
                        quid_signature_t* signature);

/**
 * @brief Verify signature
 * @param public_key Signer's public key
 * @param message Original message
 * @param message_len Message length
 * @param signature Signature to verify
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_verify(const uint8_t* public_key,
                          const uint8_t* message,
                          size_t message_len,
                          const quid_signature_t* signature);

/* Authentication Functions */

/**
 * @brief Authentication request structure
 */
typedef struct {
    quid_context_t context;
    uint8_t challenge[64];
    size_t challenge_len;
    uint64_t timestamp;
    char nonce[32];
} quid_auth_request_t;

/**
 * @brief Authentication response structure
 */
typedef struct {
    quid_signature_t signature;
    uint8_t proof[128];
    size_t proof_len;
    char identity_id[QUID_ID_ID_SIZE];
    uint64_t timestamp;
} quid_auth_response_t;

/**
 * @brief Authenticate to a service
 * @param identity Identity to authenticate
 * @param request Authentication request
 * @param response Authentication response
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_authenticate(const quid_identity_t* identity,
                                const quid_auth_request_t* request,
                                quid_auth_response_t* response);

/**
 * @brief Verify authentication response
 * @param response Authentication response to verify
 * @param request Original authentication request
 * @param expected_identity_id Expected identity ID (optional)
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_verify_auth(const quid_auth_response_t* response,
                               const quid_auth_request_t* request,
                               const char* expected_identity_id);

/* Utility Functions */

/**
 * @brief Generate secure random bytes
 * @param buffer Output buffer
 * @param size Number of bytes to generate
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_random_bytes(uint8_t* buffer, size_t size);

/**
 * @brief Zero memory in a secure manner
 * @param buffer Memory to zero
 * @param size Size of memory
 */
void quid_secure_zero(void* buffer, size_t size);

/**
 * @brief Compare two memory regions in constant time
 * @param a First buffer
 * @param b Second buffer
 * @param size Size to compare
 * @return 0 if equal, non-zero if different
 */
int quid_constant_time_compare(const void* a, const void* b, size_t size);

/**
 * @brief Check if system is quantum-safe
 * @return true if quantum-safe algorithms are available
 */
bool quid_is_quantum_safe(void);

/**
 * @brief Get library version information
 * @param major Output for major version (optional)
 * @param minor Output for minor version (optional)
 * @param patch Output for patch version (optional)
 * @return Version string
 */
const char* quid_get_version(int* major, int* minor, int* patch);

/* Memory Protection Functions */

/**
 * @brief Lock identity in secure memory
 * @param identity Identity to lock
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_lock(quid_identity_t* identity);

/**
 * @brief Unlock identity from secure memory
 * @param identity Identity to unlock
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_unlock(quid_identity_t* identity);

/**
 * @brief Check if identity is locked
 * @param identity Identity to check
 * @return true if locked, false otherwise
 */
bool quid_identity_is_locked(const quid_identity_t* identity);

/* Backup and Restore Functions */

/**
 * @brief Backup identity to encrypted format
 * @param identity Identity to backup
 * @param password Encryption password
 * @param comment Optional backup comment
 * @param backup_data Output buffer for encrypted backup
 * @param backup_data_size Input/output backup size
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_backup(const quid_identity_t* identity,
                                   const char* password,
                                   const char* comment,
                                   uint8_t* backup_data,
                                   size_t* backup_data_size);

/**
 * @brief Restore identity from encrypted backup
 * @param backup_data Encrypted backup data
 * @param backup_data_size Size of backup data
 * @param password Decryption password
 * @param identity Output pointer for restored identity
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_identity_restore(const uint8_t* backup_data,
                                   size_t backup_data_size,
                                   const char* password,
                                   quid_identity_t** identity);

/**
 * @brief Verify backup integrity without decrypting
 * @param backup_data Backup data to verify
 * @param backup_data_size Size of backup data
 * @param identity_id Expected identity ID (optional)
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_backup_verify(const uint8_t* backup_data,
                                 size_t backup_data_size,
                                 const char* identity_id);

/**
 * @brief Get backup metadata information
 * @param backup_data Backup data
 * @param backup_data_size Size of backup data
 * @param timestamp Output buffer for timestamp (optional)
 * @param timestamp_size Size of timestamp buffer
 * @param identity_id Output buffer for identity ID (optional)
 * @param identity_id_size Size of identity ID buffer
 * @param security_level Output for security level (optional)
 * @param comment Output buffer for comment (optional)
 * @param comment_size Size of comment buffer
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_backup_get_info(const uint8_t* backup_data,
                                  size_t backup_data_size,
                                  char* timestamp,
                                  size_t timestamp_size,
                                  char* identity_id,
                                  size_t identity_id_size,
                                  quid_security_level_t* security_level,
                                  char* comment,
                                  size_t comment_size);

/**
 * @brief Export backup to base64 format
 * @param backup_data Binary backup data
 * @param backup_data_size Size of backup data
 * @param base64_output Output buffer for base64 string
 * @param base64_size Input/output size of base64 buffer
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_backup_export_base64(const uint8_t* backup_data,
                                       size_t backup_data_size,
                                       char* base64_output,
                                       size_t* base64_size);

/**
 * @brief Import backup from base64 format
 * @param base64_input Base64 encoded backup string
 * @param backup_data Output buffer for binary backup data
 * @param backup_data_size Input/output size of backup data buffer
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_backup_import_base64(const char* base64_input,
                                       uint8_t* backup_data,
                                       size_t* backup_data_size);

/* Error Handling */

/**
 * @brief Get error description
 * @param status Error code
 * @return Human-readable error description
 */
const char* quid_get_error_string(quid_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* QUID_H */