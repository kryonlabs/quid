/**
 * @file adapter.h
 * @brief QUID Adapter Interface
 *
 * Standardized interface for network-specific adapters that
 * derive protocol-specific keys from QUID master identity.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_ADAPTER_H
#define QUID_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "quid/quid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Adapter ABI Version */
#define QUID_ADAPTER_ABI_VERSION 1

/* Adapter Types */
typedef enum {
    QUID_ADAPTER_TYPE_BLOCKCHAIN = 1,
    QUID_ADAPTER_TYPE_AUTHENTICATION = 2,
    QUID_ADAPTER_TYPE_COMMUNICATION = 3,
    QUID_ADAPTER_TYPE_CUSTOM = 255
} quid_adapter_type_t;

/* Adapter Capabilities */
typedef enum {
    QUID_ADAPTER_CAP_SIGN = 0x01,
    QUID_ADAPTER_CAP_VERIFY = 0x02,
    QUID_ADAPTER_CAP_ENCRYPT = 0x04,
    QUID_ADAPTER_CAP_DECRYPT = 0x08,
    QUID_ADAPTER_CAP_DERIVE_ADDRESS = 0x10,
    QUID_ADAPTER_CAP_DERIVE_PUBLIC = 0x20,
    QUID_ADAPTER_CAP_BATCH_OPERATIONS = 0x40
} quid_adapter_capabilities_t;

/* Adapter Status Codes */
typedef enum {
    QUID_ADAPTER_SUCCESS = 0,
    QUID_ADAPTER_ERROR_INVALID_CONTEXT = -1,
    QUID_ADAPTER_ERROR_KEY_DERIVATION = -2,
    QUID_ADAPTER_ERROR_SIGNING = -3,
    QUID_ADAPTER_ERROR_VERIFICATION = -4,
    QUID_ADAPTER_ERROR_NETWORK_SPECIFIC = -5,
    QUID_ADAPTER_ERROR_NOT_SUPPORTED = -6
} quid_adapter_status_t;

/* Forward Declarations */
typedef struct quid_adapter quid_adapter_t;
typedef struct quid_adapter_info quid_adapter_info_t;

/**
 * @brief Adapter information structure
 */
struct quid_adapter_info {
    uint32_t abi_version;                    /* ABI version */
    char name[64];                           /* Adapter name */
    char version[16];                        /* Adapter version */
    char network_name[32];                   /* Network name */
    quid_network_type_t network_type;        /* Network type */
    quid_adapter_type_t adapter_type;        /* Adapter type */
    uint32_t capabilities;                   /* Bitwise OR of capabilities */
    char description[256];                   /* Adapter description */
    char author[64];                         /* Adapter author */
    char license[32];                        /* Adapter license */
};

/**
 * @brief Adapter context structure
 */
typedef struct {
    char network_name[32];                   /* Network identifier */
    char network_version[16];                /* Network protocol version */
    uint8_t derivation_path[128];            /* BIP-32 style path or similar */
    size_t derivation_path_len;              /* Length of derivation path */
    uint8_t network_params[64];              /* Network-specific parameters */
    size_t network_params_len;               /* Length of network parameters */
} quid_adapter_context_t;

/**
 * @brief Adapter operation result structure
 */
typedef struct {
    quid_adapter_status_t status;            /* Operation status */
    uint8_t* data;                          /* Result data */
    size_t data_len;                        /* Length of result data */
    char error_message[128];                /* Error message if failed */
} quid_adapter_result_t;

/* Adapter Function Pointers */

/**
 * @brief Adapter initialization function
 * @param context Adapter context
 * @return Adapter instance pointer or NULL on failure
 */
typedef quid_adapter_t* (*quid_adapter_init_fn)(const quid_adapter_context_t* context);

/**
 * @brief Adapter cleanup function
 * @param adapter Adapter instance
 */
typedef void (*quid_adapter_cleanup_fn)(quid_adapter_t* adapter);

/**
 * @brief Get adapter information
 * @param adapter Adapter instance
 * @return Pointer to adapter info (valid until adapter is cleaned up)
 */
typedef const quid_adapter_info_t* (*quid_adapter_get_info_fn)(const quid_adapter_t* adapter);

/**
 * @brief Derive network-specific key from QUID identity
 * @param adapter Adapter instance
 * @param master_key QUID master key
 * @param master_key_size Size of master key
 * @param context QUID context
 * @param derived_key Output buffer for derived key
 * @param key_size Size of derived key buffer
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_derive_key_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* master_key,
    size_t master_key_size,
    const quid_context_t* context,
    uint8_t* derived_key,
    size_t key_size);

/**
 * @brief Derive network-specific address
 * @param adapter Adapter instance
 * @param derived_key Derived network key
 * @param key_size Size of derived key
 * @param address Output buffer for address
 * @param address_size Input/output address size
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_derive_address_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    char* address,
    size_t* address_size);

/**
 * @brief Sign message with derived key
 * @param adapter Adapter instance
 * @param derived_key Derived network key
 * @param key_size Size of derived key
 * @param message Message to sign
 * @param message_len Message length
 * @param signature Output signature
 * @param signature_size Input/output signature size
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_sign_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature,
    size_t* signature_size);

/**
 * @brief Verify signature with derived public key
 * @param adapter Adapter instance
 * @param public_key Derived public key
 * @param key_size Size of public key
 * @param message Original message
 * @param message_len Message length
 * @param signature Signature to verify
 * @param signature_len Signature length
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_verify_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* public_key,
    size_t key_size,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len);

/**
 * @brief Encrypt message with derived key
 * @param adapter Adapter instance
 * @param derived_key Derived network key
 * @param key_size Size of derived key
 * @param plaintext Message to encrypt
 * @param plaintext_len Message length
 * @param ciphertext Output ciphertext
 * @param ciphertext_size Input/output ciphertext size
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_encrypt_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_size);

/**
 * @brief Decrypt message with derived key
 * @param adapter Adapter instance
 * @param derived_key Derived network key
 * @param key_size Size of derived key
 * @param ciphertext Message to decrypt
 * @param ciphertext_len Message length
 * @param plaintext Output plaintext
 * @param plaintext_size Input/output plaintext size
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_decrypt_fn)(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_size);

/**
 * @brief Batch operations support
 * @param adapter Adapter instance
 * @param operations Array of operations
 * @param operation_count Number of operations
 * @param results Array of results
 * @return Adapter status
 */
typedef quid_adapter_status_t (*quid_adapter_batch_fn)(
    const quid_adapter_t* adapter,
    const void** operations,
    size_t operation_count,
    quid_adapter_result_t* results);

/**
 * @brief Adapter function table
 */
typedef struct {
    uint32_t abi_version;                    /* Must be QUID_ADAPTER_ABI_VERSION */
    quid_adapter_init_fn init;               /* Initialize adapter */
    quid_adapter_cleanup_fn cleanup;         /* Cleanup adapter */
    quid_adapter_get_info_fn get_info;       /* Get adapter info */
    quid_adapter_derive_key_fn derive_key;   /* Derive key (required) */
    quid_adapter_derive_address_fn derive_address; /* Derive address (optional) */
    quid_adapter_sign_fn sign;               /* Sign message (optional) */
    quid_adapter_verify_fn verify;           /* Verify signature (optional) */
    quid_adapter_encrypt_fn encrypt;         /* Encrypt message (optional) */
    quid_adapter_decrypt_fn decrypt;         /* Decrypt message (optional) */
    quid_adapter_batch_fn batch;             /* Batch operations (optional) */
} quid_adapter_functions_t;

/**
 * @brief Adapter instance structure
 */
struct quid_adapter {
    quid_adapter_functions_t* functions;     /* Function table */
    quid_adapter_info_t info;                /* Adapter information */
    void* private_data;                      /* Private adapter data */
    bool is_initialized;                     /* Initialization state */
};

/* Adapter Management Functions */

/**
 * @brief Load adapter from shared library
 * @param library_path Path to adapter shared library
 * @param context Adapter context
 * @param adapter Output adapter instance
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_adapter_load(const char* library_path,
                                const quid_adapter_context_t* context,
                                quid_adapter_t** adapter);

/**
 * @brief Unload adapter
 * @param adapter Adapter to unload
 */
void quid_adapter_unload(quid_adapter_t* adapter);

/**
 * @brief Get adapter capabilities as string
 * @param capabilities Capabilities bitmask
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return QUID_SUCCESS on success, error code on failure
 */
quid_status_t quid_adapter_capabilities_string(uint32_t capabilities,
                                               char* buffer,
                                               size_t buffer_size);

/**
 * @brief Check if adapter supports capability
 * @param adapter Adapter instance
 * @param capability Capability to check
 * @return true if supported, false otherwise
 */
bool quid_adapter_supports(const quid_adapter_t* adapter,
                           quid_adapter_capabilities_t capability);

/* Helper Macros for Adapter Implementation */

#define QUID_ADAPTER_EXPORT __attribute__((visibility("default")))

#define QUID_ADAPTER_DEFINE_FUNCTIONS(prefix, adapter_type, private_type) \
    static quid_adapter_info_t prefix##_info = { \
        .abi_version = QUID_ADAPTER_ABI_VERSION, \
        .name = #adapter_type, \
        .version = "1.0.0", \
        .network_name = #adapter_type, \
        .network_type = QUID_NETWORK_CUSTOM, \
        .adapter_type = QUID_ADAPTER_TYPE_CUSTOM, \
        .capabilities = 0, \
        .description = "QUID Adapter for " #adapter_type, \
        .author = "QUID Foundation", \
        .license = "0BSD" \
    }; \
    \
    static quid_adapter_functions_t prefix##_functions = { \
        .abi_version = QUID_ADAPTER_ABI_VERSION, \
        .init = prefix##_init, \
        .cleanup = prefix##_cleanup, \
        .get_info = prefix##_get_info, \
        .derive_key = prefix##_derive_key, \
        .derive_address = prefix##_derive_address, \
        .sign = prefix##_sign, \
        .verify = prefix##_verify, \
        .encrypt = prefix##_encrypt, \
        .decrypt = prefix##_decrypt, \
        .batch = prefix##_batch \
    }; \
    \
    QUID_ADAPTER_EXPORT quid_adapter_functions_t* quid_adapter_get_functions(void) { \
        return &prefix##_functions; \
    }

#ifdef __cplusplus
}
#endif

#endif /* QUID_ADAPTER_H */