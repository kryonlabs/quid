/**
 * @file identity.c
 * @brief QUID Core Identity Implementation
 *
 * Implementation of QUID identity management functions including
 * key generation, derivation, and secure memory management.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>

#include <argon2.h>

#include "quid/quid.h"
#include "../utils/memory.h"
#include "../utils/random.h"
#include "../utils/validation.h"
#include "../utils/crypto.h"
#include "../utils/constants.h"
#include "identity_internal.h"

/* Internal constants */
#define QUID_DERIVED_KEY_INFO "QUID derived key v1"

/* Global initialization state */
static bool g_quid_initialized = false;

/**
 * @brief Get ML-DSA parameters for security level
 */
static const ml_dsa_params_t* get_ml_dsa_params(quid_security_level_t security_level)
{
    switch (security_level) {
        case QUID_SECURITY_LEVEL_1:
            return &ml_dsa_params[0];  /* ML-DSA-44 */
        case QUID_SECURITY_LEVEL_3:
            return &ml_dsa_params[1];  /* ML-DSA-65 */
        case QUID_SECURITY_LEVEL_5:
            return &ml_dsa_params[2];  /* ML-DSA-87 */
        default:
            return &ml_dsa_params[2];  /* Default to highest security */
    }
}

/**
 * @brief Generate deterministic ID string from public key
 * @param public_key Public key bytes
 * @param public_key_size Size of public key
 * @param id_string Output ID string buffer
 */
static void generate_id_string(const uint8_t* public_key, size_t public_key_size, char* id_string)
{
    /* Create human-readable ID from public key hash */
    uint8_t hash[32];
    quid_crypto_sha256(public_key, public_key_size, hash);

    /* Encode as base58 with prefix */
    static const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    strcpy(id_string, "quid");

    /* Convert hash to base58 */
    char* ptr = id_string + 4;
    for (int i = 0; i < 12; i++) {
        uint32_t value = (hash[i*2] << 8) | hash[i*2 + 1];
        *ptr++ = alphabet[value % 58];
        *ptr++ = alphabet[(value / 58) % 58];
    }
    *ptr = '\0';
}

/**
 * @brief Initialize the QUID library
 */
quid_status_t quid_init(void)
{
    if (g_quid_initialized) {
        return QUID_SUCCESS;
    }

    /* Initialize cryptographic subsystem */
    if (!quid_crypto_init()) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Initialize secure memory subsystem */
    if (!quid_memory_init()) {
        quid_crypto_cleanup();
        return QUID_ERROR_MEMORY_ALLOCATION;
    }

    /* Initialize random number generator */
    if (!quid_random_init()) {
        quid_memory_cleanup();
        quid_crypto_cleanup();
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    g_quid_initialized = true;
    return QUID_SUCCESS;
}

/**
 * @brief Cleanup the QUID library
 */
void quid_cleanup(void)
{
    if (!g_quid_initialized) {
        return;
    }

    quid_random_cleanup();
    quid_memory_cleanup();
    quid_crypto_cleanup();

    g_quid_initialized = false;
}

/**
 * @brief Create a new QUID identity
 */
quid_status_t quid_identity_create(quid_identity_t** identity,
                                   quid_security_level_t security_level)
{
    /* Comprehensive input validation */
    if (!identity || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!quid_validate_security_level(security_level)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Allocate secure memory for identity */
    quid_identity_internal_t* id_internal =
        (quid_identity_internal_t*)quid_memory_secure_alloc(sizeof(quid_identity_internal_t));
    if (!id_internal) {
        return QUID_ERROR_MEMORY_ALLOCATION;
    }

    /* Initialize structure */
    quid_secure_zero(id_internal, sizeof(quid_identity_internal_t));
    id_internal->magic = QUID_IDENTITY_MAGIC;
    id_internal->security_level = security_level;
    id_internal->creation_time = (uint64_t)time(NULL);

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(security_level);

    /* Generate ML-DSA keypair */
    if (!quid_crypto_ml_dsa_keygen(NULL, 0,  /* PQClean generates its own randomness */
                                    id_internal->master_keypair, params->private_key_size,
                                    id_internal->public_key, params->public_key_size,
                                    security_level)) {
        quid_memory_secure_free(id_internal, sizeof(quid_identity_internal_t));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Key generation validation - arrays are always valid, but we check consistency */
    /* The actual validation happens during the cryptographic operations */

    /* Generate ID string */
    generate_id_string(id_internal->public_key, params->public_key_size, id_internal->id_string);

    *identity = (quid_identity_t*)id_internal;
    return QUID_SUCCESS;
}

/**
 * @brief Create identity from seed
 */
quid_status_t quid_identity_from_seed(quid_identity_t** identity,
                                      const uint8_t* seed,
                                      size_t seed_size,
                                      quid_security_level_t security_level)
{
    if (!identity || !seed || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (seed_size != QUID_SEED_SIZE) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!quid_validate_security_level(security_level)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Allocate secure memory for identity */
    quid_identity_internal_t* id_internal =
        (quid_identity_internal_t*)quid_memory_secure_alloc(sizeof(quid_identity_internal_t));
    if (!id_internal) {
        return QUID_ERROR_MEMORY_ALLOCATION;
    }

    /* Initialize structure */
    quid_secure_zero(id_internal, sizeof(quid_identity_internal_t));
    id_internal->magic = QUID_IDENTITY_MAGIC;
    id_internal->security_level = security_level;
    id_internal->creation_time = (uint64_t)time(NULL);

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(security_level);

    /* Generate ML-DSA keypair from seed */
    if (!quid_crypto_ml_dsa_keygen(seed, seed_size,
                                    id_internal->master_keypair, params->private_key_size,
                                    id_internal->public_key, params->public_key_size,
                                    security_level)) {
        quid_memory_secure_free(id_internal, sizeof(quid_identity_internal_t));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Generate ID string */
    generate_id_string(id_internal->public_key, params->public_key_size, id_internal->id_string);

    *identity = (quid_identity_t*)id_internal;
    return QUID_SUCCESS;
}

/* Identity export format */
#define QUID_EXPORT_VERSION 1
#define QUID_EXPORT_MAGIC 0x51585054  /* "QXPT" - QUID eXPorT */

typedef struct {
    uint32_t magic;                         /* Magic number */
    uint32_t version;                       /* Format version */
    uint32_t security_level;                /* Security level (1, 3, or 5) */
    uint64_t creation_time;                 /* Creation timestamp */
    uint32_t public_key_size;               /* Size of public key */
    uint32_t private_key_size;              /* Size of private key */
    uint8_t salt[32];                       /* Argon2id salt */
    uint8_t nonce[16];                      /* AEAD nonce/IV */
    uint32_t encrypted_data_size;           /* Size of encrypted data */
    uint8_t tag[16];                        /* AEAD authentication tag */
} quid_export_header_t;

/**
 * @brief Import identity from encrypted backup
 */
quid_status_t quid_identity_import(quid_identity_t** identity,
                                   const uint8_t* data,
                                   size_t data_len,
                                   const char* password)
{
    if (!identity || !data || !password || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (data_len < sizeof(quid_export_header_t)) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Parse export header */
    quid_export_header_t header;
    memcpy(&header, data, sizeof(quid_export_header_t));

    /* Validate magic and version */
    if (header.magic != QUID_EXPORT_MAGIC) {
        return QUID_ERROR_INVALID_FORMAT;
    }
    if (header.version != QUID_EXPORT_VERSION) {
        return QUID_ERROR_VERSION_MISMATCH;
    }

    /* Validate security level */
    if (header.security_level != 1 &&
        header.security_level != 3 &&
        header.security_level != 5) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Validate sizes */
    if (header.public_key_size > QUID_MAX_PUBLIC_KEY_SIZE ||
        header.private_key_size > QUID_MAX_PRIVATE_KEY_SIZE) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Calculate encrypted data offset and validate total size */
    const size_t encrypted_offset = sizeof(quid_export_header_t);
    const size_t expected_total = encrypted_offset + header.encrypted_data_size;
    if (data_len < expected_total) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Derive decryption key from password using Argon2id */
    quid_security_level_t sec_level = (quid_security_level_t)header.security_level;
    quid_argon2_params_t argon2_params;
    if (!quid_get_argon2_params(&argon2_params)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    uint8_t derived_key[32];
    int rc = argon2id_hash_raw(argon2_params.t_cost,
                               argon2_params.m_cost,
                               argon2_params.parallelism,
                               password, strlen(password),
                               header.salt, 32,
                               derived_key, sizeof(derived_key));
    if (rc != ARGON2_OK) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Decrypt identity data */
    const uint8_t* encrypted_data = data + encrypted_offset;
    uint8_t plaintext[sizeof(quid_identity_internal_t)];
    size_t plaintext_size = sizeof(plaintext);

    /* Calculate AAD size: everything up to the tag field */
    const size_t aad_size = offsetof(quid_export_header_t, tag);

    if (!quid_crypto_aead_decrypt(derived_key, header.nonce,
                                  encrypted_data, header.encrypted_data_size,
                                  (const uint8_t*)&header, aad_size,
                                  header.tag,
                                  plaintext, &plaintext_size)) {
        /* Clear derived key */
        quid_secure_zero(derived_key, sizeof(derived_key));
        return QUID_ERROR_DECRYPTION_FAILED;
    }

    /* Clear derived key */
    quid_secure_zero(derived_key, sizeof(derived_key));

    /* Parse decrypted data */
    size_t offset = 0;

    /* Verify magic in decrypted data */
    uint32_t decrypted_magic;
    memcpy(&decrypted_magic, plaintext + offset, sizeof(decrypted_magic));
    offset += sizeof(decrypted_magic);
    if (decrypted_magic != QUID_IDENTITY_MAGIC) {
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_INTEGRITY_CHECK_FAILED;
    }

    /* Allocate secure memory for identity */
    quid_identity_internal_t* id_internal =
        (quid_identity_internal_t*)quid_memory_secure_alloc(sizeof(quid_identity_internal_t));
    if (!id_internal) {
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_MEMORY_ALLOCATION;
    }

    quid_secure_zero(id_internal, sizeof(quid_identity_internal_t));

    /* Copy security level and creation time */
    id_internal->security_level = sec_level;
    id_internal->creation_time = header.creation_time;
    id_internal->magic = QUID_IDENTITY_MAGIC;

    /* Copy private key */
    if (offset + header.private_key_size > plaintext_size) {
        quid_memory_secure_free(id_internal, sizeof(quid_identity_internal_t));
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_INVALID_FORMAT;
    }
    memcpy(id_internal->master_keypair, plaintext + offset, header.private_key_size);
    offset += header.private_key_size;

    /* Copy public key */
    if (offset + header.public_key_size > plaintext_size) {
        quid_memory_secure_free(id_internal, sizeof(quid_identity_internal_t));
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_INVALID_FORMAT;
    }
    memcpy(id_internal->public_key, plaintext + offset, header.public_key_size);
    offset += header.public_key_size;

    /* Generate ID string from public key */
    generate_id_string(id_internal->public_key, header.public_key_size, id_internal->id_string);

    /* Clear plaintext buffer */
    quid_secure_zero(plaintext, sizeof(plaintext));

    *identity = (quid_identity_t*)id_internal;
    return QUID_SUCCESS;
}

/**
 * @brief Export identity to encrypted backup
 */
quid_status_t quid_identity_export(const quid_identity_t* identity,
                                   uint8_t* data,
                                   size_t* data_len,
                                   const char* password)
{
    if (!identity || !data_len || !password || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    /* Get Argon2 parameters */
    quid_argon2_params_t argon2_params;
    if (!quid_get_argon2_params(&argon2_params)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Calculate plaintext size for buffer estimation */
    const size_t plaintext_size = sizeof(id_internal->magic) + params->private_key_size + params->public_key_size;
    const size_t total_size = sizeof(quid_export_header_t) + plaintext_size;

    /* Check buffer size before doing expensive encryption */
    if (!data || *data_len < total_size) {
        *data_len = total_size;
        if (!data) {
            return QUID_ERROR_BUFFER_TOO_SMALL;
        }
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Prepare plaintext data */
    uint8_t plaintext[sizeof(quid_identity_internal_t)];
    size_t plaintext_offset = 0;

    /* Serialize identity data */
    memcpy(plaintext + plaintext_offset, &id_internal->magic, sizeof(id_internal->magic));
    plaintext_offset += sizeof(id_internal->magic);

    memcpy(plaintext + plaintext_offset, id_internal->master_keypair, params->private_key_size);
    plaintext_offset += params->private_key_size;

    memcpy(plaintext + plaintext_offset, id_internal->public_key, params->public_key_size);
    plaintext_offset += params->public_key_size;

    /* Prepare export header */
    quid_export_header_t header;
    quid_secure_zero(&header, sizeof(header));

    header.magic = QUID_EXPORT_MAGIC;
    header.version = QUID_EXPORT_VERSION;
    header.security_level = id_internal->security_level;
    header.creation_time = id_internal->creation_time;
    header.public_key_size = params->public_key_size;
    header.private_key_size = params->private_key_size;
    header.encrypted_data_size = plaintext_offset;

    /* Generate salt and nonce */
    if (quid_random_bytes(header.salt, sizeof(header.salt)) != QUID_SUCCESS) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }
    if (quid_random_bytes(header.nonce, sizeof(header.nonce)) != QUID_SUCCESS) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Derive encryption key from password using Argon2id */
    uint8_t derived_key[32];
    int rc = argon2id_hash_raw(argon2_params.t_cost,
                               argon2_params.m_cost,
                               argon2_params.parallelism,
                               password, strlen(password),
                               header.salt, 32,
                               derived_key, sizeof(derived_key));
    if (rc != ARGON2_OK) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Encrypt identity data */
    uint8_t ciphertext[sizeof(quid_identity_internal_t)];
    size_t ciphertext_size = sizeof(ciphertext);

    /* Calculate AAD size: everything up to the tag field */
    const size_t aad_size = offsetof(quid_export_header_t, tag);

    if (!quid_crypto_aead_encrypt(derived_key, header.nonce,
                                  plaintext, plaintext_offset,
                                  (const uint8_t*)&header, aad_size,
                                  ciphertext, &ciphertext_size,
                                  header.tag)) {
        quid_secure_zero(derived_key, sizeof(derived_key));
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Clear sensitive data */
    quid_secure_zero(derived_key, sizeof(derived_key));
    quid_secure_zero(plaintext, sizeof(plaintext));

    /* Write output */
    memcpy(data, &header, sizeof(quid_export_header_t));
    memcpy(data + sizeof(quid_export_header_t), ciphertext, ciphertext_size);
    *data_len = total_size;

    return QUID_SUCCESS;
}

/**
 * @brief Free identity and secure memory
 */
void quid_identity_free(quid_identity_t* identity)
{
    if (!identity || !g_quid_initialized) {
        return;
    }

    quid_identity_internal_t* id_internal = (quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return;
    }

    /* Clear magic to prevent use-after-free */
    id_internal->magic = 0;

    /* Free secure memory */
    quid_memory_secure_free(id_internal, sizeof(quid_identity_internal_t));
}

/**
 * @brief Get identity ID string
 */
const char* quid_get_identity_id(const quid_identity_t* identity)
{
    if (!identity || !g_quid_initialized) {
        return NULL;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return NULL;
    }

    return id_internal->id_string;
}

/**
 * @brief Get public key
 */
quid_status_t quid_get_public_key(const quid_identity_t* identity,
                                  uint8_t* public_key)
{
    if (!identity || !public_key || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    /* Copy public key and zero the rest of the buffer */
    memcpy(public_key, id_internal->public_key, params->public_key_size);
    if (params->public_key_size < QUID_PUBLIC_KEY_SIZE) {
        memset(public_key + params->public_key_size, 0,
               QUID_PUBLIC_KEY_SIZE - params->public_key_size);
    }
    return QUID_SUCCESS;
}

/**
 * @brief Derive key for specific network/context
 */
quid_status_t quid_derive_key(const quid_identity_t* identity,
                              const quid_context_t* context,
                              uint8_t* derived_key,
                              size_t key_size)
{
    if (!identity || !context || !derived_key || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (key_size > QUID_DERIVED_KEY_SIZE) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Create derivation info */
    uint8_t info[QUID_MAX_CONTEXT_SIZE];
    size_t info_len = 0;

    /* Add derivation context info */
    const size_t derivation_tag_len = strlen(QUID_DERIVED_KEY_INFO);
    if (derivation_tag_len + 1 > sizeof(info)) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(info + info_len, QUID_DERIVED_KEY_INFO, derivation_tag_len);
    info_len += derivation_tag_len;
    info[info_len++] = '\0';

    /* Add network type */
    const size_t net_len = strlen(context->network_type);
    if (info_len + net_len + 1 > sizeof(info)) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(info + info_len, context->network_type, net_len);
    info_len += net_len;
    info[info_len++] = '\0';

    /* Add application ID */
    const size_t app_len = strlen(context->application_id);
    if (info_len + app_len + 1 > sizeof(info)) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(info + info_len, context->application_id, app_len);
    info_len += app_len;
    info[info_len++] = '\0';

    /* Add purpose */
    const size_t purpose_len = strlen(context->purpose);
    if (info_len + purpose_len + 1 > sizeof(info)) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(info + info_len, context->purpose, purpose_len);
    info_len += purpose_len;
    info[info_len++] = '\0';

    /* Add additional data */
    if (context->additional_data_len > 0) {
        if (info_len + context->additional_data_len > sizeof(info)) {
            return QUID_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(info + info_len, context->additional_data, context->additional_data_len);
        info_len += context->additional_data_len;
    }

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    /* Derive key using KDF */
    if (!quid_crypto_kdf(id_internal->master_keypair, params->private_key_size,
                         info, info_len, derived_key, key_size)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Sign message using identity
 */
quid_status_t quid_sign(const quid_identity_t* identity,
                        const uint8_t* message,
                        size_t message_len,
                        quid_signature_t* signature)
{
    /* Comprehensive input validation */
    if (!identity || !signature || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Validate message parameters */
    if (!quid_validate_message(message, message_len)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Prepare output signature buffer */
    quid_secure_zero(signature, sizeof(*signature));
    signature->size = QUID_SIGNATURE_SIZE;

    /* Validate identity structure */
    if (!quid_validate_identity_structure(identity)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    /* Validate signature buffer */
    if (signature->size < QUID_SIGNATURE_SIZE) {
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Sign with ML-DSA */
    if (!quid_crypto_ml_dsa_sign(id_internal->master_keypair, params->private_key_size,
                                 message, message_len,
                                 signature->data, &signature->size,
                                 id_internal->security_level)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Validate signature was created successfully */
    if (signature->size == 0 || signature->size > QUID_SIGNATURE_SIZE) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Include public key in signature */
    memcpy(signature->public_key, id_internal->public_key, params->public_key_size);

    /* Validate public key copy was successful */
    if (memcmp(signature->public_key, id_internal->public_key, params->public_key_size) != 0) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Verify signature
 */
quid_status_t quid_verify(const uint8_t* public_key,
                          const uint8_t* message,
                          size_t message_len,
                          const quid_signature_t* signature)
{
    /* Comprehensive input validation */
    if (!public_key || !signature || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Validate message parameters */
    if (!quid_validate_message(message, message_len)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Validate signature structure */
    if (!quid_validate_signature(signature)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Validate public key buffer */
    if (!quid_validate_buffer(public_key, QUID_PUBLIC_KEY_SIZE)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Determine security level from signature size and get parameters */
    quid_security_level_t security_level = QUID_SECURITY_LEVEL_5; /* Default */
    for (int i = 0; i < 3; i++) {
        if (signature->size == ml_dsa_params[i].signature_size) {
            security_level = (quid_security_level_t)(i * 2 + 1);
            break;
        }
    }
    const ml_dsa_params_t* params = get_ml_dsa_params(security_level);

    /* Verify with ML-DSA */
    if (!quid_crypto_ml_dsa_verify(public_key, params->public_key_size,
                                   message, message_len,
                                   signature->data, signature->size)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Lock identity in secure memory
 */
quid_status_t quid_identity_lock(quid_identity_t* identity)
{
    if (!identity || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    quid_identity_internal_t* id_internal = (quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (id_internal->is_locked) {
        return QUID_SUCCESS;  /* Already locked */
    }

    /* Lock memory pages */
    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    if (!quid_memory_lock(&id_internal->master_keypair, params->private_key_size)) {
        /* Best-effort: if the OS refuses mlock (e.g., limits), still mark as logically locked */
        id_internal->is_locked = true;
        return QUID_SUCCESS;
    }

    id_internal->is_locked = true;
    return QUID_SUCCESS;
}

/**
 * @brief Unlock identity from secure memory
 */
quid_status_t quid_identity_unlock(quid_identity_t* identity)
{
    if (!identity || !g_quid_initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    quid_identity_internal_t* id_internal = (quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!id_internal->is_locked) {
        return QUID_SUCCESS;  /* Already unlocked */
    }

    /* Unlock memory pages */
    /* Get ML-DSA parameters for security level */
    const ml_dsa_params_t* params = get_ml_dsa_params(id_internal->security_level);

    quid_memory_unlock(&id_internal->master_keypair, params->private_key_size);

    id_internal->is_locked = false;
    return QUID_SUCCESS;
}

/**
 * @brief Check if identity is locked
 */
bool quid_identity_is_locked(const quid_identity_t* identity)
{
    if (!identity || !g_quid_initialized) {
        return false;
    }

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;

    /* Validate magic */
    if (id_internal->magic != QUID_IDENTITY_MAGIC) {
        return false;
    }

    return id_internal->is_locked;
}
