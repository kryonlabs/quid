/**
 * @file backup.c
 * @brief QUID Identity Backup and Restore Implementation
 *
 * Implements encrypted identity backup and restore functionality using
 * strong password-based encryption and secure key derivation.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <stddef.h>

#include <argon2.h>
#include <openssl/evp.h>

#include "quid/quid.h"
#include "../utils/crypto.h"
#include "../utils/memory.h"
#include "../utils/random.h"
#include "../utils/constants.h"
#include "identity_internal.h"

/* Backup format constants */
#define QUID_BACKUP_VERSION 2
#define QUID_BACKUP_MAGIC "QUID"

/* Backup format fields */
typedef struct {
    char magic[4];                   /* "QUID" */
    uint32_t version;                /* Backup format version */
    char timestamp[32];              /* ISO 8601 timestamp */
    char identity_id[QUID_ID_ID_SIZE]; /* Identity ID */
    quid_security_level_t security_level; /* Security level */
    uint32_t encrypted_data_size;    /* Size of encrypted identity data */
    uint8_t salt[32];                /* PBKDF salt */
    uint32_t argon2_time_cost;       /* Argon2 time cost */
    uint32_t argon2_memory_kib;      /* Argon2 memory cost */
    uint32_t argon2_parallelism;     /* Argon2 parallelism */
    uint8_t iv[16];                  /* AES-GCM initialization vector */
    uint8_t tag[16];                 /* AES-GCM authentication tag */
    char comment[128];               /* User-provided comment */
    uint8_t reserved[128];           /* Reserved for future use */
} quid_backup_header_t;

/* Encrypted identity data */
typedef struct {
    uint8_t master_keypair[QUID_MASTER_KEY_SIZE];
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
    char id_string[QUID_ID_ID_SIZE];
    quid_security_level_t security_level;
    uint64_t creation_time;
    uint8_t additional_data[256];    /* Additional metadata */
    size_t additional_data_size;
} quid_identity_backup_data_t;

/**
 * @brief Generate current timestamp string
 */
static void generate_timestamp(char timestamp[32])
{
    time_t now = time(NULL);
    struct tm* tm_info = gmtime(&now);
    if (tm_info) {
        snprintf(timestamp, 32, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    } else {
        strcpy(timestamp, "1970-01-01T00:00:00Z");
    }
}

/**
 * @brief Derive encryption key from password
 */
static bool derive_encryption_key(const char* password,
                                  const uint8_t* salt,
                                  uint32_t time_cost,
                                  uint32_t memory_kib,
                                  uint32_t parallelism,
                                  uint8_t* key,
                                  size_t key_size)
{
    if (!password || !salt || !key || key_size == 0) {
        return false;
    }

    int rc = argon2id_hash_raw(time_cost, memory_kib, parallelism,
                               password, strlen(password),
                               salt, 32,
                               key, key_size);
    return rc == ARGON2_OK;
}

/**
 * @brief Encrypt identity data with AES-256-GCM
 */
static bool encrypt_identity_data(const uint8_t* plaintext,
                                  size_t plaintext_size,
                                  const uint8_t* key,
                                  const uint8_t* iv,
                                  const uint8_t* aad,
                                  size_t aad_size,
                                  uint8_t* ciphertext,
                                  size_t* ciphertext_size,
                                  uint8_t* tag)
{
    if (!plaintext || !key || !iv || !ciphertext || !ciphertext_size || !tag) {
        return false;
    }

    return quid_crypto_aead_encrypt(key, iv,
                                   plaintext, plaintext_size,
                                   aad, aad_size,
                                   ciphertext, ciphertext_size, tag);
}

/**
 * @brief Decrypt identity data with AES-256-GCM
 */
static bool decrypt_identity_data(const uint8_t* ciphertext,
                                  size_t ciphertext_size,
                                  const uint8_t* key,
                                  const uint8_t* iv,
                                  const uint8_t* tag,
                                  const uint8_t* aad,
                                  size_t aad_size,
                                  uint8_t* plaintext,
                                  size_t* plaintext_size)
{
    if (!ciphertext || !key || !iv || !tag || !plaintext || !plaintext_size) {
        return false;
    }

    return quid_crypto_aead_decrypt(key, iv,
                                   ciphertext, ciphertext_size,
                                   aad, aad_size,
                                   tag, plaintext, plaintext_size);
}

/**
 * @brief Serialize backup header to bytes
 */
static void serialize_header(const quid_backup_header_t* header, uint8_t* buffer)
{
    memcpy(buffer, header, sizeof(quid_backup_header_t));
}

/**
 * @brief Deserialize backup header from bytes
 */
static void deserialize_header(const uint8_t* buffer, quid_backup_header_t* header)
{
    memcpy(header, buffer, sizeof(quid_backup_header_t));
}

/**
 * @brief Backup identity to encrypted format
 */
quid_status_t quid_identity_backup(const quid_identity_t* identity,
                                   const char* password,
                                   const char* comment,
                                   uint8_t* backup_data,
                                   size_t* backup_data_size)
{
    if (!identity || !password || !backup_data || !backup_data_size) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    quid_argon2_params_t argon2_params;
    if (!quid_get_argon2_params(&argon2_params)) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Prepare identity backup data */
    quid_identity_backup_data_t identity_data = {0};

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;
    if (!id_internal || id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    size_t pk_size, sk_size, sig_size;
    QUID_MLDSA_PARAMS(id_internal->security_level, &pk_size, &sk_size, &sig_size);

    /* Calculate plaintext and required buffer sizes */
    const size_t plaintext_size = sk_size + pk_size +
                                  sizeof(identity_data.id_string) +
                                  sizeof(identity_data.security_level) +
                                  sizeof(identity_data.creation_time) +
                                  sizeof(identity_data.additional_data_size) +
                                  identity_data.additional_data_size;
    const size_t required_size = sizeof(quid_backup_header_t) + plaintext_size;

    if (plaintext_size > QUID_BACKUP_MAX_SIZE || required_size > QUID_BACKUP_MAX_SIZE) {
        *backup_data_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    if (*backup_data_size < required_size) {
        *backup_data_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Copy private/public data */
    memcpy(identity_data.master_keypair, id_internal->master_keypair, sk_size);
    memcpy(identity_data.public_key, id_internal->public_key, pk_size);
    strncpy(identity_data.id_string, id_internal->id_string, sizeof(identity_data.id_string) - 1);
    identity_data.creation_time = id_internal->creation_time;
    identity_data.security_level = id_internal->security_level;
    identity_data.additional_data_size = 0;

    /* Prepare backup header */
    quid_backup_header_t header = {0};
    memcpy(header.magic, QUID_BACKUP_MAGIC, 4);
    header.version = QUID_BACKUP_VERSION;
    generate_timestamp(header.timestamp);
    strncpy(header.identity_id, identity_data.id_string, sizeof(header.identity_id) - 1);
    header.security_level = identity_data.security_level;
    header.encrypted_data_size = sizeof(quid_identity_backup_data_t);
    header.argon2_time_cost = argon2_params.t_cost;
    header.argon2_memory_kib = argon2_params.m_cost;
    header.argon2_parallelism = argon2_params.parallelism;
    const size_t header_aad_size = offsetof(quid_backup_header_t, tag);

    /* Generate random salt and IV */
    quid_status_t status = quid_random_bytes(header.salt, sizeof(header.salt));
    if (status != QUID_SUCCESS) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    status = quid_random_bytes(header.iv, sizeof(header.iv));
    if (status != QUID_SUCCESS) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Copy user comment */
    if (comment) {
        strncpy(header.comment, comment, sizeof(header.comment) - 1);
    }

    /* Derive encryption key from password */
    uint8_t encryption_key[32];
    if (!derive_encryption_key(password, header.salt,
                               header.argon2_time_cost, header.argon2_memory_kib,
                               header.argon2_parallelism,
                               encryption_key, sizeof(encryption_key))) {
        quid_secure_zero(encryption_key, sizeof(encryption_key));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Build plaintext payload with only the used key material */
    uint8_t plaintext[QUID_BACKUP_MAX_SIZE];
    size_t offset = 0;
    memcpy(plaintext + offset, identity_data.master_keypair, sk_size);
    offset += sk_size;
    memcpy(plaintext + offset, identity_data.public_key, pk_size);
    offset += pk_size;
    memcpy(plaintext + offset, identity_data.id_string, sizeof(identity_data.id_string));
    offset += sizeof(identity_data.id_string);
    memcpy(plaintext + offset, &identity_data.security_level, sizeof(identity_data.security_level));
    offset += sizeof(identity_data.security_level);
    memcpy(plaintext + offset, &identity_data.creation_time, sizeof(identity_data.creation_time));
    offset += sizeof(identity_data.creation_time);
    memcpy(plaintext + offset, &identity_data.additional_data_size, sizeof(identity_data.additional_data_size));
    offset += sizeof(identity_data.additional_data_size);
    if (identity_data.additional_data_size > 0) {
        memcpy(plaintext + offset, identity_data.additional_data, identity_data.additional_data_size);
        offset += identity_data.additional_data_size;
    }

    if (offset != plaintext_size) {
        quid_secure_zero(encryption_key, sizeof(encryption_key));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Encrypt identity data */
    uint8_t* encrypted_data = backup_data + sizeof(quid_backup_header_t);
    size_t encrypted_size = plaintext_size;

    /* Include header (without tag) as associated data to detect tampering */
    header.encrypted_data_size = plaintext_size;

    if (!encrypt_identity_data(plaintext, plaintext_size, encryption_key, header.iv,
                               (const uint8_t*)&header, header_aad_size,
                               encrypted_data, &encrypted_size, header.tag)) {
        quid_secure_zero(encryption_key, sizeof(encryption_key));
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Update header with actual encrypted size */
    header.encrypted_data_size = encrypted_size;

    /* Clear sensitive buffers from memory */
    quid_secure_zero(plaintext, sizeof(plaintext));
    quid_secure_zero(encryption_key, sizeof(encryption_key));

    /* Serialize header to buffer */
    serialize_header(&header, backup_data);

    /* Set actual backup size */
    *backup_data_size = sizeof(quid_backup_header_t) + encrypted_size;

    return QUID_SUCCESS;
}

/**
 * @brief Restore identity from encrypted backup
 */
quid_status_t quid_identity_restore(const uint8_t* backup_data,
                                   size_t backup_data_size,
                                   const char* password,
                                   quid_identity_t** identity)
{
    if (!backup_data || !password || !identity || backup_data_size < sizeof(quid_backup_header_t)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Parse backup header */
    quid_backup_header_t header;
    deserialize_header(backup_data, &header);

    /* Validate backup format */
    if (memcmp(header.magic, QUID_BACKUP_MAGIC, 4) != 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (header.version != QUID_BACKUP_VERSION) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (backup_data_size != sizeof(quid_backup_header_t) + header.encrypted_data_size) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Derive decryption key from password */
    uint8_t decryption_key[32];
    if (!derive_encryption_key(password, header.salt,
                               header.argon2_time_cost, header.argon2_memory_kib,
                               header.argon2_parallelism,
                               decryption_key, sizeof(decryption_key))) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Decrypt identity data */
    if (header.encrypted_data_size > QUID_BACKUP_MAX_SIZE) {
        quid_secure_zero(decryption_key, sizeof(decryption_key));
        return QUID_ERROR_INVALID_FORMAT;
    }

    const size_t header_aad_size = offsetof(quid_backup_header_t, tag);
    uint8_t plaintext[QUID_BACKUP_MAX_SIZE];
    size_t plaintext_size = header.encrypted_data_size;
    const uint8_t* encrypted_data = backup_data + sizeof(quid_backup_header_t);

    if (!decrypt_identity_data(encrypted_data, header.encrypted_data_size,
                               decryption_key, header.iv, header.tag,
                               (const uint8_t*)&header, header_aad_size,
                               plaintext, &plaintext_size)) {
        quid_secure_zero(decryption_key, sizeof(decryption_key));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Clear decryption key from memory */
    quid_secure_zero(decryption_key, sizeof(decryption_key));

    /* Parse decrypted payload */
    size_t pk_size, sk_size, sig_size;
    QUID_MLDSA_PARAMS(header.security_level, &pk_size, &sk_size, &sig_size);

    const size_t minimum_size = sk_size + pk_size +
                                QUID_ID_ID_SIZE +
                                sizeof(quid_security_level_t) +
                                sizeof(uint64_t) +
                                sizeof(size_t);
    if (plaintext_size < minimum_size) {
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_INVALID_FORMAT;
    }

    quid_identity_backup_data_t identity_data = {0};
    size_t offset = 0;
    memcpy(identity_data.master_keypair, plaintext + offset, sk_size);
    offset += sk_size;
    memcpy(identity_data.public_key, plaintext + offset, pk_size);
    offset += pk_size;
    memcpy(identity_data.id_string, plaintext + offset, sizeof(identity_data.id_string));
    offset += sizeof(identity_data.id_string);
    memcpy(&identity_data.security_level, plaintext + offset, sizeof(identity_data.security_level));
    offset += sizeof(identity_data.security_level);
    memcpy(&identity_data.creation_time, plaintext + offset, sizeof(identity_data.creation_time));
    offset += sizeof(identity_data.creation_time);
    memcpy(&identity_data.additional_data_size, plaintext + offset, sizeof(identity_data.additional_data_size));
    offset += sizeof(identity_data.additional_data_size);

    if (identity_data.additional_data_size > sizeof(identity_data.additional_data) ||
        offset + identity_data.additional_data_size > plaintext_size) {
        quid_secure_zero(plaintext, sizeof(plaintext));
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (identity_data.additional_data_size > 0) {
        memcpy(identity_data.additional_data, plaintext + offset, identity_data.additional_data_size);
        offset += identity_data.additional_data_size;
    }

    quid_secure_zero(plaintext, sizeof(plaintext));

    /* Reconstruct identity */
    quid_identity_internal_t* restored =
        (quid_identity_internal_t*)quid_memory_secure_alloc(sizeof(quid_identity_internal_t));
    if (!restored) {
        quid_secure_zero(&identity_data, sizeof(identity_data));
        return QUID_ERROR_MEMORY_ALLOCATION;
    }

    quid_secure_zero(restored, sizeof(quid_identity_internal_t));
    restored->magic = QUID_IDENTITY_MAGIC;
    restored->security_level = identity_data.security_level;
    restored->creation_time = identity_data.creation_time;
    restored->is_locked = false;

    memcpy(restored->master_keypair, identity_data.master_keypair, sk_size);
    memcpy(restored->public_key, identity_data.public_key, pk_size);
    strncpy(restored->id_string, identity_data.id_string, sizeof(restored->id_string) - 1);

    *identity = (quid_identity_t*)restored;

    /* Clear sensitive data */
    quid_secure_zero(&identity_data, sizeof(identity_data));

    return QUID_SUCCESS;
}

/**
 * @brief Verify backup integrity without decrypting
 */
quid_status_t quid_backup_verify(const uint8_t* backup_data,
                                 size_t backup_data_size,
                                 const char* identity_id)
{
    if (!backup_data || backup_data_size < sizeof(quid_backup_header_t)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Parse backup header */
    quid_backup_header_t header;
    deserialize_header(backup_data, &header);

    /* Validate backup format */
    if (memcmp(header.magic, QUID_BACKUP_MAGIC, 4) != 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (header.version != QUID_BACKUP_VERSION) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (backup_data_size != sizeof(quid_backup_header_t) + header.encrypted_data_size) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Verify identity ID if provided */
    if (identity_id && strcmp(identity_id, header.identity_id) != 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Get backup metadata
 */
quid_status_t quid_backup_get_info(const uint8_t* backup_data,
                                  size_t backup_data_size,
                                  char* timestamp,
                                  size_t timestamp_size,
                                  char* identity_id,
                                  size_t identity_id_size,
                                  quid_security_level_t* security_level,
                                  char* comment,
                                  size_t comment_size)
{
    if (!backup_data || backup_data_size < sizeof(quid_backup_header_t)) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Parse backup header */
    quid_backup_header_t header;
    deserialize_header(backup_data, &header);

    /* Validate backup format */
    if (memcmp(header.magic, QUID_BACKUP_MAGIC, 4) != 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Copy metadata if buffers provided */
    if (timestamp && timestamp_size > 0) {
        strncpy(timestamp, header.timestamp, timestamp_size - 1);
        timestamp[timestamp_size - 1] = '\0';
    }

    if (identity_id && identity_id_size > 0) {
        strncpy(identity_id, header.identity_id, identity_id_size - 1);
        identity_id[identity_id_size - 1] = '\0';
    }

    if (security_level) {
        *security_level = header.security_level;
    }

    if (comment && comment_size > 0) {
        strncpy(comment, header.comment, comment_size - 1);
        comment[comment_size - 1] = '\0';
    }

    return QUID_SUCCESS;
}

/**
 * @brief Export backup to base64 format
 */
quid_status_t quid_backup_export_base64(const uint8_t* backup_data,
                                       size_t backup_data_size,
                                       char* base64_output,
                                       size_t* base64_size)
{
    if (!backup_data || !base64_output || !base64_size) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    /* Calculate required size (including null terminator) */
    size_t required_size = 4 * ((backup_data_size + 2) / 3) + 1;
    if (*base64_size < required_size) {
        *base64_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    int encoded_len = EVP_EncodeBlock((unsigned char*)base64_output,
                                      backup_data,
                                      (int)backup_data_size);
    if (encoded_len < 0) {
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    base64_output[encoded_len] = '\0';
    *base64_size = (size_t)encoded_len;

    return QUID_SUCCESS;
}

/**
 * @brief Import backup from base64 format
 */
quid_status_t quid_backup_import_base64(const char* base64_input,
                                       uint8_t* backup_data,
                                       size_t* backup_data_size)
{
    if (!base64_input || !backup_data || !backup_data_size) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    size_t input_len = strlen(base64_input);
    if (input_len == 0 || input_len % 4 != 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    size_t padding = 0;
    for (size_t i = 0; i < input_len; i++) {
        char c = base64_input[i];
        if (c == '=') {
            padding++;
        } else if (!isalnum((unsigned char)c) && c != '+' && c != '/') {
            return QUID_ERROR_INVALID_FORMAT;
        }
    }

    size_t required_size = (input_len / 4) * 3;
    if (*backup_data_size < required_size) {
        *backup_data_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    int decoded_len = EVP_DecodeBlock(backup_data,
                                      (const unsigned char*)base64_input,
                                      (int)input_len);
    if (decoded_len < 0) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (padding > 2) {
        return QUID_ERROR_INVALID_FORMAT;
    }

    decoded_len -= (int)padding;
    *backup_data_size = (size_t)decoded_len;

    return QUID_SUCCESS;
}
