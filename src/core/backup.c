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

#include <argon2.h>

#include "quid/quid.h"
#include "../utils/crypto.h"
#include "../utils/memory.h"
#include "../utils/random.h"
#include "../utils/constants.h"
#include "identity_internal.h"

/* Backup format constants */
#define QUID_BACKUP_VERSION 2
#define QUID_BACKUP_MAGIC "QUID"
#define QUID_BACKUP_HEADER_SIZE 256
#define QUID_BACKUP_MAX_SIZE (1024 * 1024)  /* 1MB max backup size */

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
static bool encrypt_identity_data(const quid_identity_backup_data_t* identity_data,
                                  const uint8_t* key,
                                  const uint8_t* iv,
                                  uint8_t* ciphertext,
                                  size_t* ciphertext_size,
                                  uint8_t* tag)
{
    if (!identity_data || !key || !iv || !ciphertext || !ciphertext_size || !tag) {
        return false;
    }

    /* Encrypt the identity data */
    size_t data_size = sizeof(quid_identity_backup_data_t);
    return quid_crypto_aead_encrypt(key, iv,
                                   (const uint8_t*)identity_data, data_size,
                                   NULL, 0,  /* No AAD for now */
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
                                  quid_identity_backup_data_t* identity_data)
{
    if (!ciphertext || !key || !iv || !tag || !identity_data) {
        return false;
    }

    /* Decrypt the identity data */
    size_t output_size = sizeof(quid_identity_backup_data_t);
    return quid_crypto_aead_decrypt(key, iv,
                                   ciphertext, ciphertext_size,
                                   NULL, 0,  /* No AAD for now */
                                   tag, (uint8_t*)identity_data, &output_size);
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

    size_t required_size = sizeof(quid_backup_header_t) + sizeof(quid_identity_backup_data_t) + 32; /* Extra padding */
    if (*backup_data_size < required_size) {
        *backup_data_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    /* Prepare identity backup data */
    quid_identity_backup_data_t identity_data = {0};

    const quid_identity_internal_t* id_internal = (const quid_identity_internal_t*)identity;
    if (!id_internal || id_internal->magic != QUID_IDENTITY_MAGIC) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    size_t pk_size, sk_size, sig_size;
    QUID_MLDSA_PARAMS(id_internal->security_level, &pk_size, &sk_size, &sig_size);

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
    header.argon2_time_cost = 3;
    header.argon2_memory_kib = 1 << 16; /* 64 MiB */
    header.argon2_parallelism = 1;

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

    /* Encrypt identity data */
    uint8_t* encrypted_data = backup_data + sizeof(quid_backup_header_t);
    size_t encrypted_size = sizeof(quid_identity_backup_data_t);

    if (!encrypt_identity_data(&identity_data, encryption_key, header.iv,
                               encrypted_data, &encrypted_size, header.tag)) {
        quid_secure_zero(encryption_key, sizeof(encryption_key));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Update header with actual encrypted size */
    header.encrypted_data_size = encrypted_size;

    /* Clear encryption key from memory */
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
    quid_identity_backup_data_t identity_data;
    const uint8_t* encrypted_data = backup_data + sizeof(quid_backup_header_t);

    if (!decrypt_identity_data(encrypted_data, header.encrypted_data_size,
                               decryption_key, header.iv, header.tag, &identity_data)) {
        quid_secure_zero(decryption_key, sizeof(decryption_key));
        return QUID_ERROR_CRYPTOGRAPHIC;
    }

    /* Clear decryption key from memory */
    quid_secure_zero(decryption_key, sizeof(decryption_key));

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

    size_t pk_size, sk_size, sig_size;
    QUID_MLDSA_PARAMS(restored->security_level, &pk_size, &sk_size, &sig_size);

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

    /* Simple base64 encoding implementation */
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_index = 0;
    size_t input_index = 0;

    /* Calculate required size */
    size_t required_size = ((backup_data_size + 2) / 3) * 4 + 1;
    if (*base64_size < required_size) {
        *base64_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    while (input_index < backup_data_size) {
        uint32_t triple = 0;
        int bytes_in_triple = 0;

        /* Read up to 3 bytes */
        for (int i = 0; i < 3 && input_index < backup_data_size; i++) {
            triple = (triple << 8) | backup_data[input_index++];
            bytes_in_triple++;
        }

        /* Pad the triple if necessary */
        for (int i = bytes_in_triple; i < 3; i++) {
            triple <<= 8;
        }

        /* Output 4 base64 characters */
        for (int i = 18; i >= 0; i -= 6) {
            if (i >= (3 - bytes_in_triple) * 8) {
                base64_output[output_index++] = base64_chars[(triple >> i) & 0x3F];
            } else {
                base64_output[output_index++] = '=';
            }
        }
    }

    base64_output[output_index] = '\0';
    *base64_size = output_index;

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

    /* Simple base64 decoding implementation */
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int base64_decode[256];

    /* Build decode table */
    for (int i = 0; i < 64; i++) {
        base64_decode[(unsigned char)base64_chars[i]] = i;
    }

    size_t input_len = strlen(base64_input);
    size_t output_index = 0;

    /* Calculate required size */
    size_t required_size = (input_len / 4) * 3;
    if (*backup_data_size < required_size) {
        *backup_data_size = required_size;
        return QUID_ERROR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < input_len; i += 4) {
        if (i + 3 >= input_len) break;

        uint32_t quadruple = 0;
        int valid_chars = 4;

        for (int j = 0; j < 4; j++) {
            char c = base64_input[i + j];
            if (c == '=') {
                valid_chars--;
                continue;
            }
            quadruple = (quadruple << 6) | base64_decode[(unsigned char)c];
        }

        /* Output up to 3 bytes */
        for (int j = 16; j >= 0 && valid_chars > 1; j -= 8) {
            if (j >= (4 - valid_chars) * 8) {
                backup_data[output_index++] = (quadruple >> j) & 0xFF;
            }
        }
    }

    *backup_data_size = output_index;
    return QUID_SUCCESS;
}
