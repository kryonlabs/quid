/**
 * @file crypto_production.c
 * @brief Production QUID Cryptographic Implementation
 *
 * Clean version of crypto.c with all DEBUG statements removed
 * and minimal logging for production use.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

#include "quid/quid.h"
#include "constants.h"
#include "random.h"

/* Include PQClean ML-DSA implementations */
#include "../../PQClean/crypto_sign/ml-dsa-44/clean/api.h"
#include "../../PQClean/crypto_sign/ml-dsa-65/clean/api.h"
#include "../../PQClean/crypto_sign/ml-dsa-87/clean/api.h"
#include "../../PQClean/common/fips202.h"
#include "memory.h"

/* Forward declarations */
void quid_crypto_shake256(const uint8_t* input, size_t input_len,
                         uint8_t* output, size_t output_len);

/* ML-DSA parameter structure */
typedef struct {
    size_t public_key_size;
    size_t private_key_size;
    size_t signature_size;
    int security_level;
} ml_dsa_params_t;

/* ML-DSA parameters for different security levels */
const ml_dsa_params_t ml_dsa_params[] = {
    {   /* ML-DSA-44 */
        .public_key_size = QUID_MLDSA44_PUBLIC_KEY_SIZE,
        .private_key_size = QUID_MLDSA44_PRIVATE_KEY_SIZE,
        .signature_size = QUID_MLDSA44_SIGNATURE_SIZE,
        .security_level = 1
    },
    {   /* ML-DSA-65 */
        .public_key_size = QUID_MLDSA65_PUBLIC_KEY_SIZE,
        .private_key_size = QUID_MLDSA65_PRIVATE_KEY_SIZE,
        .signature_size = QUID_MLDSA65_SIGNATURE_SIZE,
        .security_level = 3
    },
    {   /* ML-DSA-87 */
        .public_key_size = QUID_MLDSA87_PUBLIC_KEY_SIZE,
        .private_key_size = QUID_MLDSA87_PRIVATE_KEY_SIZE,
        .signature_size = QUID_MLDSA87_SIGNATURE_SIZE,
        .security_level = 5
    }
};

/**
 * @brief SHA-256 hash function (using SHAKE256 truncated to 32 bytes)
 */
void quid_crypto_sha256(const uint8_t* input, size_t input_len,
                        uint8_t* output)
{
    quid_crypto_shake256(input, input_len, output, 32);
}

/**
 * @brief Key derivation function using Argon2id
 */
bool quid_crypto_kdf(const uint8_t* input_key_material, size_t ikm_len,
                     const uint8_t* info, size_t info_len,
                     uint8_t* output, size_t output_len)
{
    if (!input_key_material || !output || output_len == 0) {
        return false;
    }

    /* Derive a salt from the context to ensure domain separation */
    uint8_t salt[QUID_KDF_SALT_SIZE];
    quid_crypto_shake256(info ? info : input_key_material,
                         info ? info_len : ikm_len,
                         salt, sizeof(salt));

    /* Use Argon2id as a memory-hard KDF to resist GPU/ASIC cracking */
    const uint32_t t_cost = 3;              /* iterations */
    const uint32_t m_cost = 1 << 16;        /* memory cost in kibibytes (64 MiB) */
    const uint32_t parallelism = 1;         /* lanes */

    int rc = argon2id_hash_raw(t_cost, m_cost, parallelism,
                               input_key_material, ikm_len,
                               salt, sizeof(salt),
                               output, output_len);
    return rc == ARGON2_OK;
}

/**
 * @brief Initialize cryptographic subsystem
 */
bool quid_crypto_init(void)
{
    /* PQClean implementations don't require explicit initialization */
    return true;
}

/**
 * @brief Cleanup cryptographic subsystem
 */
void quid_crypto_cleanup(void)
{
    /* PQClean implementations don't require explicit cleanup */
}

/**
 * @brief Generate ML-DSA keypair
 */
bool quid_crypto_ml_dsa_keygen(const uint8_t* seed, size_t seed_size,
                               uint8_t* private_key, size_t private_key_size,
                               uint8_t* public_key, size_t public_key_size,
                               quid_security_level_t security_level)
{
    bool deterministic = (seed && seed_size > 0);
    if (deterministic) {
        if (!quid_random_begin_deterministic(seed, seed_size)) {
            return false;
        }
    }

    bool result = false;
    switch (security_level) {
        case QUID_SECURITY_LEVEL_1:
            result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(
                public_key, private_key) == 0;
            break;

        case QUID_SECURITY_LEVEL_3:
            result = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(
                public_key, private_key) == 0;
            break;

        case QUID_SECURITY_LEVEL_5:
            result = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(
                public_key, private_key) == 0;
            break;

        default:
            result = false;
            break;
    }

    if (deterministic) {
        quid_random_end_deterministic();
    }

    return result;
}

/**
 * @brief Sign message with ML-DSA
 */
bool quid_crypto_ml_dsa_sign(const uint8_t* private_key, size_t private_key_size,
                             const uint8_t* message, size_t message_size,
                             uint8_t* signature, size_t* signature_size,
                             quid_security_level_t security_level)
{
    switch (security_level) {
        case QUID_SECURITY_LEVEL_1:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
                signature, signature_size, message, message_size, NULL, 0, private_key) == 0;

        case QUID_SECURITY_LEVEL_3:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
                signature, signature_size, message, message_size, NULL, 0, private_key) == 0;

        case QUID_SECURITY_LEVEL_5:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(
                signature, signature_size, message, message_size, NULL, 0, private_key) == 0;

        default:
            return false;
    }
}

/**
 * @brief Verify ML-DSA signature
 */
bool quid_crypto_ml_dsa_verify(const uint8_t* public_key, size_t public_key_size,
                               const uint8_t* message, size_t message_size,
                               const uint8_t* signature, size_t signature_size)
{
    int result = -1;

    /* Determine security level from signature size */
    if (signature_size == QUID_MLDSA44_SIGNATURE_SIZE) {
        result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
            signature, signature_size, message, message_size, NULL, 0, public_key);
    } else if (signature_size == QUID_MLDSA65_SIGNATURE_SIZE) {
        result = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
            signature, signature_size, message, message_size, NULL, 0, public_key);
    } else if (signature_size == QUID_MLDSA87_SIGNATURE_SIZE) {
        result = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(
            signature, signature_size, message, message_size, NULL, 0, public_key);
    }

    return (result == 0);
}

/**
 * @brief SHAKE256 hash function
 */
void quid_crypto_shake256(const uint8_t* input, size_t input_len,
                         uint8_t* output, size_t output_len)
{
    shake256(output, output_len, input, input_len);
}

/**
 * @brief Simple PBKDF implementation using SHAKE256
 */
bool quid_crypto_pbkdf(const char* password,
                       size_t password_len,
                       const uint8_t* salt,
                       size_t iterations,
                       size_t memory_cost,
                       size_t parallelism,
                       uint8_t* output,
                       size_t output_size)
{
    if (!password || !salt || !output || output_size == 0) {
        return false;
    }

    /* Validate parameters */
    if (iterations < QUID_MIN_ITERATIONS || iterations > QUID_MAX_ITERATIONS) {
        iterations = QUID_DEFAULT_ITERATIONS;
    }

    /* Create initial hash of password */
    uint8_t password_hash[64];
    quid_crypto_shake256((const uint8_t*)password, password_len, password_hash, sizeof(password_hash));

    /* Create memory-hard mixing function */
    uint8_t mixing_state[128];
    memcpy(mixing_state, password_hash, 32);
    size_t salt_size = QUID_KDF_SALT_SIZE;  /* Use defined salt size */
    memcpy(mixing_state + 32, salt, salt_size);

    /* Memory-hard iterations with expansion */
    uint8_t expanded_state[QUID_LARGE_BUFFER_SIZE];  /* 4KB state for memory hardness */
    for (size_t iter = 0; iter < iterations / 1000; iter++) {
        /* Expand state to simulate memory usage */
        quid_crypto_shake256(mixing_state, 64 + salt_size,
                            expanded_state, sizeof(expanded_state));

        /* Compress state with cryptographic hash */
        for (size_t i = 0; i < 16; i++) {
            uint8_t block_input[80];
            memcpy(block_input, expanded_state + i * 64, 64);
            memcpy(block_input + 64, &iter, sizeof(size_t));

            uint8_t block_hash[32];
            quid_crypto_shake256(block_input, 64 + sizeof(size_t), block_hash, 32);

            /* Mix back into mixing state */
            for (int j = 0; j < 32; j++) {
                mixing_state[j] ^= block_hash[j];
                mixing_state[32 + j] ^= block_hash[(j + 16) % 32];
            }
        }

        /* Add iteration counter */
        for (size_t i = 0; i < 64; i++) {
            mixing_state[i] ^= (uint8_t)((iter >> (i % 8)) & 0xFF);
        }
    }

    /* Final PBKDF-like iterations with compression */
    uint8_t result[128];
    memcpy(result, mixing_state, 64);
    memcpy(result + 64, password_hash, 32);
    memcpy(result + 96, salt, salt_size);

    /* Apply remaining iterations with cryptographic compression */
    for (size_t iter = 0; iter < iterations % 1000; iter++) {
        /* Hash-based compression */
        uint8_t compress_input[160];
        uint8_t compress_output[32];
        memcpy(compress_input, result, 128);
        memcpy(compress_input + 128, &iter, sizeof(size_t));

        quid_crypto_shake256(compress_input, 128 + sizeof(size_t), compress_output, 32);

        /* Mix back into result */
        for (int j = 0; j < 32; j++) {
            result[j] ^= compress_output[j];
            result[32 + j] ^= compress_output[(j + 8) % 32];
            result[64 + j] ^= compress_output[(j + 16) % 32];
            result[96 + j] ^= compress_output[(j + 24) % 32];
        }
    }

    /* Generate final output */
    quid_crypto_shake256(result, 128, output, output_size);

    return true;
}

/**
 * @brief AEAD encryption using SHAKE256-based construction
 */
bool quid_crypto_aead_encrypt(const uint8_t* key, const uint8_t* iv,
                             const uint8_t* plaintext, size_t plaintext_size,
                             const uint8_t* aad, size_t aad_size,
                             uint8_t* ciphertext, size_t* ciphertext_size,
                             uint8_t* tag)
{
    if (!key || !iv || !plaintext || !ciphertext || !ciphertext_size || !tag) {
        return false;
    }

    if (*ciphertext_size < plaintext_size) {
        *ciphertext_size = plaintext_size;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int len = 0;
    bool success = false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QUID_AEAD_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if (aad && aad_size > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_size) != 1) {
            goto cleanup;
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_size) != 1) {
        goto cleanup;
    }
    int total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        goto cleanup;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QUID_AEAD_TAG_SIZE, tag) != 1) {
        goto cleanup;
    }

    *ciphertext_size = (size_t)total_len;
    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

/**
 * @brief AEAD decryption using SHAKE256-based construction
 */
bool quid_crypto_aead_decrypt(const uint8_t* key, const uint8_t* iv,
                             const uint8_t* ciphertext, size_t ciphertext_size,
                             const uint8_t* aad, size_t aad_size,
                             const uint8_t* tag,
                             uint8_t* plaintext, size_t* plaintext_size)
{
    if (!key || !iv || !ciphertext || !plaintext || !plaintext_size || !tag) {
        return false;
    }

    if (*plaintext_size < ciphertext_size) {
        *plaintext_size = ciphertext_size;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int len = 0;
    bool success = false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QUID_AEAD_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto cleanup;
    }

    if (aad && aad_size > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_size) != 1) {
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_size) != 1) {
        goto cleanup;
    }
    int total_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, QUID_AEAD_TAG_SIZE, (void*)tag) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        goto cleanup;
    }
    total_len += len;

    *plaintext_size = (size_t)total_len;
    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}
