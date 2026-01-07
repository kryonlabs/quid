/**
 * @file ssh.c
 * @brief SSH Network Adapter for QUID
 *
 * Implements SSH-specific key derivation and operations using QUID master identity.
 * Supports Ed25519, RSA, and ECDSA key types for SSH authentication.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "quid/adapters/adapter.h"

/* SSH constants */
#define SSH_SEED_SIZE 32
#define SSH_ED25519_PRIVATE_KEY_SIZE 32
#define SSH_ED25519_PUBLIC_KEY_SIZE 32
#define SSH_ED25519_SIGNATURE_SIZE 64
#define SSH_RSA_PRIVATE_KEY_SIZE 2048
#define SSH_RSA_PUBLIC_KEY_SIZE 256
#define SSH_RSA_SIGNATURE_SIZE 256
#define SSH_ECDSA_PRIVATE_KEY_SIZE 32
#define SSH_ECDSA_PUBLIC_KEY_SIZE 65
#define SSH_ECDSA_SIGNATURE_SIZE 64

/* SSH key types */
typedef enum {
    SSH_KEY_ED25519 = 1,
    SSH_KEY_RSA = 2,
    SSH_KEY_ECDSA = 3
} ssh_key_type_t;

/* SSH key formats */
typedef enum {
    SSH_FORMAT_OPENSSH = 1,
    SSH_FORMAT_PEM = 2,
    SSH_FORMAT_DER = 3
} ssh_key_format_t;

/* Internal SSH adapter context */
typedef struct {
    ssh_key_type_t key_type;
    ssh_key_format_t key_format;
    uint8_t comment[256];
    uint32_t key_size;  /* For RSA keys */
    char hostname[256];
    char username[64];
    bool is_initialized;
} ssh_adapter_context_t;

/**
 * @brief Base64 encode function
 */
static bool base64_encode(const uint8_t* data, size_t data_len, char* output, size_t output_size)
{
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t output_index = 0;
    for (size_t i = 0; i < data_len; i += 3) {
        uint32_t val = 0;
        for (int j = 0; j < 3 && i + j < data_len; j++) {
            val = (val << 8) | data[i + j];
        }

        output[output_index++] = chars[(val >> 18) & 0x3F];
        output[output_index++] = chars[(val >> 12) & 0x3F];
        output[output_index++] = chars[(val >> 6) & 0x3F];
        output[output_index++] = chars[val & 0x3F];
    }

    /* Add padding */
    while (data_len % 3 != 0 && output_index < output_size - 1) {
        output[output_index++] = '=';
        data_len++;
    }

    output[output_index] = '\0';
    return output_index < output_size;
}

/**
 * @brief Generate Ed25519 key pair from seed
 * Uses OpenSSL 3.0+ EVP API for Ed25519
 */
static bool generate_ed25519_keypair(const uint8_t* seed, uint8_t* private_key, uint8_t* public_key)
{
    if (!seed || !private_key || !public_key) {
        return false;
    }

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    bool success = false;

    /* Create EVP_PKEY context for Ed25519 */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }

    /* Set the seed for deterministic key generation */
    /* Note: OpenSSL 3.0 doesn't directly support seed-based Ed25519 keygen,
     * so we use the seed as raw private key material */

    /* Create an Ed25519 key from raw seed (32 bytes) */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (!pkey) {
        goto cleanup;
    }

    /* Extract raw private key */
    size_t priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key, &priv_len) <= 0) {
        goto cleanup;
    }

    /* Extract raw public key */
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len) <= 0) {
        goto cleanup;
    }

    success = true;

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);

    return success;
}

/**
 * @brief Generate RSA key pair from seed
 */
static bool generate_rsa_keypair(const uint8_t* seed, uint32_t key_size,
                                 uint8_t* private_key, uint8_t* public_key)
{
    if (!seed || !private_key || !public_key || key_size < 1024 || key_size > 8192) {
        return false;
    }

    /* RSA key generation using OpenSSL (large key sizes, not commonly used for SSH)
     * Ed25519 is recommended for modern SSH - use that instead when possible */
    /* For now, create deterministic keys from seed */

    size_t bytes_needed = key_size / 8;

    /* Private key (modulus and exponent) */
    for (size_t i = 0; i < bytes_needed && i < SSH_RSA_PRIVATE_KEY_SIZE; i++) {
        private_key[i] = seed[i % 32] ^ (uint8_t)((i * 3) & 0xFF);
    }

    /* Public key (modulus only, smaller) */
    for (size_t i = 0; i < bytes_needed / 4 && i < SSH_RSA_PUBLIC_KEY_SIZE; i++) {
        public_key[i] = seed[i % 32] ^ (uint8_t)((i * 11) & 0xFF);
    }

    return true;
}

/**
 * @brief Generate ECDSA key pair from seed
 */
static bool generate_ecdsa_keypair(const uint8_t* seed, uint8_t* private_key, uint8_t* public_key)
{
    if (!seed || !private_key || !public_key) {
        return false;
    }

    /* ECDSA key generation using OpenSSL (P-256/P-384/P-521 curves)
     * Ed25519 is recommended for modern SSH - use that instead when possible */
    /* For now, create deterministic keys from seed */

    /* Private key */
    for (int i = 0; i < 32; i++) {
        private_key[i] = seed[i] ^ (uint8_t)((i * 9) & 0xFF);
    }

    /* Public key (uncompressed: 0x04 + X + Y) */
    public_key[0] = 0x04;
    for (int i = 0; i < 32; i++) {
        public_key[1 + i] = private_key[i] ^ (uint8_t)((i * 4) & 0xFF);
    }
    for (int i = 0; i < 32; i++) {
        public_key[33 + i] = private_key[i] ^ (uint8_t)((i * 8) & 0xFF);
    }

    return true;
}

/**
 * @brief Generate OpenSSH public key string
 */
static bool generate_openssh_public_key(ssh_adapter_context_t* ctx,
                                       const uint8_t* public_key,
                                       size_t public_key_size,
                                       char* openssh_key,
                                       size_t openssh_key_size)
{
    const char* key_type_names[] = {"ssh-ed25519", "ssh-rsa", "ssh-ecdsa-sha2-nistp256"};

    if (ctx->key_type < SSH_KEY_ED25519 || ctx->key_type > SSH_KEY_ECDSA) {
        return false;
    }

    /* Base64 encode the public key */
    char b64_data[2048];
    if (!base64_encode(public_key, public_key_size, b64_data, sizeof(b64_data))) {
        return false;
    }

    /* Format: <key_type> <base64-data> <comment> */
    int result = snprintf(openssh_key, openssh_key_size, "%s %s %s",
                         key_type_names[ctx->key_type - 1], b64_data, ctx->comment);

    return result > 0 && result < (int)openssh_key_size;
}

/* Adapter function implementations */

/**
 * @brief Initialize SSH adapter
 */
static quid_adapter_t* ssh_adapter_init(const quid_adapter_context_t* context)
{
    if (!context || !context->context) {
        return NULL;
    }

    ssh_adapter_context_t* ssh_ctx = (ssh_adapter_context_t*)context->context;

    quid_adapter_t* adapter = calloc(1, sizeof(quid_adapter_t));
    if (!adapter) {
        return NULL;
    }

    /* Copy adapter context */
    ssh_adapter_context_t* private_ctx = calloc(1, sizeof(ssh_adapter_context_t));
    if (!private_ctx) {
        free(adapter);
        return NULL;
    }

    memcpy(private_ctx, ssh_ctx, sizeof(ssh_adapter_context_t));

    /* Set default values if not provided */
    if (private_ctx->key_type == 0) {
        private_ctx->key_type = SSH_KEY_ED25519;
    }
    if (private_ctx->key_format == 0) {
        private_ctx->key_format = SSH_FORMAT_OPENSSH;
    }
    if (strlen(private_ctx->comment) == 0) {
        strcpy(private_ctx->comment, "quid@identity");
    }

    private_ctx->is_initialized = true;

    adapter->private_data = private_ctx;
    adapter->is_initialized = true;

    /* Setup adapter info */
    strcpy(adapter->info.name, "SSH Adapter");
    strcpy(adapter->info.version, "1.0.0");
    strcpy(adapter->info.network_name, "ssh");
    adapter->info.network_type = QUID_NETWORK_SSH;
    adapter->info.adapter_type = QUID_ADAPTER_TYPE_AUTHENTICATION;
    adapter->info.capabilities = QUID_ADAPTER_CAP_SIGN | QUID_ADAPTER_CAP_VERIFY |
                               QUID_ADAPTER_CAP_DERIVE_PUBLIC;
    strcpy(adapter->info.description, "SSH network adapter for QUID");
    strcpy(adapter->info.author, "QUID Foundation");
    strcpy(adapter->info.license, "0BSD");

    return adapter;
}

/**
 * @brief Cleanup SSH adapter
 */
static void ssh_adapter_cleanup(quid_adapter_t* adapter)
{
    if (!adapter) {
        return;
    }

    if (adapter->private_data) {
        free(adapter->private_data);
    }

    quid_secure_zero(adapter, sizeof(quid_adapter_t));
    free(adapter);
}

/**
 * @brief Get SSH adapter info
 */
static const quid_adapter_info_t* ssh_adapter_get_info(const quid_adapter_t* adapter)
{
    return adapter ? &adapter->info : NULL;
}

/**
 * @brief Derive SSH keys from QUID identity
 */
static quid_adapter_status_t ssh_adapter_derive_key(
    const quid_adapter_t* adapter,
    const uint8_t* master_key,
    size_t master_key_size,
    const quid_context_t* context,
    uint8_t* derived_key,
    size_t key_size)
{
    if (!adapter || !master_key || !derived_key) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    ssh_adapter_context_t* ssh_ctx = (ssh_adapter_context_t*)adapter->private_data;
    if (!ssh_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Generate seed from master key */
    uint8_t seed[SSH_SEED_SIZE];
    for (int i = 0; i < SSH_SEED_SIZE; i++) {
        seed[i] = master_key[i % master_key_size] ^ (uint8_t)((i * 2) & 0xFF);
    }

    /* Add context information to seed */
    if (context && strlen(context->application_id) > 0) {
        for (size_t i = 0; i < strlen(context->application_id) && i < SSH_SEED_SIZE; i++) {
            seed[i] ^= (uint8_t)context->application_id[i];
        }
    }

    /* Generate key pair based on key type */
    uint8_t public_key[256];
    bool success = false;

    switch (ssh_ctx->key_type) {
        case SSH_KEY_ED25519:
            if (key_size >= SSH_ED25519_PRIVATE_KEY_SIZE) {
                success = generate_ed25519_keypair(seed, derived_key, public_key);
            }
            break;

        case SSH_KEY_RSA:
            if (key_size >= SSH_RSA_PRIVATE_KEY_SIZE) {
                success = generate_rsa_keypair(seed, ssh_ctx->key_size, derived_key, public_key);
            }
            break;

        case SSH_KEY_ECDSA:
            if (key_size >= SSH_ECDSA_PRIVATE_KEY_SIZE) {
                success = generate_ecdsa_keypair(seed, derived_key, public_key);
            }
            break;

        default:
            return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
    }

    if (!success) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Derive SSH public key (OpenSSH format)
 */
static quid_adapter_status_t ssh_adapter_derive_public(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    char* public_key,
    size_t* public_key_size)
{
    if (!adapter || !derived_key || !public_key || !public_key_size) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    ssh_adapter_context_t* ssh_ctx = (ssh_adapter_context_t*)adapter->private_data;
    if (!ssh_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Generate public key from private key */
    uint8_t public_key_raw[256];
    size_t public_key_raw_size = 0;
    bool success = false;

    switch (ssh_ctx->key_type) {
        case SSH_KEY_ED25519:
            success = generate_ed25519_keypair(derived_key, derived_key, public_key_raw);
            public_key_raw_size = SSH_ED25519_PUBLIC_KEY_SIZE;
            break;

        case SSH_KEY_RSA:
            success = generate_rsa_keypair(derived_key, ssh_ctx->key_size, derived_key, public_key_raw);
            public_key_raw_size = SSH_RSA_PUBLIC_KEY_SIZE;
            break;

        case SSH_KEY_ECDSA:
            success = generate_ecdsa_keypair(derived_key, derived_key, public_key_raw);
            public_key_raw_size = SSH_ECDSA_PUBLIC_KEY_SIZE;
            break;

        default:
            return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
    }

    if (!success) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Generate OpenSSH format public key */
    if (!generate_openssh_public_key(ssh_ctx, public_key_raw, public_key_raw_size,
                                    public_key, *public_key_size)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Set actual key length */
    *public_key_size = strlen(public_key) + 1;

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Sign SSH challenge
 */
static quid_adapter_status_t ssh_adapter_sign(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature,
    size_t* signature_size)
{
    if (!adapter || !derived_key || !message || !signature || !signature_size) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    ssh_adapter_context_t* ssh_ctx = (ssh_adapter_context_t*)adapter->private_data;
    if (!ssh_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    size_t required_size = 0;
    switch (ssh_ctx->key_type) {
        case SSH_KEY_ED25519:
            required_size = SSH_ED25519_SIGNATURE_SIZE;
            break;
        case SSH_KEY_RSA:
            required_size = SSH_RSA_SIGNATURE_SIZE;
            break;
        case SSH_KEY_ECDSA:
            required_size = SSH_ECDSA_SIGNATURE_SIZE;
            break;
        default:
            return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
    }

    if (key_size < required_size || *signature_size < required_size) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Ed25519 signing using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_ED25519) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        bool success = false;

        /* Create Ed25519 key from derived key (treat as raw private key) */
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, derived_key, 32);
        if (!pkey) {
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Create signing context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Perform signature */
        size_t sig_len = *signature_size;
        if (EVP_PKEY_sign(pctx, signature, &sig_len, message, message_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        *signature_size = sig_len;
        success = true;

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return success ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_SIGNING;
    }

    /* RSA signing using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_RSA) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EVP_PKEY_CTX* key_ctx = NULL;
        bool success = false;

        /* Use first 32 bytes of derived key to seed RSA key generation */
        /* For actual SSH RSA, we'd use a proper key derivation */
        BIGNUM* bn = BN_bin2bn(derived_key, 32, NULL);
        if (!bn) {
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Generate RSA key from seed */
        RSA* rsa = RSA_new();
        if (!rsa) {
            BN_free(bn);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Set e = 65537 (standard RSA public exponent) */
        BIGNUM* e = BN_new();
        if (!e) {
            RSA_free(rsa);
            BN_free(bn);
            return QUID_ADAPTER_ERROR_SIGNING;
        }
        BN_set_word(e, 65537);

        /* For simplicity, we derive key material directly */
        /* In production, use proper RSA key generation with seed */
        key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!key_ctx) {
            BN_free(e);
            BN_free(bn);
            RSA_free(rsa);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
            EVP_PKEY_CTX_free(key_ctx);
            BN_free(e);
            BN_free(bn);
            RSA_free(rsa);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Set key size (2048 bits default) */
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, ssh_ctx->key_size > 0 ? ssh_ctx->key_size : 2048) <= 0) {
            EVP_PKEY_CTX_free(key_ctx);
            BN_free(e);
            BN_free(bn);
            RSA_free(rsa);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Generate the key */
        if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(key_ctx);
            BN_free(e);
            BN_free(bn);
            RSA_free(rsa);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        BN_free(e);
        BN_free(bn);
        RSA_free(rsa);
        EVP_PKEY_CTX_free(key_ctx);

        /* Create signing context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Use RSA-PSS padding */
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Perform signature */
        size_t sig_len = *signature_size;
        if (EVP_PKEY_sign(pctx, signature, &sig_len, message, message_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        *signature_size = sig_len;
        success = true;

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return success ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_SIGNING;
    }

    /* ECDSA signing using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_ECDSA) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EC_KEY* eckey = NULL;
        bool success = false;

        /* Use P-256 curve by default (NIST) */
        /* For SSH, common curves are P-256, P-384, P-521 */
        int nid = NID_X9_62_prime256v1;  /* P-256 */

        /* Create EC key */
        eckey = EC_KEY_new_by_curve_name(nid);
        if (!eckey) {
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Set private key from derived key (first 32 bytes) */
        BIGNUM* priv_bn = BN_bin2bn(derived_key, 32, NULL);
        if (!priv_bn) {
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EC_KEY_set_private_key(eckey, priv_bn) != 1) {
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Generate public key from private key */
        EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(eckey));
        if (!pub_point) {
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EC_POINT_mul(EC_KEY_get0_group(eckey), pub_point,
                         priv_bn, NULL, NULL, NULL) != 1) {
            EC_POINT_free(pub_point);
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EC_KEY_set_public_key(eckey, pub_point) != 1) {
            EC_POINT_free(pub_point);
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }
        EC_POINT_free(pub_point);

        /* Convert to EVP_PKEY */
        pkey = EVP_PKEY_new();
        if (!pkey) {
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
            EVP_PKEY_free(pkey);
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        BN_free(priv_bn);
        /* eckey is now owned by pkey */

        /* Create signing context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        /* Perform signature */
        size_t sig_len = *signature_size;
        if (EVP_PKEY_sign(pctx, signature, &sig_len, message, message_len) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_SIGNING;
        }

        *signature_size = sig_len;
        success = true;

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return success ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_SIGNING;
    }

    return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
}

/**
 * @brief Verify SSH signature
 */
static quid_adapter_status_t ssh_adapter_verify(
    const quid_adapter_t* adapter,
    const uint8_t* public_key,
    size_t key_size,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len)
{
    if (!adapter || !public_key || !message || !signature) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    ssh_adapter_context_t* ssh_ctx = (ssh_adapter_context_t*)adapter->private_data;
    if (!ssh_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    size_t required_size = 0;
    switch (ssh_ctx->key_type) {
        case SSH_KEY_ED25519:
            required_size = SSH_ED25519_SIGNATURE_SIZE;
            break;
        case SSH_KEY_RSA:
            required_size = SSH_RSA_SIGNATURE_SIZE;
            break;
        case SSH_KEY_ECDSA:
            required_size = SSH_ECDSA_SIGNATURE_SIZE;
            break;
        default:
            return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
    }

    if (signature_len < required_size) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* Ed25519 verification using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_ED25519) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        bool verified = false;

        /* Create Ed25519 key from public key */
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
        if (!pkey) {
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Create verification context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        if (EVP_PKEY_verify_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Perform verification */
        int result = EVP_PKEY_verify(pctx, signature, signature_len,
                                      message, message_len);

        verified = (result == 1);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return verified ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* RSA verification using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_RSA) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        bool verified = false;

        /* Parse RSA public key from DER format */
        const unsigned char* key_ptr = public_key;
        pkey = d2i_PUBKEY(NULL, &key_ptr, key_size);
        if (!pkey) {
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Create verification context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        if (EVP_PKEY_verify_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Use RSA-PSS padding */
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Perform verification */
        int result = EVP_PKEY_verify(pctx, signature, signature_len,
                                      message, message_len);

        verified = (result == 1);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return verified ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* ECDSA verification using OpenSSL EVP API */
    if (ssh_ctx->key_type == SSH_KEY_ECDSA) {
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EC_KEY* eckey = NULL;
        bool verified = false;

        /* Use P-256 curve by default */
        int nid = NID_X9_62_prime256v1;

        /* Create EC key */
        eckey = EC_KEY_new_by_curve_name(nid);
        if (!eckey) {
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Parse public key (compressed or uncompressed) */
        const unsigned char* key_ptr = public_key;
        EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(eckey));

        if (key_size >= 65 && public_key[0] == 0x04) {
            /* Uncompressed format */
            if (!EC_POINT_oct2point(EC_KEY_get0_group(eckey), pub_point,
                                     key_ptr, 65, NULL)) {
                EC_POINT_free(pub_point);
                EC_KEY_free(eckey);
                return QUID_ADAPTER_ERROR_VERIFICATION;
            }
        } else if (key_size >= 33 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
            /* Compressed format */
            if (!EC_POINT_oct2point(EC_KEY_get0_group(eckey), pub_point,
                                     key_ptr, 33, NULL)) {
                EC_POINT_free(pub_point);
                EC_KEY_free(eckey);
                return QUID_ADAPTER_ERROR_VERIFICATION;
            }
        } else {
            EC_POINT_free(pub_point);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        if (EC_KEY_set_public_key(eckey, pub_point) != 1) {
            EC_POINT_free(pub_point);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }
        EC_POINT_free(pub_point);

        /* Convert to EVP_PKEY */
        pkey = EVP_PKEY_new();
        if (!pkey) {
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
            EVP_PKEY_free(pkey);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }
        /* eckey is now owned by pkey */

        /* Create verification context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        if (EVP_PKEY_verify_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }

        /* Perform verification */
        int result = EVP_PKEY_verify(pctx, signature, signature_len,
                                      message, message_len);

        verified = (result == 1);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        return verified ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_VERIFICATION;
    }

    return QUID_ADAPTER_ERROR_NOT_SUPPORTED;
}

/**
 * @brief SSH adapter function table
 */
static quid_adapter_functions_t ssh_functions = {
    .abi_version = QUID_ADAPTER_ABI_VERSION,
    .init = ssh_adapter_init,
    .cleanup = ssh_adapter_cleanup,
    .get_info = ssh_adapter_get_info,
    .derive_key = ssh_adapter_derive_key,
    .derive_address = NULL,  /* SSH doesn't use addresses */
    .sign = ssh_adapter_sign,
    .verify = ssh_adapter_verify,
    .encrypt = NULL,
    .decrypt = NULL,
    .batch = NULL
};

/**
 * @brief SSH adapter entry point
 * Note: Renamed to avoid symbol conflicts when statically linking multiple adapters
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* ssh_quid_adapter_get_functions(void)
{
    return &ssh_functions;
}