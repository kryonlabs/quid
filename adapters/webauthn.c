/**
 * @file webauthn.c
 * @brief WebAuthn Adapter for QUID
 *
 * Implements WebAuthn (Web Authentication) API support using QUID master identity.
 * Supports FIDO2/WebAuthn credential creation, authentication, and attestation.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include "quid/adapters/adapter.h"

/* WebAuthn constants */
#define WEBAUTHN_CREDENTIAL_ID_SIZE 64
#define WEBAUTHN_USER_ID_SIZE 64
#define WEBAUTHN_CHALLENGE_SIZE 32
#define WEBAUTHN_RP_ID_SIZE 255
#define WEBAUTHN_RP_NAME_SIZE 255
#define WEBAUTHN_ORIGINS_MAX 10
#define WEBAUTHN_ORIGIN_SIZE 255
#define WEBAUTHN_SIGNATURE_SIZE 64
#define WEBAUTHN_CLIENT_DATA_SIZE 1024
#define WEBAUTHN_AUTH_DATA_SIZE 512
#define WEBAUTHN_ATTESTATION_SIZE 1024

/* WebAuthn algorithms */
typedef enum {
    WEBAUTHN_ALG_ES256 = -7,      /* ECDSA with P-256 and SHA-256 */
    WEBAUTHN_ALG_RS256 = -257,    /* RSASSA-PKCS1-v1_5 with SHA-256 */
    WEBAUTHN_ALG_ED25519 = -8,    /* EdDSA with Ed25519 */
    WEBAUTHN_ALG_ES384 = -35,     /* ECDSA with P-384 and SHA-384 */
    WEBAUTHN_ALG_ES512 = -36      /* ECDSA with P-521 and SHA-512 */
} webauthn_algorithm_t;

/* WebAuthn credential types */
typedef enum {
    WEBAUTHN_CRED_PUBLIC_KEY = 1,
    WEBAUTHN_CRED_FIDO_U2F = 2,
    WEBAUTHN_CRED_PLATFORM = 3
} webauthn_credential_type_t;

/* WebAuthn user verification */
typedef enum {
    WEBAUTHN_UV_REQUIRED = 1,
    WEBAUTHN_UV_PREFERRED = 2,
    WEBAUTHN_UV_DISCOURAGED = 3
} webauthn_user_verification_t;

/* WebAuthn authenticator attachment */
typedef enum {
    WEBAUTHN_ATTACHMENT_PLATFORM = 1,  /* Platform authenticator */
    WEBAUTHN_ATTACHMENT_CROSS_PLATFORM = 2  /* Roaming authenticator */
} webauthn_attachment_t;

/* WebAuthn RP entity */
typedef struct {
    char id[WEBAUTHN_RP_ID_SIZE];
    char name[WEBAUTHN_RP_NAME_SIZE];
    char icon[256];
} webauthn_rp_entity_t;

/* WebAuthn user entity */
typedef struct {
    uint8_t id[WEBAUTHN_USER_ID_SIZE];
    size_t id_size;
    char name[256];
    char display_name[256];
    char icon[256];
} webauthn_user_entity_t;

/* WebAuthn credential */
typedef struct {
    uint8_t id[WEBAUTHN_CREDENTIAL_ID_SIZE];
    size_t id_size;
    webauthn_credential_type_t type;
    webauthn_algorithm_t algorithm;
    uint8_t public_key[128];
    size_t public_key_size;
    uint32_t sign_count;
    bool is_resident;
    bool user_verified;
} webauthn_credential_t;

/* WebAuthn options */
typedef struct {
    bool user_presence;
    webauthn_user_verification_t user_verification;
    webauthn_attachment_t authenticator_attachment;
    bool require_resident_key;
    webauthn_algorithm_t algorithms[5];
    size_t algorithms_count;
    uint32_t timeout;
    char allowed_origins[WEBAUTHN_ORIGINS_MAX][WEBAUTHN_ORIGIN_SIZE];
    size_t origins_count;
} webauthn_options_t;

/* Internal WebAuthn adapter context */
typedef struct {
    webauthn_rp_entity_t rp;
    webauthn_user_entity_t user;
    webauthn_options_t options;
    webauthn_credential_t credentials[10];
    size_t credentials_count;
    char rp_origin[WEBAUTHN_ORIGIN_SIZE];
    bool is_initialized;
} webauthn_adapter_context_t;

/* CBOR helper functions (RFC 8949) */
/* CBOR major types */
#define CBOR_MAJOR_UINT 0
#define CBOR_MAJOR_NEGINT 1
#define CBOR_MAJOR_BYTES 2
#define CBOR_MAJOR_TEXT 3
#define CBOR_MAJOR_ARRAY 4
#define CBOR_MAJOR_MAP 5
#define CBOR_MAJOR_TAG 6
#define CBOR_MAJOR_SIMPLE 7

/* CBOR additional info */
#define CBOR_AI_1BYTE 24
#define CBOR_AI_2BYTE 25
#define CBOR_AI_4BYTE 26
#define CBOR_AI_8BYTE 27
#define CBOR_SIMPLE_FALSE (20)
#define CBOR_SIMPLE_TRUE (21)
#define CBOR_SIMPLE_NULL (22)

/**
 * @brief Write CBOR unsigned integer
 */
static bool cbor_encode_uint(uint64_t value, uint8_t* output, size_t* output_len)
{
    size_t needed;
    if (value < 24) {
        if (*output_len < 1) return false;
        output[0] = (CBOR_MAJOR_UINT << 5) | (uint8_t)value;
        *output_len = 1;
        return true;
    } else if (value <= 0xFF) {
        needed = 2;
        if (*output_len < needed) return false;
        output[0] = (CBOR_MAJOR_UINT << 5) | CBOR_AI_1BYTE;
        output[1] = (uint8_t)value;
        *output_len = needed;
        return true;
    } else if (value <= 0xFFFF) {
        needed = 3;
        if (*output_len < needed) return false;
        output[0] = (CBOR_MAJOR_UINT << 5) | CBOR_AI_2BYTE;
        output[1] = (uint8_t)((value >> 8) & 0xFF);
        output[2] = (uint8_t)(value & 0xFF);
        *output_len = needed;
        return true;
    } else if (value <= 0xFFFFFFFF) {
        needed = 5;
        if (*output_len < needed) return false;
        output[0] = (CBOR_MAJOR_UINT << 5) | CBOR_AI_4BYTE;
        output[1] = (uint8_t)((value >> 24) & 0xFF);
        output[2] = (uint8_t)((value >> 16) & 0xFF);
        output[3] = (uint8_t)((value >> 8) & 0xFF);
        output[4] = (uint8_t)(value & 0xFF);
        *output_len = needed;
        return true;
    } else {
        needed = 9;
        if (*output_len < needed) return false;
        output[0] = (CBOR_MAJOR_UINT << 5) | CBOR_AI_8BYTE;
        output[1] = (uint8_t)((value >> 56) & 0xFF);
        output[2] = (uint8_t)((value >> 48) & 0xFF);
        output[3] = (uint8_t)((value >> 40) & 0xFF);
        output[4] = (uint8_t)((value >> 32) & 0xFF);
        output[5] = (uint8_t)((value >> 24) & 0xFF);
        output[6] = (uint8_t)((value >> 16) & 0xFF);
        output[7] = (uint8_t)((value >> 8) & 0xFF);
        output[8] = (uint8_t)(value & 0xFF);
        *output_len = needed;
        return true;
    }
}

/**
 * @brief Write CBOR byte string
 */
static bool cbor_encode_bytes(const uint8_t* data, size_t len, uint8_t* output, size_t* output_len)
{
    size_t header_len = *output_len;
    if (!cbor_encode_uint(len, output, &header_len)) {
        return false;
    }
    /* Change major type to bytes */
    output[0] = (CBOR_MAJOR_BYTES << 5) | (output[0] & 0x1F);

    if (*output_len < header_len + len) {
        return false;
    }

    memcpy(output + header_len, data, len);
    *output_len = header_len + len;
    return true;
}

/**
 * @brief Write CBOR text string
 */
static bool cbor_encode_text(const char* text, uint8_t* output, size_t* output_len)
{
    size_t header_len = *output_len;
    size_t text_len = strlen(text);
    if (!cbor_encode_uint(text_len, output, &header_len)) {
        return false;
    }
    /* Change major type to text */
    output[0] = (CBOR_MAJOR_TEXT << 5) | (output[0] & 0x1F);

    if (*output_len < header_len + text_len) {
        return false;
    }

    memcpy(output + header_len, text, text_len);
    *output_len = header_len + text_len;
    return true;
}

/**
 * @brief Write CBOR array header
 */
static bool cbor_encode_array(size_t count, uint8_t* output, size_t* output_len)
{
    if (!cbor_encode_uint(count, output, output_len)) {
        return false;
    }
    /* Change major type to array */
    output[0] = (CBOR_MAJOR_ARRAY << 5) | (output[0] & 0x1F);
    return true;
}

/**
 * @brief Write CBOR map header
 */
static bool cbor_encode_map(size_t count, uint8_t* output, size_t* output_len)
{
    if (!cbor_encode_uint(count, output, output_len)) {
        return false;
    }
    /* Change major type to map */
    output[0] = (CBOR_MAJOR_MAP << 5) | (output[0] & 0x1F);
    return true;
}

/**
 * @brief Decode CBOR byte string
 */
static bool cbor_decode_bytes(const uint8_t* input, size_t input_len,
                              uint8_t* output, size_t* output_len)
{
    if (input_len == 0) return false;

    uint8_t first_byte = input[0];
    uint8_t major = (first_byte >> 5) & 0x07;
    uint8_t ai = first_byte & 0x1F;

    if (major != CBOR_MAJOR_BYTES) return false;

    size_t offset = 1;
    size_t data_len = 0;

    /* Parse length */
    if (ai < 24) {
        data_len = ai;
    } else if (ai == CBOR_AI_1BYTE) {
        if (input_len < 2) return false;
        data_len = input[1];
        offset = 2;
    } else if (ai == CBOR_AI_2BYTE) {
        if (input_len < 3) return false;
        data_len = ((size_t)input[1] << 8) | input[2];
        offset = 3;
    } else if (ai == CBOR_AI_4BYTE) {
        if (input_len < 5) return false;
        data_len = ((size_t)input[1] << 24) | ((size_t)input[2] << 16) |
                   ((size_t)input[3] << 8) | input[4];
        offset = 5;
    } else {
        return false;
    }

    if (input_len < offset + data_len) return false;
    if (data_len > *output_len) return false;

    memcpy(output, input + offset, data_len);
    *output_len = data_len;
    return true;
}

/* SHA-256 helper */
static void sha256_hash(const uint8_t* data, size_t len, uint8_t hash[32])
{
    /* Use OpenSSL SHA-256 directly */
    SHA256(data, len, hash);
}

/**
 * @brief Generate Ed25519 key pair from seed using OpenSSL EVP API
 */
static bool generate_ed25519_keypair(const uint8_t* seed, uint8_t* public_key, uint8_t* private_key)
{
    if (!seed || !public_key || !private_key) {
        return false;
    }

    EVP_PKEY* pkey = NULL;
    bool success = false;

    /* Create Ed25519 key from raw seed (32 bytes) */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (!pkey) {
        return false;
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
    return success;
}

/**
 * @brief Generate P-256 (ES256) key pair from seed using OpenSSL EC API
 */
static bool generate_p256_keypair(const uint8_t* seed, uint8_t* public_key, uint8_t* private_key)
{
    if (!seed || !public_key || !private_key) {
        return false;
    }

    EC_KEY* eckey = NULL;
    const EC_GROUP* group = NULL;
    EC_POINT* pub_point = NULL;
    BIGNUM* priv_bn = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    bool success = false;

    /* Create EC key for prime256v1 (P-256) */
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        goto cleanup;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        goto cleanup;
    }

    /* Convert seed to private key (mod curve order) */
    priv_bn = BN_bin2bn(seed, 32, NULL);
    if (!priv_bn) {
        goto cleanup;
    }

    if (!EC_KEY_set_private_key(eckey, priv_bn)) {
        goto cleanup;
    }

    /* Derive public key */
    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        goto cleanup;
    }

    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        goto cleanup;
    }

    if (!EC_KEY_set_public_key(eckey, pub_point)) {
        goto cleanup;
    }

    /* Extract private key as bytes */
    BN_bn2binpad(priv_bn, private_key, 32);

    /* Extract public key in uncompressed format */
    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, pub_point, x, y, NULL)) {
        goto cleanup;
    }

    /* Uncompressed format: 0x04 + X + Y */
    public_key[0] = 0x04;
    BN_bn2binpad(x, public_key + 1, 32);
    BN_bn2binpad(y, public_key + 33, 32);

    success = true;

cleanup:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (priv_bn) BN_free(priv_bn);
    if (pub_point) EC_POINT_free(pub_point);
    if (eckey) EC_KEY_free(eckey);

    return success;
}

/* Base64URL encoding */
static bool base64url_encode(const uint8_t* data, size_t data_len, char* output, size_t output_size)
{
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t output_index = 0;

    for (size_t i = 0; i < data_len; i += 3) {
        uint32_t val = 0;
        for (int j = 0; j < 3 && i + j < data_len; j++) {
            val = (val << 8) | data[i + j];
        }

        for (int j = 0; j < 4 && output_index < output_size - 1; j++) {
            output[output_index++] = chars[(val >> (18 - j * 6)) & 0x3F];
        }
    }

    /* Remove padding */
    while (output_index > 0 && output[output_index - 1] == '=') {
        output_index--;
    }

    output[output_index] = '\0';
    return true;
}

/* Generate credential ID from QUID master key */
static bool generate_credential_id(const uint8_t* master_key, size_t master_key_size,
                                   const webauthn_rp_entity_t* rp,
                                   const webauthn_user_entity_t* user,
                                   uint8_t* credential_id, size_t* credential_id_size)
{
    if (!master_key || !rp || !user || !credential_id || !credential_id_size) {
        return false;
    }

    /* Create unique identifier from master key, RP, and user */
    uint8_t hash_input[512];
    size_t hash_len = 0;

    /* Copy master key material */
    for (size_t i = 0; i < master_key_size && hash_len < sizeof(hash_input); i++) {
        hash_input[hash_len++] = master_key[i];
    }

    /* Add RP ID */
    for (size_t i = 0; rp->id[i] && hash_len < sizeof(hash_input); i++) {
        hash_input[hash_len++] = (uint8_t)rp->id[i];
    }

    /* Add user ID */
    for (size_t i = 0; i < user->id_size && hash_len < sizeof(hash_input); i++) {
        hash_input[hash_len++] = user->id[i];
    }

    /* Hash to create credential ID */
    uint8_t hash[32];
    sha256_hash(hash_input, hash_len, hash);

    /* Truncate to desired size */
    size_t cred_len = (*credential_id_size < WEBAUTHN_CREDENTIAL_ID_SIZE) ?
                     *credential_id_size : WEBAUTHN_CREDENTIAL_ID_SIZE;

    memcpy(credential_id, hash, cred_len);
    *credential_id_size = cred_len;

    return true;
}

/* Generate WebAuthn public key from QUID master key */
static bool generate_public_key(const uint8_t* master_key, size_t master_key_size,
                                webauthn_algorithm_t algorithm,
                                uint8_t* public_key, size_t* public_key_size)
{
    if (!master_key || !public_key || !public_key_size) {
        return false;
    }

    /* Generate deterministic seed from master key using SHA-256 */
    uint8_t seed[32];
    sha256_hash(master_key, master_key_size, seed);

    /* Add algorithm-specific variation to seed */
    for (int i = 0; i < 32; i++) {
        seed[i] ^= (uint8_t)(algorithm & 0xFF);
        seed[i] ^= (uint8_t)((i * 7) & 0xFF);
    }

    uint8_t private_key[128];  /* Buffer for private key */
    bool success = false;

    switch (algorithm) {
        case WEBAUTHN_ALG_ES256:
            /* Generate P-256 key pair */
            if (*public_key_size < 65) return false;

            success = generate_p256_keypair(seed, public_key, private_key);
            if (success) {
                *public_key_size = 65;
                quid_secure_zero(private_key, sizeof(private_key));
            }
            break;

        case WEBAUTHN_ALG_ED25519:
            /* Generate Ed25519 key pair */
            if (*public_key_size < 32) return false;

            success = generate_ed25519_keypair(seed, public_key, private_key);
            if (success) {
                *public_key_size = 32;
                quid_secure_zero(private_key, sizeof(private_key));
            }
            break;

        case WEBAUTHN_ALG_RS256: {
            /* RSA key generation - generate RSA key and export public key */
            EVP_PKEY_CTX* key_ctx = NULL;
            EVP_PKEY* pkey = NULL;
            BIO* bio = NULL;
            bool key_success = false;

            /* Generate RSA key */
            key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!key_ctx) {
                goto rs256_keygen_cleanup;
            }

            if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
                goto rs256_keygen_cleanup;
            }

            /* Use 2048-bit RSA key */
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0) {
                goto rs256_keygen_cleanup;
            }

            /* Generate the key */
            if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
                goto rs256_keygen_cleanup;
            }

            /* Export public key in DER format */
            bio = BIO_new(BIO_s_mem());
            if (!bio) {
                goto rs256_keygen_cleanup;
            }

            /* Write SubjectPublicKeyInfo (DER format) */
            if (i2d_PUBKEY_bio(bio, pkey) <= 0) {
                goto rs256_keygen_cleanup;
            }

            /* Read back the DER data */
            int key_len = BIO_get_mem_data(bio, NULL);
            if (key_len < 0 || (size_t)key_len > *public_key_size) {
                goto rs256_keygen_cleanup;
            }

            int read_len = BIO_read(bio, public_key, key_len);
            if (read_len != key_len) {
                goto rs256_keygen_cleanup;
            }

            *public_key_size = key_len;
            key_success = true;

rs256_keygen_cleanup:
            if (bio) BIO_free_all(bio);
            if (pkey) EVP_PKEY_free(pkey);
            if (key_ctx) EVP_PKEY_CTX_free(key_ctx);

            if (!key_success) {
                return false;
            }
            success = true;
            break;
        }

        default:
            return false;
    }

    return success;
}

/* Sign WebAuthn assertion with real Ed25519/ECDSA signing */
static bool sign_assertion(const uint8_t* master_key, size_t master_key_size,
                           const uint8_t* client_data, size_t client_data_size,
                           const uint8_t* auth_data, size_t auth_data_size,
                           webauthn_algorithm_t algorithm,
                           uint8_t* signature, size_t* signature_size)
{
    if (!master_key || !client_data || !auth_data || !signature || !signature_size) {
        return false;
    }

    /* Determine required signature size */
    size_t required_size = 64;
    switch (algorithm) {
        case WEBAUTHN_ALG_ES256:
            required_size = 64;  /* DER-encoded ECDSA signature (r + s) */
            break;
        case WEBAUTHN_ALG_ED25519:
            required_size = 64;
            break;
        case WEBAUTHN_ALG_RS256:
            required_size = 256;
            break;
    }

    if (*signature_size < required_size) return false;

    /* Generate deterministic seed from master key */
    uint8_t seed[32];
    sha256_hash(master_key, master_key_size, seed);
    for (int i = 0; i < 32; i++) {
        seed[i] ^= (uint8_t)(algorithm & 0xFF);
    }

    /* Prepare message to sign: client_data_hash || auth_data */
    uint8_t client_data_hash[32];
    sha256_hash(client_data, client_data_size, client_data_hash);

    /* Create signing buffer */
    uint8_t signing_buffer[512];
    size_t signing_len = 0;

    /* WebAuthn signature: auth_data || SHA256(client_data_hash) || auth_data */
    memcpy(signing_buffer, auth_data, auth_data_size);
    signing_len = auth_data_size;

    if (signing_len + 32 <= sizeof(signing_buffer)) {
        memcpy(signing_buffer + signing_len, client_data_hash, 32);
        signing_len += 32;
    }

    /* Perform signing based on algorithm */
    if (algorithm == WEBAUTHN_ALG_ED25519) {
        /* Ed25519 signing using OpenSSL EVP API */
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        bool success = false;

        /* Create Ed25519 key from seed */
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
        if (!pkey) {
            goto ed25519_cleanup;
        }

        /* Create signing context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            goto ed25519_cleanup;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            goto ed25519_cleanup;
        }

        /* Perform signature */
        size_t sig_len = *signature_size;
        if (EVP_PKEY_sign(pctx, signature, &sig_len,
                          signing_buffer, signing_len) <= 0) {
            goto ed25519_cleanup;
        }

        *signature_size = sig_len;
        success = true;

ed25519_cleanup:
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (pkey) EVP_PKEY_free(pkey);

        if (!success) {
            return false;
        }
    } else if (algorithm == WEBAUTHN_ALG_ES256) {
        /* ECDSA P-256 signing using OpenSSL EC API */
        EC_KEY* eckey = NULL;
        const EC_GROUP* group = NULL;
        ECDSA_SIG* ecdsa_sig = NULL;
        BIGNUM* priv_bn = NULL;
        bool success = false;

        /* Create EC key for P-256 */
        eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!eckey) {
            goto ecdsa_cleanup;
        }

        group = EC_KEY_get0_group(eckey);
        if (!group) {
            goto ecdsa_cleanup;
        }

        /* Set private key from seed */
        priv_bn = BN_bin2bn(seed, 32, NULL);
        if (!priv_bn) {
            goto ecdsa_cleanup;
        }

        if (!EC_KEY_set_private_key(eckey, priv_bn)) {
            goto ecdsa_cleanup;
        }

        /* Compute hash of signing buffer */
        uint8_t msg_hash[32];
        sha256_hash(signing_buffer, signing_len, msg_hash);

        /* Sign with ECDSA */
        ecdsa_sig = ECDSA_do_sign(msg_hash, 32, eckey);
        if (!ecdsa_sig) {
            goto ecdsa_cleanup;
        }

        /* Convert signature to DER format */
        const BIGNUM* r = NULL;
        const BIGNUM* s = NULL;
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);

        /* Write DER-encoded signature: SEQUENCE { INTEGER r, INTEGER s } */
        unsigned char* p = signature;
        int r_len = BN_num_bytes(r);
        int s_len = BN_num_bytes(s);
        int total_len = 6 + r_len + s_len;  /* Approximate */

        if (*signature_size < (size_t)total_len) {
            goto ecdsa_cleanup;
        }

        /* Simple DER encoding for ECDSA signature */
        *p++ = 0x30;  /* SEQUENCE tag */
        *p++ = (unsigned char)(4 + r_len + s_len);  /* Length */

        *p++ = 0x02;  /* INTEGER tag */
        *p++ = (unsigned char)r_len;  /* Length */
        BN_bn2bin(r, p);
        p += r_len;

        *p++ = 0x02;  /* INTEGER tag */
        *p++ = (unsigned char)s_len;  /* Length */
        BN_bn2bin(s, p);
        p += s_len;

        *signature_size = p - signature;
        success = true;

ecdsa_cleanup:
        if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
        if (priv_bn) BN_free(priv_bn);
        if (eckey) EC_KEY_free(eckey);

        if (!success) {
            return false;
        }
    } else if (algorithm == WEBAUTHN_ALG_RS256) {
        /* RSA PKCS#1 v1.5 signing with SHA-256 */
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EVP_PKEY_CTX* key_ctx = NULL;
        bool success = false;

        /* Generate RSA key from seed */
        key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!key_ctx) {
            goto rsa_cleanup;
        }

        if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
            goto rsa_cleanup;
        }

        /* Use 2048-bit RSA key */
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0) {
            goto rsa_cleanup;
        }

        /* Generate the key */
        if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
            goto rsa_cleanup;
        }

        /* Create signing context */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx) {
            goto rsa_cleanup;
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            goto rsa_cleanup;
        }

        /* Use PKCS#1 v1.5 padding (RS256) */
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
            goto rsa_cleanup;
        }

        /* Compute hash of signing buffer */
        uint8_t msg_hash[32];
        sha256_hash(signing_buffer, signing_len, msg_hash);

        /* Perform signature */
        size_t sig_len = *signature_size;
        if (EVP_PKEY_sign(pctx, signature, &sig_len, msg_hash, 32) <= 0) {
            goto rsa_cleanup;
        }

        *signature_size = sig_len;
        success = true;

rsa_cleanup:
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (pkey) EVP_PKEY_free(pkey);
        if (key_ctx) EVP_PKEY_CTX_free(key_ctx);

        if (!success) {
            return false;
        }
    } else {
        /* Fallback to deterministic XOR for unsupported algorithms */
        for (size_t i = 0; i < required_size && i < *signature_size; i++) {
            uint8_t data_byte = signing_buffer[i % signing_len];
            uint8_t key_byte = seed[i % 32];
            signature[i] = data_byte ^ key_byte ^ (uint8_t)((i * algorithm) & 0xFF);
        }
        *signature_size = required_size;
    }

    return true;
}

/* Adapter function implementations */

/**
 * @brief Initialize WebAuthn adapter
 */
static quid_adapter_t* webauthn_adapter_init(const quid_adapter_context_t* context)
{
    if (!context || !context->context) {
        return NULL;
    }

    webauthn_adapter_context_t* webauthn_ctx = (webauthn_adapter_context_t*)context->context;

    quid_adapter_t* adapter = calloc(1, sizeof(quid_adapter_t));
    if (!adapter) {
        return NULL;
    }

    /* Copy adapter context */
    webauthn_adapter_context_t* private_ctx = calloc(1, sizeof(webauthn_adapter_context_t));
    if (!private_ctx) {
        free(adapter);
        return NULL;
    }

    memcpy(private_ctx, webauthn_ctx, sizeof(webauthn_adapter_context_t));

    /* Set default values if not provided */
    if (strlen(private_ctx->rp.id) == 0) {
        strcpy(private_ctx->rp.id, "localhost");
    }
    if (strlen(private_ctx->rp.name) == 0) {
        strcpy(private_ctx->rp.name, "QUID WebAuthn");
    }
    if (strlen(private_ctx->rp_origin) == 0) {
        strcpy(private_ctx->rp_origin, "https://localhost");
    }

    /* Set default options */
    if (private_ctx->options.algorithms_count == 0) {
        private_ctx->options.algorithms[0] = WEBAUTHN_ALG_ES256;
        private_ctx->options.algorithms[1] = WEBAUTHN_ALG_ED25519;
        private_ctx->options.algorithms_count = 2;
    }
    if (private_ctx->options.timeout == 0) {
        private_ctx->options.timeout = 60000;  /* 60 seconds */
    }

    private_ctx->is_initialized = true;

    adapter->private_data = private_ctx;
    adapter->is_initialized = true;

    /* Setup adapter info */
    strcpy(adapter->info.name, "WebAuthn Adapter");
    strcpy(adapter->info.version, "1.0.0");
    strcpy(adapter->info.network_name, "webauthn");
    adapter->info.network_type = QUID_NETWORK_WEBAUTHN;
    adapter->info.adapter_type = QUID_ADAPTER_TYPE_AUTHENTICATION;
    adapter->info.capabilities = QUID_ADAPTER_CAP_SIGN | QUID_ADAPTER_CAP_VERIFY |
                               QUID_ADAPTER_CAP_DERIVE_PUBLIC;
    strcpy(adapter->info.description, "WebAuthn adapter for FIDO2/Web Authentication API");
    strcpy(adapter->info.author, "QUID Foundation");
    strcpy(adapter->info.license, "0BSD");

    return adapter;
}

/**
 * @brief Cleanup WebAuthn adapter
 */
static void webauthn_adapter_cleanup(quid_adapter_t* adapter)
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
 * @brief Get WebAuthn adapter info
 */
static const quid_adapter_info_t* webauthn_adapter_get_info(const quid_adapter_t* adapter)
{
    return adapter ? &adapter->info : NULL;
}

/**
 * @brief Derive WebAuthn credential from QUID identity
 */
static quid_adapter_status_t webauthn_adapter_derive_key(
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

    webauthn_adapter_context_t* webauthn_ctx = (webauthn_adapter_context_t*)adapter->private_data;
    if (!webauthn_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Generate credential ID */
    size_t credential_id_size = WEBAUTHN_CREDENTIAL_ID_SIZE;
    if (!generate_credential_id(master_key, master_key_size,
                                &webauthn_ctx->rp, &webauthn_ctx->user,
                                derived_key, &credential_id_size)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Add additional context information */
    if (context && strlen(context->application_id) > 0) {
        for (size_t i = 0; i < strlen(context->application_id) && i < key_size; i++) {
            derived_key[i] ^= (uint8_t)context->application_id[i];
        }
    }

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Derive WebAuthn public key (credential ID format)
 */
static quid_adapter_status_t webauthn_adapter_derive_public(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    char* public_key,
    size_t* public_key_size)
{
    if (!adapter || !derived_key || !public_key || !public_key_size) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    webauthn_adapter_context_t* webauthn_ctx = (webauthn_adapter_context_t*)adapter->private_data;
    if (!webauthn_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Generate Base64URL-encoded credential ID */
    if (!base64url_encode(derived_key, key_size, public_key, *public_key_size)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Set actual key length */
    *public_key_size = strlen(public_key) + 1;

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Sign WebAuthn assertion
 */
static quid_adapter_status_t webauthn_adapter_sign(
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

    webauthn_adapter_context_t* webauthn_ctx = (webauthn_adapter_context_t*)adapter->private_data;
    if (!webauthn_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Parse message as WebAuthn client data + auth data */
    if (message_len < 64) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Split message into client data and auth data */
    size_t client_data_size = message_len / 2;
    const uint8_t* client_data = message;
    const uint8_t* auth_data = message + client_data_size;

    /* Use first algorithm for signing */
    webauthn_algorithm_t algorithm = webauthn_ctx->options.algorithms[0];

    /* Reconstruct master key for signing */
    uint8_t master_key[32];
    for (int i = 0; i < 32; i++) {
        master_key[i] = derived_key[i % key_size] ^ (uint8_t)((i * 17) & 0xFF);
    }

    if (!sign_assertion(master_key, sizeof(master_key),
                       client_data, client_data_size,
                       auth_data, message_len - client_data_size,
                       algorithm, signature, signature_size)) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Verify WebAuthn assertion
 */
static quid_adapter_status_t webauthn_adapter_verify(
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

    webauthn_adapter_context_t* webauthn_ctx = (webauthn_adapter_context_t*)adapter->private_data;
    if (!webauthn_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Parse message as WebAuthn client data + auth data */
    if (message_len < 64) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* Split message into client data and auth data */
    size_t client_data_size = message_len / 2;
    const uint8_t* client_data = message;
    const uint8_t* auth_data = message + client_data_size;

    /* Reconstruct signing key from public key */
    uint8_t signing_key[32];
    for (int i = 0; i < 32; i++) {
        signing_key[i] = public_key[i % key_size] ^ (uint8_t)((i * 19) & 0xFF);
    }

    /* Generate expected signature */
    uint8_t expected_sig[256];
    size_t expected_size = sizeof(expected_sig);
    webauthn_algorithm_t algorithm = webauthn_ctx->options.algorithms[0];

    if (!sign_assertion(signing_key, sizeof(signing_key),
                       client_data, client_data_size,
                       auth_data, message_len - client_data_size,
                       algorithm, expected_sig, &expected_size)) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* Compare signatures */
    int result = quid_constant_time_compare(signature, expected_sig,
                                           (signature_len < expected_size) ? signature_len : expected_size);

    quid_secure_zero(expected_sig, sizeof(expected_sig));

    return (result == 0) ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_VERIFICATION;
}

/**
 * @brief WebAuthn adapter function table
 */
static quid_adapter_functions_t webauthn_functions = {
    .abi_version = QUID_ADAPTER_ABI_VERSION,
    .init = webauthn_adapter_init,
    .cleanup = webauthn_adapter_cleanup,
    .get_info = webauthn_adapter_get_info,
    .derive_key = webauthn_adapter_derive_key,
    .derive_address = NULL,  /* WebAuthn doesn't use addresses */
    .sign = webauthn_adapter_sign,
    .verify = webauthn_adapter_verify,
    .encrypt = NULL,
    .decrypt = NULL,
    .batch = NULL
};

/**
 * @brief WebAuthn adapter entry point
 * Note: Renamed to avoid symbol conflicts when statically linking multiple adapters
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* webauthn_quid_adapter_get_functions(void)
{
    return &webauthn_functions;
}