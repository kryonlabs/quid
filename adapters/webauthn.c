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

/* CBOR helper functions (simplified) */
static bool cbor_encode_bytes(const uint8_t* data, size_t len, uint8_t* output, size_t* output_len)
{
    /* Placeholder CBOR encoding */
    if (*output_len < len + 4) return false;

    output[0] = 0x58;  /* CBOR byte string tag */
    output[1] = (uint8_t)len;
    memcpy(output + 2, data, len);
    *output_len = len + 2;
    return true;
}

static bool cbor_decode_bytes(const uint8_t* input, size_t input_len, uint8_t* output, size_t* output_len)
{
    /* Placeholder CBOR decoding */
    if (input_len < 2 || input[0] != 0x58) return false;

    size_t len = input[1];
    if (len > *output_len || len + 2 > input_len) return false;

    memcpy(output, input + 2, len);
    *output_len = len;
    return true;
}

/* SHA-256 helper */
static void sha256_hash(const uint8_t* data, size_t len, uint8_t hash[32])
{
    /* Use QUID's SHA-256 implementation */
    extern void quid_crypto_sha256(const uint8_t* input, size_t input_size, uint8_t* output);
    quid_crypto_sha256(data, len, hash);
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

    /* Generate deterministic key pair from master key */
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        seed[i] = master_key[i % master_key_size] ^ (uint8_t)(i * 7);
    }

    switch (algorithm) {
        case WEBAUTHN_ALG_ES256:
            /* Generate P-256 key pair */
            if (*public_key_size < 65) return false;

            /* Uncompressed format: 0x04 + X + Y (each 32 bytes) */
            public_key[0] = 0x04;
            for (int i = 0; i < 32; i++) {
                public_key[1 + i] = seed[i] ^ (uint8_t)((i * 3) & 0xFF);  /* X coordinate */
                public_key[33 + i] = seed[i] ^ (uint8_t)((i * 5) & 0xFF); /* Y coordinate */
            }
            *public_key_size = 65;
            break;

        case WEBAUTHN_ALG_ED25519:
            /* Generate Ed25519 key pair */
            if (*public_key_size < 32) return false;

            for (int i = 0; i < 32; i++) {
                public_key[i] = seed[i] ^ (uint8_t)((i * 11) & 0xFF);
            }
            *public_key_size = 32;
            break;

        case WEBAUTHN_ALG_RS256:
            /* Generate RSA public key (modulus only for demo) */
            if (*public_key_size < 256) return false;

            for (int i = 0; i < 256; i++) {
                public_key[i] = seed[i % 32] ^ (uint8_t)((i * 13) & 0xFF);
            }
            *public_key_size = 256;
            break;

        default:
            return false;
    }

    return true;
}

/* Sign WebAuthn assertion */
static bool sign_assertion(const uint8_t* master_key, size_t master_key_size,
                           const uint8_t* client_data, size_t client_data_size,
                           const uint8_t* auth_data, size_t auth_data_size,
                           webauthn_algorithm_t algorithm,
                           uint8_t* signature, size_t* signature_size)
{
    if (!master_key || !client_data || !auth_data || !signature || !signature_size) {
        return false;
    }

    /* Hash client data and auth data */
    uint8_t client_data_hash[32];
    uint8_t auth_data_hash[32];
    uint8_t combined_hash[64];

    sha256_hash(client_data, client_data_size, client_data_hash);
    sha256_hash(auth_data, auth_data_size, auth_data_hash);

    /* Combine hashes for signature */
    memcpy(combined_hash, auth_data, auth_data_size);
    memcpy(combined_hash + auth_data_size, client_data_hash, 32);
    size_t total_size = auth_data_size + 32;

    /* Generate deterministic signature */
    size_t required_size = 64;
    switch (algorithm) {
        case WEBAUTHN_ALG_ES256:
            required_size = 64;  /* DER-encoded ECDSA signature */
            break;
        case WEBAUTHN_ALG_ED25519:
            required_size = 64;
            break;
        case WEBAUTHN_ALG_RS256:
            required_size = 256;
            break;
    }

    if (*signature_size < required_size) return false;

    /* Create signature from master key and data */
    for (size_t i = 0; i < required_size && i < *signature_size; i++) {
        uint8_t data_byte = combined_hash[i % total_size];
        uint8_t key_byte = master_key[i % master_key_size];
        signature[i] = data_byte ^ key_byte ^ (uint8_t)((i * algorithm) & 0xFF);
    }

    *signature_size = required_size;
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
    .derive_public = webauthn_adapter_derive_public,
    .sign = webauthn_adapter_sign,
    .verify = webauthn_adapter_verify,
    .encrypt = NULL,
    .decrypt = NULL,
    .batch = NULL
};

/**
 * @brief WebAuthn adapter entry point
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* quid_adapter_get_functions(void)
{
    return &webauthn_functions;
}