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
 */
static bool generate_ed25519_keypair(const uint8_t* seed, uint8_t* private_key, uint8_t* public_key)
{
    if (!seed || !private_key || !public_key) {
        return false;
    }

    /* TODO: Implement actual Ed25519 key generation */
    /* For now, create deterministic keys from seed */

    /* Private key (seed with some transformation) */
    for (int i = 0; i < 32; i++) {
        private_key[i] = seed[i] ^ (uint8_t)((i * 5) & 0xFF);
    }

    /* Public key (hash of private key) */
    for (int i = 0; i < 32; i++) {
        public_key[i] = private_key[i] ^ (uint8_t)((i * 7) & 0xFF);
    }

    return true;
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

    /* TODO: Implement actual RSA key generation */
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

    /* TODO: Implement actual ECDSA key generation */
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

    /* TODO: Implement actual SSH key signing */
    /* For now, create deterministic signature */
    for (size_t i = 0; i < required_size && i < *signature_size; i++) {
        signature[i] = derived_key[i % key_size] ^
                      message[i % message_len] ^ (uint8_t)((i * ssh_ctx->key_type) & 0xFF);
    }

    *signature_size = required_size;
    return QUID_ADAPTER_SUCCESS;
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

    /* TODO: Implement actual SSH signature verification */
    /* For now, always succeed */
    return QUID_ADAPTER_SUCCESS;
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
    .derive_public = ssh_adapter_derive_public,
    .sign = ssh_adapter_sign,
    .verify = ssh_adapter_verify,
    .encrypt = NULL,
    .decrypt = NULL,
    .batch = NULL
};

/**
 * @brief SSH adapter entry point
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* quid_adapter_get_functions(void)
{
    return &ssh_functions;
}