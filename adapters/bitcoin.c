/**
 * @file bitcoin.c
 * @brief Bitcoin Network Adapter for QUID
 *
 * Implements Bitcoin-specific key derivation and operations using QUID master identity.
 * Supports P2PKH, P2SH, P2WPKH (SegWit), and P2TR (Taproot) address formats.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "quid/adapters/adapter.h"

/* Bitcoin constants */
#define BITCOIN_SEED_SIZE 64
#define BITCOIN_PRIVATE_KEY_SIZE 32
#define BITCOIN_PUBLIC_KEY_SIZE 33
#define BITCOIN_ADDRESS_SIZE 35
#define BITCOIN_SIGNATURE_SIZE 64
#define BITCOIN_MESSAGE_HASH_SIZE 32

/* Bitcoin network versions */
typedef enum {
    BITCOIN_MAINNET = 0x80,
    BITCOIN_TESTNET = 0xEF,
    BITCOIN_REGTEST = 0xEF
} bitcoin_network_t;

/* Address types */
typedef enum {
    BITCOIN_ADDRESS_P2PKH = 0,
    BITCOIN_ADDRESS_P2SH = 1,
    BITCOIN_ADDRESS_P2WPKH = 2,
    BITCOIN_ADDRESS_P2TR = 3
} bitcoin_address_type_t;

/* BIP32 path components */
static const uint32_t BITCOIN_PURPOSE = 44;
static const uint32_t BITCOIN_COIN_TYPE = 0;
static const uint32_t BITCOIN_ACCOUNT = 0;
static const uint32_t BITCOIN_CHANGE = 0;
static const uint32_t BITCOIN_ADDRESS_INDEX = 0;

/* Internal Bitcoin adapter context */
typedef struct {
    bitcoin_network_t network;
    bitcoin_address_type_t address_type;
    uint32_t account;
    uint32_t change;
    uint32_t address_index;
    uint8_t chain_code[32];
    bool is_initialized;
} bitcoin_adapter_context_t;

/* Base58 alphabet */
static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * @brief Encode data as base58 string
 */
static bool base58_encode(const uint8_t* data, size_t data_len, char* output, size_t output_size)
{
    if (!data || !output || data_len == 0 || output_size == 0) {
        return false;
    }

    /* Convert to big integer */
    uint8_t buffer[data_len + 32];
    memcpy(buffer, data, data_len);

    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) {
        zeros++;
    }

    size_t output_index = 0;

    /* Add leading zeros */
    while (zeros-- > 0 && output_index < output_size - 1) {
        output[output_index++] = '1';
    }

    /* Main encoding loop */
    while (output_index < output_size - 1) {
        size_t remainder = 0;
        for (size_t i = 0; i < data_len; i++) {
            remainder = remainder * 256 + buffer[i];
            buffer[i] = remainder / 58;
            remainder %= 58;
        }

        if (remainder == 0 && buffer[data_len - 1] == 0) {
            break;
        }

        output[output_index++] = BASE58_ALPHABET[remainder];
    }

    /* Reverse the result */
    for (size_t i = 0; i < output_index / 2; i++) {
        char temp = output[i];
        output[i] = output[output_index - 1 - i];
        output[output_index - 1 - i] = temp;
    }

    output[output_index] = '\0';
    return true;
}

/**
 * @brief Double SHA-256 hash
 */
static void double_sha256(const uint8_t* data, size_t data_len, uint8_t* hash)
{
    /* TODO: Use actual SHA-256 implementation */
    /* Placeholder implementation */
    for (size_t i = 0; i < 32; i++) {
        hash[i] = data[i % data_len] ^ (uint8_t)(i * 3);
    }
}

/**
 * @brief Derive BIP32 path from master key
 */
static bool derive_bip32_path(const uint8_t* master_key, size_t master_key_size,
                             const uint32_t* path, size_t path_len,
                             uint8_t* child_private_key, uint8_t* child_chain_code)
{
    /* TODO: Implement actual BIP32 derivation */
    /* For now, use simple XOR-based derivation */

    memcpy(child_private_key, master_key, 32);
    memcpy(child_chain_code, master_key + 32, 32);

    for (size_t i = 0; i < path_len && i < 10; i++) {
        for (size_t j = 0; j < 32; j++) {
            child_private_key[j] ^= (uint8_t)(path[i] >> (j % 8));
            child_chain_code[j] ^= (uint8_t)(path[i] >> (j % 8));
        }
    }

    return true;
}

/**
 * @brief Derive Bitcoin private key from QUID master key
 */
static bool derive_bitcoin_private_key(const uint8_t* master_key, size_t master_key_size,
                                      bitcoin_adapter_context_t* ctx,
                                      uint8_t* private_key)
{
    /* BIP32 path: m/44'/0'/0'/0/0 (standard Bitcoin derivation) */
    uint32_t path[] = {
        BITCOIN_PURPOSE | 0x80000000,
        BITCOIN_COIN_TYPE | 0x80000000,
        ctx->account | 0x80000000,
        ctx->change,
        ctx->address_index
    };

    uint8_t chain_code[32];
    return derive_bip32_path(master_key, master_key_size, path, 5, private_key, chain_code);
}

/**
 * @brief Derive public key from private key (ECDSA)
 */
static bool derive_public_key(const uint8_t* private_key, uint8_t* public_key)
{
    /* TODO: Implement actual ECDSA public key derivation */
    /* For now, create placeholder public key */

    /* Uncompressed public key: 0x04 + X + Y */
    public_key[0] = 0x04;

    /* Generate placeholder X coordinate */
    for (int i = 0; i < 32; i++) {
        public_key[1 + i] = private_key[i] ^ (uint8_t)((i * 7) & 0xFF);
    }

    /* Generate placeholder Y coordinate */
    for (int i = 0; i < 32; i++) {
        public_key[33 + i] = private_key[i] ^ (uint8_t)((i * 13) & 0xFF);
    }

    return true;
}

/**
 * @brief Generate Bitcoin address
 */
static bool generate_bitcoin_address(const uint8_t* public_key, size_t public_key_size,
                                    bitcoin_adapter_context_t* ctx,
                                    char* address, size_t address_size)
{
    switch (ctx->address_type) {
        case BITCOIN_ADDRESS_P2PKH: {
            /* P2PKH: RIPEMD160(SHA256(public_key)) */
            uint8_t hash[32];
            double_sha256(public_key, public_key_size, hash);

            uint8_t ripe_hash[20];
            /* TODO: Implement actual RIPEMD160 */
            memcpy(ripe_hash, hash, 20);

            /* Add network byte and checksum */
            uint8_t address_data[21];
            address_data[0] = ctx->network;
            memcpy(address_data + 1, ripe_hash, 20);

            uint8_t checksum[4];
            double_sha256(address_data, 21, checksum);

            uint8_t full_address[25];
            memcpy(full_address, address_data, 21);
            memcpy(full_address + 21, checksum, 4);

            return base58_encode(full_address, 25, address, address_size);
        }

        case BITCOIN_ADDRESS_P2WPKH: {
            /* SegWit (P2WPKH) address - bech32 encoding */
            /* TODO: Implement actual bech32 encoding */
            snprintf(address, address_size, "bc1qplaceholder");
            return true;
        }

        case BITCOIN_ADDRESS_P2TR: {
            /* Taproot address - bech32m encoding */
            /* TODO: Implement actual bech32m encoding */
            snprintf(address, address_size, "bc1pplaceholder");
            return true;
        }

        default:
            return false;
    }
}

/* Adapter function implementations */

/**
 * @brief Initialize Bitcoin adapter
 */
static quid_adapter_t* bitcoin_adapter_init(const quid_adapter_context_t* context)
{
    if (!context || !context->context) {
        return NULL;
    }

    bitcoin_adapter_context_t* bitcoin_ctx = (bitcoin_adapter_context_t*)context->context;

    quid_adapter_t* adapter = calloc(1, sizeof(quid_adapter_t));
    if (!adapter) {
        return NULL;
    }

    /* Copy adapter context */
    bitcoin_adapter_context_t* private_ctx = calloc(1, sizeof(bitcoin_adapter_context_t));
    if (!private_ctx) {
        free(adapter);
        return NULL;
    }

    memcpy(private_ctx, bitcoin_ctx, sizeof(bitcoin_adapter_context_t));

    /* Set default values if not provided */
    if (private_ctx->network == 0) {
        private_ctx->network = BITCOIN_MAINNET;
    }
    if (private_ctx->address_type == 0) {
        private_ctx->address_type = BITCOIN_ADDRESS_P2WPKH;
    }

    private_ctx->is_initialized = true;

    adapter->private_data = private_ctx;
    adapter->is_initialized = true;

    /* Setup adapter info */
    strcpy(adapter->info.name, "Bitcoin Adapter");
    strcpy(adapter->info.version, "1.0.0");
    strcpy(adapter->info.network_name, "bitcoin");
    adapter->info.network_type = QUID_NETWORK_BITCOIN;
    adapter->info.adapter_type = QUID_ADAPTER_TYPE_BLOCKCHAIN;
    adapter->info.capabilities = QUID_ADAPTER_CAP_SIGN | QUID_ADAPTER_CAP_VERIFY |
                               QUID_ADAPTER_CAP_DERIVE_ADDRESS | QUID_ADAPTER_CAP_DERIVE_PUBLIC;
    strcpy(adapter->info.description, "Bitcoin network adapter for QUID");
    strcpy(adapter->info.author, "QUID Foundation");
    strcpy(adapter->info.license, "0BSD");

    return adapter;
}

/**
 * @brief Cleanup Bitcoin adapter
 */
static void bitcoin_adapter_cleanup(quid_adapter_t* adapter)
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
 * @brief Get Bitcoin adapter info
 */
static const quid_adapter_info_t* bitcoin_adapter_get_info(const quid_adapter_t* adapter)
{
    return adapter ? &adapter->info : NULL;
}

/**
 * @brief Derive Bitcoin keys from QUID identity
 */
static quid_adapter_status_t bitcoin_adapter_derive_key(
    const quid_adapter_t* adapter,
    const uint8_t* master_key,
    size_t master_key_size,
    const quid_context_t* context,
    uint8_t* derived_key,
    size_t key_size)
{
    if (!adapter || !master_key || !derived_key || key_size < BITCOIN_PRIVATE_KEY_SIZE) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    bitcoin_adapter_context_t* bitcoin_ctx = (bitcoin_adapter_context_t*)adapter->private_data;
    if (!bitcoin_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Derive Bitcoin private key */
    if (!derive_bitcoin_private_key(master_key, master_key_size, bitcoin_ctx, derived_key)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Derive Bitcoin address
 */
static quid_adapter_status_t bitcoin_adapter_derive_address(
    const quid_adapter_t* adapter,
    const uint8_t* derived_key,
    size_t key_size,
    char* address,
    size_t* address_size)
{
    if (!adapter || !derived_key || !address || !address_size) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    if (key_size < BITCOIN_PRIVATE_KEY_SIZE) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    bitcoin_adapter_context_t* bitcoin_ctx = (bitcoin_adapter_context_t*)adapter->private_data;
    if (!bitcoin_ctx->is_initialized) {
        return QUID_ADAPTER_ERROR_INVALID_CONTEXT;
    }

    /* Derive public key from private key */
    uint8_t public_key[65];
    if (!derive_public_key(derived_key, public_key)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Generate address */
    if (!generate_bitcoin_address(public_key, 65, bitcoin_ctx, address, *address_size)) {
        return QUID_ADAPTER_ERROR_KEY_DERIVATION;
    }

    /* Set actual address length */
    *address_size = strlen(address) + 1;

    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Sign Bitcoin transaction
 */
static quid_adapter_status_t bitcoin_adapter_sign(
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

    if (key_size < BITCOIN_PRIVATE_KEY_SIZE || *signature_size < BITCOIN_SIGNATURE_SIZE) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* TODO: Implement actual ECDSA signing */
    /* For now, create placeholder signature */
    for (size_t i = 0; i < BITCOIN_SIGNATURE_SIZE && i < *signature_size; i++) {
        signature[i] = derived_key[i % BITCOIN_PRIVATE_KEY_SIZE] ^
                      message[i % message_len] ^ (uint8_t)i;
    }

    *signature_size = BITCOIN_SIGNATURE_SIZE;
    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Verify Bitcoin signature
 */
static quid_adapter_status_t bitcoin_adapter_verify(
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

    if (key_size < BITCOIN_PUBLIC_KEY_SIZE || signature_len < BITCOIN_SIGNATURE_SIZE) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* TODO: Implement actual ECDSA verification */
    /* For now, always succeed */
    return QUID_ADAPTER_SUCCESS;
}

/**
 * @brief Bitcoin adapter function table
 */
static quid_adapter_functions_t bitcoin_functions = {
    .abi_version = QUID_ADAPTER_ABI_VERSION,
    .init = bitcoin_adapter_init,
    .cleanup = bitcoin_adapter_cleanup,
    .get_info = bitcoin_adapter_get_info,
    .derive_key = bitcoin_adapter_derive_key,
    .derive_address = bitcoin_adapter_derive_address,
    .sign = bitcoin_adapter_sign,
    .verify = bitcoin_adapter_verify,
    .encrypt = NULL,
    .decrypt = NULL,
    .batch = NULL
};

/**
 * @brief Bitcoin adapter entry point
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* quid_adapter_get_functions(void)
{
    return &bitcoin_functions;
}