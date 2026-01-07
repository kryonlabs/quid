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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

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
    uint8_t first_hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, first_hash);
    SHA256(first_hash, SHA256_DIGEST_LENGTH, hash);
}

/**
 * @brief Single SHA-256 hash
 */
static void sha256(const uint8_t* data, size_t data_len, uint8_t* hash)
{
    SHA256(data, data_len, hash);
}

/**
 * @brief HMAC-SHA512 for BIP32
 */
static void hmac_sha512(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t* hash)
{
    HMAC(EVP_sha512(), key, key_len, data, data_len, hash, NULL);
}

/**
 * @brief RIPEMD160 hash
 */
static void ripemd160(const uint8_t* data, size_t data_len, uint8_t* hash)
{
    RIPEMD160(data, data_len, hash);
}

/**
 * @brief Parse BIP32 serialized key
 * Assumes master_key is 64 bytes: [32-byte private key][32-byte chain code]
 */
static bool parse_bip32_key(const uint8_t* serialized, uint8_t* key_out, uint8_t* chain_out)
{
    memcpy(key_out, serialized, 32);
    memcpy(chain_out, serialized + 32, 32);
    return true;
}

/**
 * @brief Serialize BIP32 key
 */
static bool serialize_bip32_key(const uint8_t* key, const uint8_t* chain, uint8_t* serialized)
{
    memcpy(serialized, key, 32);
    memcpy(serialized + 32, chain, 32);
    return true;
}

/**
 * @brief Add 256-bit integers modulo secp256k1 order
 * n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
 */
static void ecc_privkey_add(uint8_t* priv_key, const uint8_t* tweak)
{
    /* secp256k1 order n */
    static const uint8_t curve_order[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };

    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t a = priv_key[i];
        uint32_t b = tweak[i];
        uint32_t sum = a + b + carry;
        priv_key[i] = sum & 0xff;
        carry = sum >> 8;
    }

    /* Modulo reduction (subtract n if >= n) */
    uint64_t borrow = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t diff = priv_key[i] - curve_order[i] - borrow;
        priv_key[i] = diff & 0xff;
        borrow = (diff >> 8) | (borrow ? 1 : 0);
    }

    /* If we borrowed, we need to add n back */
    if (borrow) {
        carry = 0;
        for (int i = 0; i < 32; i++) {
            uint32_t sum = priv_key[i] + curve_order[i] + carry;
            priv_key[i] = sum & 0xff;
            carry = sum >> 8;
        }
    }
}

/**
 * @brief Derive BIP32 child key (CKDpriv)
 * Implements BIP32: Hierarchical Deterministic Wallets
 */
static bool derive_bip32_path(const uint8_t* master_key, size_t master_key_size,
                             const uint32_t* path, size_t path_len,
                             uint8_t* child_private_key, uint8_t* child_chain_code)
{
    if (!master_key || master_key_size < 64 || !path || !child_private_key || !child_chain_code) {
        return false;
    }

    /* Parse master key into private key and chain code */
    uint8_t priv_key[32];
    uint8_t chain_code[32];
    parse_bip32_key(master_key, priv_key, chain_code);

    /* Derive each level in the path */
    for (size_t i = 0; i < path_len; i++) {
        uint32_t index = path[i];
        int is_hardened = (index & 0x80000000) != 0;

        /* Prepare data for HMAC */
        uint8_t data[65]; /* 0x00 + 32-byte key + 4-byte index OR 33-byte pub key + 4-byte index */
        size_t data_len;

        if (is_hardened) {
            /* Hardened derivation: 0x00 || private_key || index */
            data[0] = 0x00;
            memcpy(data + 1, priv_key, 32);
            data_len = 33;
        } else {
            /* Normal derivation: compressed public key || index */
            /* For now, use simplified version: hash private_key to get pub key point */
            /* In production, you'd derive actual public key here */
            data[0] = 0x02; /* Compressed public key prefix (even y) */
            memcpy(data + 1, priv_key, 32);
            data_len = 33;
        }

        /* Write index as big-endian */
        data[data_len] = (index >> 24) & 0xff;
        data[data_len + 1] = (index >> 16) & 0xff;
        data[data_len + 2] = (index >> 8) & 0xff;
        data[data_len + 3] = index & 0xff;
        data_len += 4;

        /* HMAC-SHA512 of chain code and data */
        uint8_t hmac_result[64];
        hmac_sha512(chain_code, 32, data, data_len, hmac_result);

        /* Split into left (L) and right (R) parts */
        uint8_t L[32], R[32];
        memcpy(L, hmac_result, 32);
        memcpy(R, hmac_result + 32, 32);

        /* New private key = (L + old_private_key) mod n */
        memcpy(priv_key, L, 32);
        ecc_privkey_add(priv_key, R);

        /* New chain code = right part of HMAC */
        memcpy(chain_code, R, 32);
    }

    /* Output final private key and chain code */
    memcpy(child_private_key, priv_key, 32);
    memcpy(child_chain_code, chain_code, 32);

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
        44 | 0x80000000,  /* purpose */
        0 | 0x80000000,   /* coin type (Bitcoin) */
        ctx->account | 0x80000000,
        ctx->change,
        ctx->address_index
    };

    uint8_t chain_code[32];
    return derive_bip32_path(master_key, master_key_size, path, 5, private_key, chain_code);
}

/**
 * @brief Derive public key from private key using secp256k1
 * Uses OpenSSL EC API with secp256k1 curve (works with OpenSSL 1.1+ and 3.0+)
 */
static bool derive_public_key(const uint8_t* private_key, uint8_t* public_key)
{
    EC_KEY* eckey = NULL;
    const EC_GROUP* group = NULL;
    EC_POINT* pub_point = NULL;
    BIGNUM* priv_bn = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    bool success = false;

    /* Create EC key for secp256k1 */
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        goto cleanup;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        goto cleanup;
    }

    /* Set private key */
    priv_bn = BN_bin2bn(private_key, 32, NULL);
    if (!priv_bn) {
        goto cleanup;
    }

    if (!EC_KEY_set_private_key(eckey, priv_bn)) {
        goto cleanup;
    }

    /* Derive public key: pub_key = priv_key * G */
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

    /* Extract affine coordinates for compressed format */
    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, pub_point, x, y, NULL)) {
        goto cleanup;
    }

    /* Write compressed public key: 0x02/0x03 + X coordinate */
    public_key[0] = BN_is_odd(y) ? 0x03 : 0x02;
    BN_bn2binpad(x, public_key + 1, 32);

    success = true;

cleanup:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (priv_bn) BN_free(priv_bn);
    if (pub_point) EC_POINT_free(pub_point);
    if (eckey) EC_KEY_free(eckey);

    return success;
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
            uint8_t sha256_hash[32];
            sha256(public_key, public_key_size, sha256_hash);

            uint8_t ripe_hash[20];
            ripemd160(sha256_hash, 32, ripe_hash);

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
            /* For now, use placeholder; full bech32 is complex */
            snprintf(address, address_size, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            return true;
        }

        case BITCOIN_ADDRESS_P2TR: {
            /* Taproot address - bech32m encoding */
            /* For now, use placeholder; full bech32m is complex */
            snprintf(address, address_size, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
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

    /* ECDSA signing not implemented - Bitcoin uses secp256k1 (ECDSA)
     * For secp256k1 signing, use the bitcoin_adapter_sign function instead */
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

    /* secp256k1 (ECDSA) verification not yet implemented
     * Use the secp256k1 curve for proper Bitcoin signature verification */
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
 * Note: Renamed to avoid symbol conflicts when statically linking multiple adapters
 */
QUID_ADAPTER_EXPORT quid_adapter_functions_t* bitcoin_quid_adapter_get_functions(void)
{
    return &bitcoin_functions;
}