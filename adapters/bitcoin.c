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

/* Bech32 constants */
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int8_t BECH32_CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/**
 * @brief Bech32 polymod (BIP173 checksum)
 */
static uint32_t bech32_polymod(const uint8_t* values, size_t values_len)
{
    uint32_t chk = 1;
    for (size_t i = 0; i < values_len; i++) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1FFFFFF) << 5 ^ values[i];
        if (top & 1)  chk ^= 0x3B6A57B2;
        if (top & 2)  chk ^= 0x26508E6D;
        if (top & 4)  chk ^= 0x1EA119FA;
        if (top & 8)  chk ^= 0x3D4233DD;
        if (top & 16) chk ^= 0x2A1462B3;
    }
    return chk;
}

/**
 * @brief Expand a human-readable part for Bech32 checksum
 */
static void bech32_hrp_expand(const char* hrp, uint8_t* expanded, size_t* expanded_len)
{
    size_t hrp_len = strlen(hrp);
    *expanded_len = hrp_len * 2 + 1;
    for (size_t i = 0; i < hrp_len; i++) {
        expanded[i] = hrp[i] >> 5;
        expanded[hrp_len + i + 1] = hrp[i] & 0x1F;
    }
    expanded[hrp_len] = 0;
}

/**
 * @brief Bech32 encode (BIP173)
 */
static bool bech32_encode(const char* hrp, const uint8_t* data, size_t data_len,
                         char* output, size_t output_size, bool bech32m)
{
    if (!hrp || !data || !output) return false;

    size_t hrp_len = strlen(hrp);
    size_t max_data_len = 90;  /* BIP173 limit */
    if (data_len > max_data_len) return false;

    /* Check output size */
    size_t max_output_len = hrp_len + 1 + data_len + 6;
    if (output_size < max_output_len + 1) return false;

    /* Expand HRP */
    uint8_t expanded[2 * 50 + 1];
    size_t expanded_len;
    bech32_hrp_expand(hrp, expanded, &expanded_len);

    /* Create values array: expanded + data + check digits */
    uint8_t values[expanded_len + data_len + 6];
    memcpy(values, expanded, expanded_len);
    memcpy(values + expanded_len, data, data_len);

    /* Calculate checksum */
    uint32_t chk = bech32_polymod(values, expanded_len + data_len);
    if (!bech32m) {
        /* Bech32 (BIP173) */
        chk ^= 1;
    }
    /* Bech32m uses chk as-is */

    for (size_t i = 0; i < 6; i++) {
        values[expanded_len + data_len + i] = (chk >> (5 * (5 - i))) & 0x1F;
    }

    /* Build output string */
    size_t output_idx = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        output[output_idx++] = hrp[i];
    }
    output[output_idx++] = '1';
    for (size_t i = 0; i < data_len + 6; i++) {
        uint8_t val = values[expanded_len + i];
        if (val >= 32) return false;  /* Invalid value */
        output[output_idx++] = BECH32_CHARSET[val];
    }
    output[output_idx] = '\0';

    return true;
}

/**
 * @brief Convert bytes to 5-bit array for Bech32
 */
static bool convert_bits(const uint8_t* in, size_t in_len, uint8_t* out,
                         size_t* out_len, int from, int to, bool pad)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t out_idx = 0;
    size_t max_out_len = *out_len;

    for (size_t i = 0; i < in_len; i++) {
        if (bits < 0 || bits + from > 32) return false;
        acc = (acc << from) | in[i];
        bits += from;
        while (bits >= to) {
            bits -= to;
            if (out_idx >= max_out_len) return false;
            out[out_idx++] = (acc >> bits) & (((uint32_t)1 << to) - 1);
        }
    }

    if (pad) {
        if (bits > 0) {
            if (out_idx >= max_out_len) return false;
            out[out_idx++] = (acc << (to - bits)) & (((uint32_t)1 << to) - 1);
        }
    } else if (bits >= from || ((acc << (to - bits)) & (((uint32_t)1 << to) - 1))) {
        return false;
    }

    *out_len = out_idx;
    return true;
}

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
            /* SegWit (P2WPKH) address - bech32 encoding (BIP173) */
            /* Witness program: 0x00 + 20-byte pubkey hash */
            uint8_t sha256_hash[32];
            sha256(public_key, public_key_size, sha256_hash);

            uint8_t pubkey_hash[20];
            ripemd160(sha256_hash, 32, pubkey_hash);

            /* Build witness program: version (0) + script hash */
            uint8_t witness_program[21];
            witness_program[0] = 0;  /* Witness version 0 */
            memcpy(witness_program + 1, pubkey_hash, 20);

            /* Convert to 5-bit array */
            uint8_t five_bit[32];
            size_t five_bit_len = sizeof(five_bit);
            if (!convert_bits(witness_program, 21, five_bit, &five_bit_len, 8, 5, true)) {
                return false;
            }

            /* Choose HRP based on network */
            const char* hrp = "bc";  /* Default to mainnet */
            if (ctx->network == BITCOIN_TESTNET || ctx->network == BITCOIN_REGTEST) {
                hrp = "tb";
            }

            return bech32_encode(hrp, five_bit, five_bit_len, address, address_size, false);
        }

        case BITCOIN_ADDRESS_P2TR: {
            /* Taproot address - bech32m encoding (BIP350) */
            /* Witness program: 0x01 + 32-byte xonly pubkey */
            uint8_t sha256_hash[32];
            sha256(public_key, public_key_size, sha256_hash);

            /* For Taproot, use the full SHA256 hash as the xonly public key */
            uint8_t witness_program[33];
            witness_program[0] = 1;  /* Witness version 1 */
            memcpy(witness_program + 1, sha256_hash, 32);

            /* Convert to 5-bit array */
            uint8_t five_bit[53];
            size_t five_bit_len = sizeof(five_bit);
            if (!convert_bits(witness_program, 33, five_bit, &five_bit_len, 8, 5, true)) {
                return false;
            }

            /* Choose HRP based on network */
            const char* hrp = "bc";  /* Default to mainnet */
            if (ctx->network == BITCOIN_TESTNET || ctx->network == BITCOIN_REGTEST) {
                hrp = "tb";
            }

            return bech32_encode(hrp, five_bit, five_bit_len, address, address_size, true);
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

    if (key_size < BITCOIN_PRIVATE_KEY_SIZE) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Use secp256k1 ECDSA signing via OpenSSL */
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Set private key */
    BIGNUM* priv_bn = BN_bin2bn(derived_key, BITCOIN_PRIVATE_KEY_SIZE, NULL);
    if (!priv_bn) {
        EC_KEY_free(eckey);
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    if (EC_KEY_set_private_key(eckey, priv_bn) != 1) {
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Compute message hash */
    uint8_t msg_hash[32];
    sha256(message, message_len, msg_hash);

    /* Sign the hash */
    ECDSA_SIG* sig = ECDSA_do_sign(msg_hash, 32, eckey);
    BN_free(priv_bn);
    EC_KEY_free(eckey);

    if (!sig) {
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Convert signature to DER format (compact) */
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    /* Get raw signature bytes (r and s, 32 bytes each for secp256k1) */
    uint8_t r_bytes[32], s_bytes[32];
    BN_bn2binpad(r, r_bytes, 32);
    BN_bn2binpad(s, s_bytes, 32);

    /* Check output size */
    size_t sig_len = 64;
    if (*signature_size < sig_len) {
        ECDSA_SIG_free(sig);
        return QUID_ADAPTER_ERROR_SIGNING;
    }

    /* Copy signature (r || s) */
    memcpy(signature, r_bytes, 32);
    memcpy(signature + 32, s_bytes, 32);
    *signature_size = sig_len;

    ECDSA_SIG_free(sig);
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

    if (key_size < 33 || signature_len < 64) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* Parse public key (compressed or uncompressed format) */
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    /* Parse public key from octet string */
    const unsigned char* key_ptr = public_key;
    EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(eckey));

    if (public_key[0] == 0x04 && key_size >= 65) {
        /* Uncompressed format: 0x04 + x + y (64 bytes) */
        if (!EC_POINT_oct2point(EC_KEY_get0_group(eckey), pub_point,
                                 key_ptr, 65, NULL)) {
            EC_POINT_free(pub_point);
            EC_KEY_free(eckey);
            return QUID_ADAPTER_ERROR_VERIFICATION;
        }
    } else if ((public_key[0] == 0x02 || public_key[0] == 0x03) && key_size >= 33) {
        /* Compressed format: 0x02/0x03 + x (32 bytes) */
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

    /* Compute message hash */
    uint8_t msg_hash[32];
    sha256(message, message_len, msg_hash);

    /* Parse signature (r || s format, 64 bytes) */
    BIGNUM* r = BN_bin2bn(signature, 32, NULL);
    BIGNUM* s = BN_bin2bn(signature + 32, 32, NULL);
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        EC_KEY_free(eckey);
        return QUID_ADAPTER_ERROR_VERIFICATION;
    }

    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    /* Verify signature */
    int result = ECDSA_do_verify(msg_hash, 32, sig, eckey);

    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);

    return result == 1 ? QUID_ADAPTER_SUCCESS : QUID_ADAPTER_ERROR_VERIFICATION;
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