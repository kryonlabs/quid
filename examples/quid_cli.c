/**
 * @file quid_cli.c
 * @brief Minimal CLI utility for generating QUID post-quantum keypairs.
 *
 * Usage:
 *   quid-cli keygen [--level 1|3|5] [--format hex|base64] [--seed <hex>]
 *
 * - If no seed is provided, a fresh random seed is used.
 * - Prints the identity ID, public key, and private key in the requested format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "quid/quid.h"

typedef enum {
    OUTPUT_HEX,
    OUTPUT_BASE64
} output_format_t;

static void print_usage(const char* prog)
{
    fprintf(stderr, "Usage: %s keygen [--level 1|3|5] [--format hex|base64] [--seed <hex>]\n", prog);
}

static bool hex_decode(const char* hex, uint8_t* out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return false;
        }
        out[i] = (uint8_t)byte;
    }
    return true;
}

static void print_hex(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_base64(const uint8_t* data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    unsigned char* buf = (unsigned char*)malloc(out_len + 1);
    if (!buf) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    int encoded = EVP_EncodeBlock(buf, data, (int)len);
    if (encoded < 0) {
        fprintf(stderr, "Base64 encode failed\n");
        free(buf);
        exit(1);
    }
    buf[encoded] = '\0';
    printf("%s\n", buf);
    free(buf);
}

static void get_sizes(quid_security_level_t level, size_t* pk, size_t* sk)
{
    switch (level) {
        case QUID_SECURITY_LEVEL_1:
            *pk = 1312;
            *sk = 2560;
            break;
        case QUID_SECURITY_LEVEL_3:
            *pk = 1952;
            *sk = 4032;
            break;
        case QUID_SECURITY_LEVEL_5:
        default:
            *pk = 2592;
            *sk = 4896;
            break;
    }
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* cmd = argv[1];
    if (strcmp(cmd, "keygen") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    quid_security_level_t level = QUID_SECURITY_LEVEL_5;
    output_format_t format = OUTPUT_HEX;
    const char* seed_hex = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) {
            int lvl = atoi(argv[++i]);
            if (lvl == 1) level = QUID_SECURITY_LEVEL_1;
            else if (lvl == 3) level = QUID_SECURITY_LEVEL_3;
            else if (lvl == 5) level = QUID_SECURITY_LEVEL_5;
            else {
                fprintf(stderr, "Invalid level: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            const char* f = argv[++i];
            if (strcmp(f, "hex") == 0) format = OUTPUT_HEX;
            else if (strcmp(f, "base64") == 0) format = OUTPUT_BASE64;
            else {
                fprintf(stderr, "Invalid format: %s\n", f);
                return 1;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed_hex = argv[++i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (quid_init() != QUID_SUCCESS) {
        fprintf(stderr, "Failed to initialize QUID\n");
        return 1;
    }

    uint8_t seed[QUID_SEED_SIZE];
    bool use_seed = false;
    if (seed_hex) {
        if (!hex_decode(seed_hex, seed, sizeof(seed))) {
            fprintf(stderr, "Invalid seed hex (expected %zu hex chars)\n", sizeof(seed) * 2);
            quid_cleanup();
            return 1;
        }
        use_seed = true;
    } else {
        if (quid_random_bytes(seed, sizeof(seed)) != QUID_SUCCESS) {
            fprintf(stderr, "Failed to generate seed\n");
            quid_cleanup();
            return 1;
        }
    }

    quid_identity_t* identity = NULL;
    quid_status_t status = use_seed
        ? quid_identity_from_seed(&identity, seed, sizeof(seed), level)
        : quid_identity_create(&identity, level);
    if (status != QUID_SUCCESS || !identity) {
        fprintf(stderr, "Key generation failed (status=%d)\n", status);
        quid_cleanup();
        return 1;
    }

    const char* id = quid_get_identity_id(identity);
    size_t pk_size = 0, sk_size = 0;
    get_sizes(level, &pk_size, &sk_size);

    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];
    memset(public_key, 0, sizeof(public_key));
    if (quid_get_public_key(identity, public_key) != QUID_SUCCESS) {
        fprintf(stderr, "Failed to extract public key\n");
        quid_identity_free(identity);
        quid_cleanup();
        return 1;
    }

    /* The private key is stored inside the identity struct; copy out the used portion */
    uint8_t private_key[QUID_MASTER_KEY_SIZE];
    memset(private_key, 0, sizeof(private_key));
    memcpy(private_key, identity->master_keypair, sk_size);

    printf("QUID Identity ID: %s\n", id);
    printf("Security level: %d\n", level);
    printf("Public key (%zu bytes) [%s]:\n", pk_size, format == OUTPUT_HEX ? "hex" : "base64");
    if (format == OUTPUT_HEX) {
        print_hex(public_key, pk_size);
    } else {
        print_base64(public_key, pk_size);
    }

    printf("Private key (%zu bytes) [%s]:\n", sk_size, format == OUTPUT_HEX ? "hex" : "base64");
    if (format == OUTPUT_HEX) {
        print_hex(private_key, sk_size);
    } else {
        print_base64(private_key, sk_size);
    }

    printf("Seed used (%s):\n", use_seed ? "provided" : "random");
    if (format == OUTPUT_HEX) {
        print_hex(seed, sizeof(seed));
    } else {
        print_base64(seed, sizeof(seed));
    }

    quid_identity_free(identity);
    quid_cleanup();
    return 0;
}
