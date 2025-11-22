/**
 * @file identity_internal.h
 * @brief Internal QUID identity representation
 *
 * Shared internal structure used by identity and backup implementations.
 */

#ifndef QUID_IDENTITY_INTERNAL_H
#define QUID_IDENTITY_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

#include "quid/quid.h"

#define QUID_IDENTITY_MAGIC 0x4944454E  /* "IDEN" */

typedef struct {
    uint32_t magic;                         /* Structure magic */
    uint8_t master_keypair[QUID_MASTER_KEY_SIZE]; /* ML-DSA private key (max size) */
    uint8_t public_key[QUID_PUBLIC_KEY_SIZE];      /* ML-DSA public key (max size) */
    char id_string[QUID_ID_ID_SIZE];       /* Human-readable ID */
    quid_security_level_t security_level;  /* Security level */
    bool is_locked;                        /* Memory protection state */
    void* secure_memory;                   /* Secure memory region */
    size_t secure_size;                    /* Size of secure region */
    uint64_t creation_time;                /* Identity creation timestamp */
    uint8_t reserved[32];                  /* Reserved for future use */
} quid_identity_internal_t;

#endif /* QUID_IDENTITY_INTERNAL_H */
