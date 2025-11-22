/**
 * @file crypto.h
 * @brief Cryptographic utilities for QUID
 *
 * Internal cryptographic functions and constants.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_CRYPTO_H
#define QUID_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "quid/quid.h"

/* ML-DSA parameters for different security levels */
typedef struct {
    size_t public_key_size;
    size_t private_key_size;
    size_t signature_size;
    size_t seed_size;
    const char* name;
} ml_dsa_params_t;

/* ML-DSA security level parameters */
extern const ml_dsa_params_t ml_dsa_params[];

/* Function prototypes */

/**
 * @brief Initialize cryptographic subsystem
 * @return true on success, false on failure
 */
bool quid_crypto_init(void);

/**
 * @brief Cleanup cryptographic subsystem
 */
void quid_crypto_cleanup(void);

/**
 * @brief Generate ML-DSA keypair
 * @param seed Random seed
 * @param seed_size Size of seed (must be QUID_SEED_SIZE)
 * @param private_key Output private key
 * @param private_key_size Size of private key buffer
 * @param public_key Output public key
 * @param public_key_size Size of public key buffer
 * @param security_level ML-DSA security level
 * @return true on success, false on failure
 */
bool quid_crypto_ml_dsa_keygen(const uint8_t* seed,
                               size_t seed_size,
                               uint8_t* private_key,
                               size_t private_key_size,
                               uint8_t* public_key,
                               size_t public_key_size,
                               quid_security_level_t security_level);

/**
 * @brief Sign message with ML-DSA
 * @param private_key Private key
 * @param private_key_size Size of private key
 * @param message Message to sign
 * @param message_size Size of message
 * @param signature Output signature
 * @param signature_size Output signature size
 * @param security_level ML-DSA security level
 * @return true on success, false on failure
 */
bool quid_crypto_ml_dsa_sign(const uint8_t* private_key,
                             size_t private_key_size,
                             const uint8_t* message,
                             size_t message_size,
                             uint8_t* signature,
                             size_t* signature_size,
                             quid_security_level_t security_level);

/**
 * @brief Verify ML-DSA signature
 * @param public_key Public key
 * @param public_key_size Size of public key
 * @param message Original message
 * @param message_size Size of message
 * @param signature Signature to verify
 * @param signature_size Size of signature
 * @return true on success, false on failure
 */
bool quid_crypto_ml_dsa_verify(const uint8_t* public_key,
                               size_t public_key_size,
                               const uint8_t* message,
                               size_t message_size,
                               const uint8_t* signature,
                               size_t signature_size);

/**
 * @brief Key derivation function
 * @param input_key Input key material
 * @param input_key_size Size of input key
 * @param info Context information
 * @param info_size Size of info
 * @param output_key Output derived key
 * @param output_key_size Size of output key
 * @return true on success, false on failure
 */
bool quid_crypto_kdf(const uint8_t* input_key,
                     size_t input_key_size,
                     const uint8_t* info,
                     size_t info_size,
                     uint8_t* output_key,
                     size_t output_key_size);

/**
 * @brief SHAKE256 hash function
 * @param input Input data
 * @param input_size Size of input
 * @param output Output hash
 * @param output_size Desired output size
 */
void quid_crypto_shake256(const uint8_t* input,
                          size_t input_size,
                          uint8_t* output,
                          size_t output_size);

/**
 * @brief SHA-256 hash function
 * @param input Input data
 * @param input_size Size of input
 * @param output 32-byte output hash
 */
void quid_crypto_sha256(const uint8_t* input,
                        size_t input_size,
                        uint8_t* output);

/**
 * @brief AEAD encryption (AES-256-GCM)
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param plaintext Data to encrypt
 * @param plaintext_size Size of plaintext
 * @param aad Additional authenticated data
 * @param aad_size Size of AAD
 * @param ciphertext Output ciphertext
 * @param ciphertext_size Input/output size
 * @param tag Authentication tag (16 bytes)
 * @return true on success, false on failure
 */
bool quid_crypto_aead_encrypt(const uint8_t* key,
                              const uint8_t* nonce,
                              const uint8_t* plaintext,
                              size_t plaintext_size,
                              const uint8_t* aad,
                              size_t aad_size,
                              uint8_t* ciphertext,
                              size_t* ciphertext_size,
                              uint8_t* tag);

/**
 * @brief AEAD decryption (AES-256-GCM)
 * @param key Decryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param ciphertext Data to decrypt
 * @param ciphertext_size Size of ciphertext
 * @param aad Additional authenticated data
 * @param aad_size Size of AAD
 * @param tag Authentication tag (16 bytes)
 * @param plaintext Output plaintext
 * @param plaintext_size Input/output size
 * @return true on success, false on failure
 */
bool quid_crypto_aead_decrypt(const uint8_t* key,
                              const uint8_t* nonce,
                              const uint8_t* ciphertext,
                              size_t ciphertext_size,
                              const uint8_t* aad,
                              size_t aad_size,
                              const uint8_t* tag,
                              uint8_t* plaintext,
                              size_t* plaintext_size);

/**
 * @brief Password-based key derivation (Argon2id)
 * @param password Password string
 * @param password_len Password length
 * @param salt Salt (16 bytes)
 * @param iterations Number of iterations
 * @param memory_cost Memory cost in KB
 * @param parallelism Parallelism factor
 * @param output Derived key
 * @param output_size Desired output size
 * @return true on success, false on failure
 */
bool quid_crypto_pbkdf(const char* password,
                       size_t password_len,
                       const uint8_t* salt,
                       size_t iterations,
                       size_t memory_cost,
                       size_t parallelism,
                       uint8_t* output,
                       size_t output_size);

#endif /* QUID_CRYPTO_H */