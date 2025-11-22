/**
 * @file random.h
 * @brief Cryptographically secure random number generation
 *
 * Provides secure random bytes for key generation and other
 * cryptographic operations.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_RANDOM_H
#define QUID_RANDOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Initialize random number generator
 * @return true on success, false on failure
 */
bool quid_random_init(void);

/**
 * @brief Cleanup random number generator
 */
void quid_random_cleanup(void);

/**
 * @brief Generate cryptographically secure random bytes
 * @param buffer Output buffer
 * @param size Number of bytes to generate
 * @return true on success, false on failure
 */
bool quid_random_bytes_internal(uint8_t* buffer, size_t size);

/**
 * @brief Generate random boolean value
 * @return Random true/false value
 */
bool quid_random_bool(void);

/**
 * @brief Generate random 64-bit integer
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @return Random integer in range
 */
uint64_t quid_random_uint64(uint64_t min, uint64_t max);

/**
 * @brief Reseed random number generator
 * @param seed Additional entropy seed
 * @param seed_size Size of seed
 * @return true on success, false on failure
 */
bool quid_random_reseed(const uint8_t* seed, size_t seed_size);

/**
 * @brief Enable deterministic RNG mode for reproducible key generation
 * @param seed Seed material
 * @param seed_size Size of seed
 * @return true on success, false on failure
 */
bool quid_random_begin_deterministic(const uint8_t* seed, size_t seed_size);

/**
 * @brief Disable deterministic RNG mode and clear state
 */
void quid_random_end_deterministic(void);

#endif /* QUID_RANDOM_H */
