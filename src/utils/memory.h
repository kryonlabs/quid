/**
 * @file memory.h
 * @brief Secure memory management for QUID
 *
 * Provides secure memory allocation, zeroization, and protection
 * against side-channel attacks.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_MEMORY_H
#define QUID_MEMORY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Initialize secure memory subsystem
 * @return true on success, false on failure
 */
bool quid_memory_init(void);

/**
 * @brief Cleanup secure memory subsystem
 */
void quid_memory_cleanup(void);

/**
 * @brief Allocate secure memory
 * @param size Size to allocate
 * @return Pointer to allocated memory or NULL on failure
 */
void* quid_memory_secure_alloc(size_t size);

/**
 * @brief Free secure memory
 * @param ptr Memory to free
 * @param size Size of allocated memory
 */
void quid_memory_secure_free(void* ptr, size_t size);

/**
 * @brief Lock memory pages to prevent swapping
 * @param ptr Memory to lock
 * @param size Size of memory
 * @return true on success, false on failure
 */
bool quid_memory_lock(const void* ptr, size_t size);

/**
 * @brief Unlock memory pages
 * @param ptr Memory to unlock
 * @param size Size of memory
 */
void quid_memory_unlock(const void* ptr, size_t size);

/**
 * @brief Zero memory in a secure manner
 * @param ptr Memory to zero
 * @param size Size of memory
 */
void quid_secure_zero(void* ptr, size_t size);

/**
 * @brief Compare memory in constant time
 * @param a First memory block
 * @param b Second memory block
 * @param size Size to compare
 * @return 0 if equal, non-zero if different
 */
int quid_constant_time_compare(const void* a, const void* b, size_t size);

#endif /* QUID_MEMORY_H */