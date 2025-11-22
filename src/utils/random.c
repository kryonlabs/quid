/**
 * @file random.c
 * @brief Cryptographically secure random number generation
 *
 * Implements secure random number generation using system
 * entropy sources with fallback mechanisms.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __unix__
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#include "random.h"
#include "crypto.h"
#include "memory.h"

/* PQClean randombytes implementation */
int PQCLEAN_randombytes(uint8_t *output, size_t n);

/* Random number generator state */
static bool g_random_initialized = false;

/* Fallback PRNG state */
static uint64_t g_prng_state[4];
static bool g_prng_seeded = false;

/* Deterministic RNG state for seed-based key generation */
static bool g_deterministic_mode = false;
static uint8_t g_deterministic_key[64];
static uint8_t g_deterministic_buffer[64];
static size_t g_deterministic_offset = sizeof(g_deterministic_buffer);
static uint64_t g_deterministic_counter = 0;

/**
 * @brief XORShift64* PRNG for fallback
 */
static uint64_t xorshift64star(uint64_t x)
{
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1DULL;
}

/**
 * @brief Initialize fallback PRNG
 */
static void init_fallback_prng(void)
{
    if (g_prng_seeded) {
        return;
    }

    /* Seed with time, process ID, and other sources */
    uint64_t seed = (uint64_t)time(NULL);

#ifdef __unix__
    seed ^= (uint64_t)getpid() << 16;
    seed ^= (uint64_t)getppid() << 32;
#elif defined(_WIN32)
    seed ^= (uint64_t)GetCurrentProcessId() << 16;
    seed ^= (uint64_t)GetCurrentThreadId() << 32;
#endif

    /* Initialize PRNG state */
    g_prng_state[0] = seed;
    g_prng_state[1] = xorshift64star(seed);
    g_prng_state[2] = xorshift64star(g_prng_state[1]);
    g_prng_state[3] = xorshift64star(g_prng_state[2]);

    g_prng_seeded = true;
}

/**
 * @brief Generate bytes from fallback PRNG
 */
static void fallback_bytes(uint8_t* buffer, size_t size)
{
    init_fallback_prng();

    for (size_t i = 0; i < size; i++) {
        uint64_t rnd = xorshift64star(g_prng_state[0]);
        g_prng_state[0] = g_prng_state[1];
        g_prng_state[1] = g_prng_state[2];
        g_prng_state[2] = g_prng_state[3];
        g_prng_state[3] = rnd;

        buffer[i] = (uint8_t)(rnd & 0xFF);
    }
}

static void deterministic_bytes(uint8_t* buffer, size_t size)
{
    while (size > 0) {
        if (g_deterministic_offset >= sizeof(g_deterministic_buffer)) {
            /* Refill buffer using SHAKE256(key || counter) */
            uint8_t input[sizeof(g_deterministic_key) + sizeof(g_deterministic_counter)];
            memcpy(input, g_deterministic_key, sizeof(g_deterministic_key));
            memcpy(input + sizeof(g_deterministic_key), &g_deterministic_counter,
                   sizeof(g_deterministic_counter));

            quid_crypto_shake256(input, sizeof(input),
                                 g_deterministic_buffer, sizeof(g_deterministic_buffer));
            g_deterministic_offset = 0;
            g_deterministic_counter++;
        }

        size_t chunk = sizeof(g_deterministic_buffer) - g_deterministic_offset;
        if (chunk > size) {
            chunk = size;
        }

        memcpy(buffer, g_deterministic_buffer + g_deterministic_offset, chunk);
        buffer += chunk;
        size -= chunk;
        g_deterministic_offset += chunk;
    }
}

bool quid_random_begin_deterministic(const uint8_t* seed, size_t seed_size)
{
    if (!seed || seed_size == 0) {
        return false;
    }

    quid_crypto_shake256(seed, seed_size, g_deterministic_key, sizeof(g_deterministic_key));
    g_deterministic_offset = sizeof(g_deterministic_buffer);
    g_deterministic_counter = 0;
    g_deterministic_mode = true;
    g_random_initialized = true; /* Ensure PQClean RNG path is satisfied */
    return true;
}

void quid_random_end_deterministic(void)
{
    if (!g_deterministic_mode) {
        return;
    }

    quid_secure_zero(g_deterministic_key, sizeof(g_deterministic_key));
    quid_secure_zero(g_deterministic_buffer, sizeof(g_deterministic_buffer));
    g_deterministic_offset = sizeof(g_deterministic_buffer);
    g_deterministic_counter = 0;
    g_deterministic_mode = false;
}

/**
 * @brief Initialize random number generator
 */
bool quid_random_init(void)
{
    if (g_random_initialized) {
        return true;
    }

    /* Initialize fallback PRNG */
    init_fallback_prng();

    g_random_initialized = true;
    return true;
}

/**
 * @brief Cleanup random number generator
 */
void quid_random_cleanup(void)
{
    if (!g_random_initialized) {
        return;
    }

    /* Clear PRNG state */
    quid_secure_zero(g_prng_state, sizeof(g_prng_state));
    g_prng_seeded = false;

    g_random_initialized = false;
}

/**
 * @brief Generate cryptographically secure random bytes
 */
bool quid_random_bytes_internal(uint8_t* buffer, size_t size)
{
    if (!buffer || size == 0 || !g_random_initialized) {
        return false;
    }

    if (g_deterministic_mode) {
        deterministic_bytes(buffer, size);
        return true;
    }

    bool success = false;

#ifdef __unix__
    /* Try getrandom() first (Linux 3.17+) */
    ssize_t result = getrandom(buffer, size, 0);
    if (result == (ssize_t)size) {
        success = true;
    } else if (errno == ENOSYS) {
        /* getrandom() not available, try /dev/urandom */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t total_read = 0;
            while (total_read < (ssize_t)size) {
                ssize_t bytes_read = read(fd, buffer + total_read, size - total_read);
                if (bytes_read <= 0) {
                    break;
                }
                total_read += bytes_read;
            }
            close(fd);

            if (total_read == (ssize_t)size) {
                success = true;
            }
        }
    }

#elif defined(_WIN32)
    /* Use BCryptGenRandom for cryptographic randomness */
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)size,
                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status == 0) {
        success = true;
    }
#endif

    /* Fallback to PRNG if system randomness failed */
    if (!success) {
        fallback_bytes(buffer, size);
        /* Note: This is not cryptographically secure but provides
         * a fallback for systems without proper randomness */
    }

    return success;
}

/**
 * @brief Generate random boolean value
 */
bool quid_random_bool(void)
{
    uint8_t byte;
    if (!quid_random_bytes_internal(&byte, 1)) {
        return false;  /* Fallback */
    }
    return (byte & 0x01) != 0;
}

/**
 * @brief Generate random 64-bit integer
 */
uint64_t quid_random_uint64(uint64_t min, uint64_t max)
{
    if (min >= max) {
        return min;
    }

    uint64_t range = max - min + 1;
    uint64_t result;
    uint8_t bytes[8];

    if (!quid_random_bytes_internal(bytes, sizeof(bytes))) {
        /* Fallback to simple PRNG */
        result = xorshift64star(g_prng_state[0]);
    } else {
        /* Convert bytes to uint64_t */
        result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | bytes[i];
        }
    }

    /* Use rejection sampling to avoid bias */
    if (range != 0 && range != UINT64_MAX) {
        uint64_t mask = ~((uint64_t)0);
        while (mask & (range - 1)) {
            mask = (mask << 1) | 0x01;
        }

        do {
            if (!quid_random_bytes_internal(bytes, sizeof(bytes))) {
                result = xorshift64star(g_prng_state[0]);
            } else {
                result = 0;
                for (int i = 0; i < 8; i++) {
                    result = (result << 8) | bytes[i];
                }
            }
            result &= mask;
        } while (result >= range);
    }

    return min + result;
}

/**
 * @brief Reseed random number generator
 */
bool quid_random_reseed(const uint8_t* seed, size_t seed_size)
{
    if (!g_random_initialized) {
        return false;
    }

    if (!seed || seed_size == 0) {
        return false;
    }

    /* Mix seed into PRNG state */
    for (size_t i = 0; i < seed_size && i < sizeof(g_prng_state); i++) {
        g_prng_state[i % 4] ^= ((uint64_t)seed[i] << (8 * (i % 8)));
    }

    /* Generate new state */
    for (int i = 0; i < 100; i++) {
        uint64_t rnd = xorshift64star(g_prng_state[0]);
        g_prng_state[0] = g_prng_state[1];
        g_prng_state[1] = g_prng_state[2];
        g_prng_state[2] = g_prng_state[3];
        g_prng_state[3] = rnd;
    }

    g_prng_seeded = true;
    return true;
}

/**
 * @brief PQClean randombytes implementation
 */
int PQCLEAN_randombytes(uint8_t *output, size_t n)
{
    if (!output || n == 0) {
        return -1;
    }

    /* Initialize if not already done */
    if (!g_random_initialized) {
        quid_random_init();
    }

    /* Use our secure random implementation */
    bool success = quid_random_bytes_internal(output, n);
    return success ? 0 : -1;
}
