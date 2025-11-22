/**
 * @file endian.h
 * @brief Endianness conversion utilities
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#ifndef QUID_ENDIAN_H
#define QUID_ENDIAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Endianness detection and conversion */
#if defined(__BYTE_ORDER__)
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define QUID_LITTLE_ENDIAN 1
        #define QUID_BIG_ENDIAN 0
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define QUID_LITTLE_ENDIAN 0
        #define QUID_BIG_ENDIAN 1
    #else
        #error "Unsupported endianness"
    #endif
#elif defined(_WIN32)
    #define QUID_LITTLE_ENDIAN 1
    #define QUID_BIG_ENDIAN 0
#else
    /* Fallback detection */
    static const uint16_t quid_endian_test = 0x0102;
    #define QUID_LITTLE_ENDIAN (*((const uint8_t*)&quid_endian_test) == 0x02)
    #define QUID_BIG_ENDIAN (!QUID_LITTLE_ENDIAN)
#endif

/* Host to big endian (network byte order) conversion */
static inline uint16_t quid_htobe16(uint16_t host16)
{
    #if QUID_LITTLE_ENDIAN
        return ((host16 >> 8) & 0xFF) | ((host16 & 0xFF) << 8);
    #else
        return host16;
    #endif
}

static inline uint32_t quid_htobe32(uint32_t host32)
{
    #if QUID_LITTLE_ENDIAN
        return ((host32 & 0xFF) << 24) |
               (((host32 >> 8) & 0xFF) << 16) |
               (((host32 >> 16) & 0xFF) << 8) |
               ((host32 >> 24) & 0xFF);
    #else
        return host32;
    #endif
}

static inline uint64_t quid_htobe64(uint64_t host64)
{
    #if QUID_LITTLE_ENDIAN
        return ((host64 & 0xFF) << 56) |
               (((host64 >> 8) & 0xFF) << 48) |
               (((host64 >> 16) & 0xFF) << 40) |
               (((host64 >> 24) & 0xFF) << 32) |
               (((host64 >> 32) & 0xFF) << 24) |
               (((host64 >> 40) & 0xFF) << 16) |
               (((host64 >> 48) & 0xFF) << 8) |
               ((host64 >> 56) & 0xFF);
    #else
        return host64;
    #endif
}

/* Compatibility macros */
#define htobe16 quid_htobe16
#define htobe32 quid_htobe32
#define htobe64 quid_htobe64

#ifdef __cplusplus
}
#endif

#endif /* QUID_ENDIAN_H */