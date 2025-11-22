/**
 * @file memory.c
 * @brief Secure memory management implementation
 *
 * Implements secure memory allocation with protection against
 * side-channel attacks and memory disclosure.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __unix__
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#elif defined(_WIN32)
#include <windows.h>
#include <memoryapi.h>
#endif

#include "memory.h"

/* Global memory state */
static bool g_memory_initialized = false;

/**
 * @brief Compiler barrier to prevent optimization
 */
static inline void memory_barrier(void)
{
#if defined(__GNUC__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

/**
 * @brief Initialize secure memory subsystem
 */
bool quid_memory_init(void)
{
    if (g_memory_initialized) {
        return true;
    }

    /* TODO: Initialize memory protection mechanisms */
    /* This would include:
     * - Page size detection
     * - Memory pool initialization
     * - Side-channel protection setup
     */

    g_memory_initialized = true;
    return true;
}

/**
 * @brief Cleanup secure memory subsystem
 */
void quid_memory_cleanup(void)
{
    if (!g_memory_initialized) {
        return;
    }

    /* TODO: Cleanup memory pools and protections */

    g_memory_initialized = false;
}

/**
 * @brief Allocate secure memory
 */
void* quid_memory_secure_alloc(size_t size)
{
    if (size == 0 || !g_memory_initialized) {
        return NULL;
    }

    /* Align size to page boundary for memory protection */
#ifdef __unix__
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0) {
        size = (size + page_size - 1) & ~(page_size - 1);
    }
#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size = (size + si.dwPageSize - 1) & ~(si.dwPageSize - 1);
#endif

    void* ptr = NULL;

#ifdef __unix__
    /* Use mmap for secure memory allocation */
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }

    /* Try to lock pages in memory */
    if (mlock(ptr, size) != 0) {
        /* Locking failed, but allocation succeeded */
        /* Continue without locking - log warning in production */
    }

    /* Mark pages as non-dumpable */
    if (madvise(ptr, size, MADV_DONTDUMP) != 0) {
        /* Advice failed, but continue */
    }

#elif defined(_WIN32)
    /* Use VirtualAlloc for secure memory allocation */
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        return NULL;
    }

    /* Try to lock pages in memory */
    if (!VirtualLock(ptr, size)) {
        /* Locking failed, but allocation succeeded */
        /* Continue without locking - log warning in production */
    }
#else
    /* Fallback to regular malloc */
    ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }
#endif

    /* Zero allocated memory */
    quid_secure_zero(ptr, size);

    return ptr;
}

/**
 * @brief Free secure memory
 */
void quid_memory_secure_free(void* ptr, size_t size)
{
    if (!ptr || size == 0 || !g_memory_initialized) {
        return;
    }

    /* Zero memory before freeing */
    quid_secure_zero(ptr, size);

#ifdef __unix__
    /* Unlock pages if locked */
    munlock(ptr, size);

    /* Unmap memory */
    if (munmap(ptr, size) != 0) {
        /* Unmapping failed - this is serious */
        /* In production, this should be logged */
    }
#elif defined(_WIN32)
    /* Unlock pages if locked */
    VirtualUnlock(ptr, size);

    /* Free memory */
    if (!VirtualFree(ptr, 0, MEM_RELEASE)) {
        /* Free failed - this is serious */
        /* In production, this should be logged */
    }
#else
    /* Regular free */
    free(ptr);
#endif
}

/**
 * @brief Lock memory pages to prevent swapping
 */
bool quid_memory_lock(const void* ptr, size_t size)
{
    if (!ptr || size == 0 || !g_memory_initialized) {
        return false;
    }

#ifdef __unix__
    return (mlock(ptr, size) == 0);
#elif defined(_WIN32)
    return VirtualLock((void*)ptr, size);
#else
    /* Not supported on this platform */
    return false;
#endif
}

/**
 * @brief Unlock memory pages
 */
void quid_memory_unlock(const void* ptr, size_t size)
{
    if (!ptr || size == 0 || !g_memory_initialized) {
        return;
    }

#ifdef __unix__
    munlock(ptr, size);
#elif defined(_WIN32)
    VirtualUnlock((void*)ptr, size);
#endif
}

/**
 * @brief Zero memory in a secure manner
 */
void quid_secure_zero(void* ptr, size_t size)
{
    if (!ptr || size == 0) {
        return;
    }

    /* Use volatile pointer to prevent optimization */
    volatile uint8_t* p = (volatile uint8_t*)ptr;

    /* Zero memory with memory barriers */
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
        memory_barrier();
    }

    /* Additional memory barrier */
    memory_barrier();
}

/**
 * @brief Compare memory in constant time
 */
int quid_constant_time_compare(const void* a, const void* b, size_t size)
{
    if (!a || !b || size == 0) {
        return -1;
    }

    const volatile uint8_t* ptr_a = (const volatile uint8_t*)a;
    const volatile uint8_t* ptr_b = (const volatile uint8_t*)b;

    uint8_t result = 0;

    /* Constant-time comparison */
    for (size_t i = 0; i < size; i++) {
        result |= ptr_a[i] ^ ptr_b[i];
        memory_barrier();
    }

    /* Convert result to -1, 0, or 1 */
    return (result != 0) ? -1 : 0;
}