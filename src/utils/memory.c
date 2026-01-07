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
#include <stdio.h>

#ifdef __unix__
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#elif defined(_WIN32)
#include <windows.h>
#include <memoryapi.h>
#endif

#include "memory.h"

/* Memory pool configuration */
#define QUID_MEMORY_POOL_SIZE (64 * 1024)  /* 64KB pool */
#define QUID_MAX_GUARD_REGIONS 16
#define QUID_PAGE_SIZE 4096  /* Default, will be detected */

/* Global memory state */
static bool g_memory_initialized = false;
static size_t g_page_size = 0;

/* Memory pool structure */
typedef struct {
    uint8_t* base;
    size_t size;
    size_t used;
    bool active;
} memory_pool_t;

static memory_pool_t g_memory_pool = {NULL, 0, 0, false};

/* Guard region tracking */
typedef struct {
    void* address;
    size_t size;
    bool in_use;
} guard_region_t;

static guard_region_t g_guard_regions[QUID_MAX_GUARD_REGIONS] = {0};
static size_t g_guard_region_count = 0;

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
 * @brief Detect system page size
 */
static size_t detect_page_size(void)
{
#ifdef __unix__
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0) {
        return (size_t)page_size;
    }
    /* Fallback to getpagesize */
    return (size_t)getpagesize();
#elif defined(_WIN32)
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    return sys_info.dwPageSize;
#else
    /* Default page size */
    return QUID_PAGE_SIZE;
#endif
}

/**
 * @brief Initialize memory pool for small allocations
 */
static bool init_memory_pool(void)
{
    /* Allocate pool with guard pages */
    size_t pool_size = QUID_MEMORY_POOL_SIZE;
    size_t total_size = pool_size + (g_page_size * 2);  /* + guard pages */

#ifdef __unix__
    uint8_t* base = mmap(NULL, total_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
    if (base == MAP_FAILED) {
        return false;
    }

    /* Protect first page (before pool) */
    mprotect(base, g_page_size, PROT_NONE);

    /* Protect last page (after pool) */
    mprotect(base + g_page_size + pool_size, g_page_size, PROT_NONE);

    g_memory_pool.base = base + g_page_size;  /* Pool starts after first guard page */
    g_memory_pool.size = pool_size;
    g_memory_pool.used = 0;
    g_memory_pool.active = true;

    return true;

#elif defined(_WIN32)
    /* Allocate with VirtualAlloc */
    uint8_t* base = VirtualAlloc(NULL, total_size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (!base) {
        return false;
    }

    /* Protect guard pages */
    DWORD old_protect;
    VirtualProtect(base, g_page_size, PAGE_NOACCESS, &old_protect);
    VirtualProtect(base + g_page_size + pool_size, g_page_size, PAGE_NOACCESS, &old_protect);

    g_memory_pool.base = base + g_page_size;
    g_memory_pool.size = pool_size;
    g_memory_pool.used = 0;
    g_memory_pool.active = true;

    return true;
#else
    /* Fallback: no guard pages */
    g_memory_pool.base = calloc(1, pool_size);
    if (!g_memory_pool.base) {
        return false;
    }
    g_memory_pool.size = pool_size;
    g_memory_pool.used = 0;
    g_memory_pool.active = true;
    return true;
#endif
}

/**
 * @brief Cleanup memory pool
 */
static void cleanup_memory_pool(void)
{
    if (!g_memory_pool.active) {
        return;
    }

#ifdef __unix__
    uint8_t* allocation_base = g_memory_pool.base - g_page_size;
    size_t total_size = g_memory_pool.size + (g_page_size * 2);

    /* Zero before unmapping */
    quid_secure_zero(g_memory_pool.base, g_memory_pool.size);

    munmap(allocation_base, total_size);

#elif defined(_WIN32)
    /* Zero and free */
    quid_secure_zero(g_memory_pool.base, g_memory_pool.size);
    VirtualFree(g_memory_pool.base - g_page_size, 0, MEM_RELEASE);
#else
    /* Regular free */
    quid_secure_zero(g_memory_pool.base, g_memory_pool.size);
    free(g_memory_pool.base);
#endif

    g_memory_pool.base = NULL;
    g_memory_pool.size = 0;
    g_memory_pool.used = 0;
    g_memory_pool.active = false;
}

/**
 * @brief Initialize secure memory subsystem
 */
bool quid_memory_init(void)
{
    if (g_memory_initialized) {
        return true;
    }

    /* Detect page size */
    g_page_size = detect_page_size();
    if (g_page_size == 0) {
        g_page_size = QUID_PAGE_SIZE;  /* Use default */
    }

    /* Initialize memory pool with guard pages */
    if (!init_memory_pool()) {
        /* Pool initialization failed, but continue without it */
        /* This is not fatal - allocations will fall back to mmap/malloc */
    }

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

    /* Cleanup memory pool */
    cleanup_memory_pool();

    /* Cleanup guard regions */
    for (size_t i = 0; i < g_guard_region_count; i++) {
        if (g_guard_regions[i].in_use) {
            quid_memory_secure_free(g_guard_regions[i].address, g_guard_regions[i].size);
            g_guard_regions[i].address = NULL;
            g_guard_regions[i].size = 0;
            g_guard_regions[i].in_use = false;
        }
    }
    g_guard_region_count = 0;

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
