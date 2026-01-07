/**
 * @file adapter_loader.c
 * @brief QUID Adapter Loading Implementation
 *
 * Implements hybrid adapter loading: static registry for linked adapters
 * and dynamic loading from shared libraries. Provides runtime adapter
 * discovery and management functionality.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>  /* Dynamic library loading */

#include "quid/quid.h"
#include "quid/adapters/adapter.h"

/* Static adapter declarations - unique symbols to avoid conflicts */
extern quid_adapter_functions_t* bitcoin_quid_adapter_get_functions(void);
extern quid_adapter_functions_t* ssh_quid_adapter_get_functions(void);
extern quid_adapter_functions_t* webauthn_quid_adapter_get_functions(void);

/* Maximum number of loaded adapters */
#define MAX_LOADED_ADAPTERS 16

/* Static adapter registry entry */
typedef struct {
    quid_network_type_t network;
    const char* name;
    quid_adapter_functions_t* (*get_functions_fn)(void);
    bool is_available;
} static_adapter_entry_t;

/* Static adapter registry - built-in adapters linked at compile time */
static static_adapter_entry_t g_static_adapters[] = {
    { QUID_NETWORK_BITCOIN, "Bitcoin", bitcoin_quid_adapter_get_functions, false },
    { QUID_NETWORK_SSH, "SSH", ssh_quid_adapter_get_functions, false },
    { QUID_NETWORK_WEBAUTHN, "WebAuthn", webauthn_quid_adapter_get_functions, false },
};
static const size_t g_static_adapter_count = sizeof(g_static_adapters) / sizeof(g_static_adapters[0]);

/* Loaded adapter tracking */
typedef struct {
    char library_path[512];
    void* handle;
    quid_adapter_t* adapter;
    bool is_loaded;
    bool is_static;  /* true = statically linked, false = dynamically loaded */
} loaded_adapter_t;

/* Global adapter registry */
static loaded_adapter_t g_loaded_adapters[MAX_LOADED_ADAPTERS];
static int g_adapter_count = 0;
static bool g_loader_initialized = false;

/**
 * @brief Initialize adapter loader
 */
static bool init_adapter_loader(void)
{
    if (g_loader_initialized) {
        return true;
    }

    /* Clear adapter registry */
    memset(g_loaded_adapters, 0, sizeof(g_loaded_adapters));
    g_adapter_count = 0;

    /* Probe static adapters for availability */
    for (size_t i = 0; i < g_static_adapter_count; i++) {
        g_static_adapters[i].is_available = false;

        /* Try to call the get_functions function to check if adapter is linked */
        if (g_static_adapters[i].get_functions_fn) {
            quid_adapter_functions_t* funcs = g_static_adapters[i].get_functions_fn();
            if (funcs && funcs->abi_version == QUID_ADAPTER_ABI_VERSION) {
                g_static_adapters[i].is_available = true;
            }
        }
    }

    g_loader_initialized = true;
    return true;
}

/**
 * @brief Cleanup adapter loader
 */
static void cleanup_adapter_loader(void)
{
    if (!g_loader_initialized) {
        return;
    }

    /* Unload all adapters */
    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded) {
            quid_adapter_unload(g_loaded_adapters[i].adapter);
        }
    }

    g_adapter_count = 0;
    g_loader_initialized = false;
}

/**
 * @brief Find free adapter slot
 */
static int find_free_slot(void)
{
    for (int i = 0; i < MAX_LOADED_ADAPTERS; i++) {
        if (!g_loaded_adapters[i].is_loaded) {
            return i;
        }
    }
    return -1;  /* No free slots */
}

/**
 * @brief Internal helper to initialize adapter from function table
 */
static quid_status_t init_adapter_from_functions(
    quid_adapter_functions_t* functions,
    const quid_adapter_context_t* context,
    const char* source_name,
    bool is_static,
    void* handle,
    int slot,
    quid_adapter_t** adapter)
{
    if (!functions) {
        return QUID_ERROR_ADAPTER_ERROR;
    }

    /* Validate function table */
    if (functions->abi_version != QUID_ADAPTER_ABI_VERSION) {
        fprintf(stderr, "Adapter ABI version mismatch in '%s'\n", source_name);
        return QUID_ERROR_INVALID_FORMAT;
    }

    if (!functions->init || !functions->cleanup || !functions->get_info) {
        fprintf(stderr, "Required adapter functions missing in '%s'\n", source_name);
        return QUID_ERROR_ADAPTER_ERROR;
    }

    /* Initialize adapter */
    quid_adapter_t* new_adapter = functions->init(context);
    if (!new_adapter) {
        fprintf(stderr, "Failed to initialize adapter from '%s'\n", source_name);
        return QUID_ERROR_ADAPTER_ERROR;
    }

    /* Validate adapter */
    if (!new_adapter->is_initialized) {
        fprintf(stderr, "Adapter not properly initialized from '%s'\n", source_name);
        functions->cleanup(new_adapter);
        return QUID_ERROR_ADAPTER_ERROR;
    }

    /* Store adapter information */
    strncpy(g_loaded_adapters[slot].library_path, source_name,
            sizeof(g_loaded_adapters[slot].library_path) - 1);
    g_loaded_adapters[slot].handle = handle;
    g_loaded_adapters[slot].adapter = new_adapter;
    g_loaded_adapters[slot].is_loaded = true;
    g_loaded_adapters[slot].is_static = is_static;

    /* Store function pointer in adapter for convenience */
    new_adapter->functions = functions;

    if (slot >= g_adapter_count) {
        g_adapter_count = slot + 1;
    }

    *adapter = new_adapter;
    return QUID_SUCCESS;
}

/**
 * @brief Load adapter by network type (hybrid: static first, then dynamic)
 */
quid_status_t quid_adapter_load_by_network(quid_network_type_t network_type,
                                           const quid_adapter_context_t* context,
                                           quid_adapter_t** adapter)
{
    if (!adapter) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!g_loader_initialized) {
        if (!init_adapter_loader()) {
            return QUID_ERROR_MEMORY_ALLOCATION;
        }
    }

    /* First, check if adapter is already loaded */
    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded &&
            g_loaded_adapters[i].adapter->info.network_type == network_type) {
            *adapter = g_loaded_adapters[i].adapter;
            return QUID_SUCCESS;
        }
    }

    /* Try static adapter registry first */
    for (size_t i = 0; i < g_static_adapter_count; i++) {
        if (g_static_adapters[i].network == network_type && g_static_adapters[i].is_available) {
            int slot = find_free_slot();
            if (slot < 0) {
                return QUID_ERROR_MEMORY_ALLOCATION;
            }

            quid_adapter_functions_t* functions = g_static_adapters[i].get_functions_fn();
            quid_status_t status = init_adapter_from_functions(
                functions, context, g_static_adapters[i].name, true, NULL, slot, adapter);

            if (status == QUID_SUCCESS) {
                return QUID_SUCCESS;
            }
        }
    }

    /* Static adapter not found, return error */
    /* Note: Could fall back to dynamic loading here if library path is known */
    return QUID_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief Load adapter from shared library
 */
quid_status_t quid_adapter_load(const char* library_path,
                                const quid_adapter_context_t* context,
                                quid_adapter_t** adapter)
{
    if (!library_path || !adapter) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    if (!g_loader_initialized) {
        if (!init_adapter_loader()) {
            return QUID_ERROR_MEMORY_ALLOCATION;
        }
    }

    /* Check if adapter is already loaded */
    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded &&
            strcmp(g_loaded_adapters[i].library_path, library_path) == 0) {
            *adapter = g_loaded_adapters[i].adapter;
            return QUID_SUCCESS;
        }
    }

    /* Find free slot */
    int slot = find_free_slot();
    if (slot < 0) {
        return QUID_ERROR_MEMORY_ALLOCATION;  /* No space for more adapters */
    }

    /* Load shared library */
    void* handle = dlopen(library_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to load adapter library '%s': %s\n",
                library_path, dlerror());
        return QUID_ERROR_INVALID_FORMAT;
    }

    /* Get adapter function table */
    typedef quid_adapter_functions_t* (*get_functions_fn)(void);
    get_functions_fn get_functions = (get_functions_fn)dlsym(handle, "quid_adapter_get_functions");

    if (!get_functions) {
        fprintf(stderr, "Failed to find quid_adapter_get_functions in '%s': %s\n",
                library_path, dlerror());
        dlclose(handle);
        return QUID_ERROR_NOT_IMPLEMENTED;
    }

    /* Get function table */
    quid_adapter_functions_t* functions = get_functions();
    if (!functions) {
        fprintf(stderr, "Adapter function table is NULL in '%s'\n", library_path);
        dlclose(handle);
        return QUID_ERROR_ADAPTER_ERROR;
    }

    /* Use common initialization */
    quid_status_t status = init_adapter_from_functions(
        functions, context, library_path, false, handle, slot, adapter);

    if (status != QUID_SUCCESS) {
        dlclose(handle);
        return status;
    }

    return QUID_SUCCESS;
}

/**
 * @brief Unload adapter
 */
void quid_adapter_unload(quid_adapter_t* adapter)
{
    if (!adapter || !g_loader_initialized) {
        return;
    }

    /* Find adapter in registry */
    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded &&
            g_loaded_adapters[i].adapter == adapter) {

            /* Call cleanup function */
            if (adapter->functions && adapter->functions->cleanup) {
                adapter->functions->cleanup(adapter);
            }

            /* Close shared library only for dynamically loaded adapters */
            if (!g_loaded_adapters[i].is_static && g_loaded_adapters[i].handle) {
                dlclose(g_loaded_adapters[i].handle);
            }

            /* Clear slot */
            memset(&g_loaded_adapters[i], 0, sizeof(loaded_adapter_t));
            return;
        }
    }
}

/**
 * @brief Get adapter capabilities as string
 */
quid_status_t quid_adapter_capabilities_string(uint32_t capabilities,
                                               char* buffer,
                                               size_t buffer_size)
{
    if (!buffer || buffer_size == 0) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    buffer[0] = '\0';

    if (capabilities & QUID_ADAPTER_CAP_SIGN) {
        strncat(buffer, "sign ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_VERIFY) {
        strncat(buffer, "verify ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_ENCRYPT) {
        strncat(buffer, "encrypt ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_DECRYPT) {
        strncat(buffer, "decrypt ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_DERIVE_ADDRESS) {
        strncat(buffer, "derive_address ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_DERIVE_PUBLIC) {
        strncat(buffer, "derive_public ", buffer_size - strlen(buffer) - 1);
    }
    if (capabilities & QUID_ADAPTER_CAP_BATCH_OPERATIONS) {
        strncat(buffer, "batch ", buffer_size - strlen(buffer) - 1);
    }

    /* Remove trailing space */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == ' ') {
        buffer[len-1] = '\0';
    }

    return QUID_SUCCESS;
}

/**
 * @brief Check if adapter supports capability
 */
bool quid_adapter_supports(const quid_adapter_t* adapter,
                           quid_adapter_capabilities_t capability)
{
    if (!adapter) {
        return false;
    }

    return (adapter->info.capabilities & capability) != 0;
}

/**
 * @brief List all loaded adapters
 */
int quid_adapter_list_loaded(quid_adapter_t** adapters,
                             int max_adapters)
{
    if (!adapters || max_adapters <= 0 || !g_loader_initialized) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < g_adapter_count && count < max_adapters; i++) {
        if (g_loaded_adapters[i].is_loaded) {
            adapters[count++] = g_loaded_adapters[i].adapter;
        }
    }

    return count;
}

/**
 * @brief Find loaded adapter by name
 */
quid_adapter_t* quid_adapter_find_by_name(const char* name)
{
    if (!name || !g_loader_initialized) {
        return NULL;
    }

    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded &&
            strcmp(g_loaded_adapters[i].adapter->info.name, name) == 0) {
            return g_loaded_adapters[i].adapter;
        }
    }

    return NULL;
}

/**
 * @brief Find loaded adapter by network type
 */
quid_adapter_t* quid_adapter_find_by_network(quid_network_type_t network_type)
{
    if (!g_loader_initialized) {
        return NULL;
    }

    for (int i = 0; i < g_adapter_count; i++) {
        if (g_loaded_adapters[i].is_loaded &&
            g_loaded_adapters[i].adapter->info.network_type == network_type) {
            return g_loaded_adapters[i].adapter;
        }
    }

    return NULL;
}

/**
 * @brief Get adapter information string
 */
quid_status_t quid_adapter_get_info_string(const quid_adapter_t* adapter,
                                           char* buffer,
                                           size_t buffer_size)
{
    if (!adapter || !buffer || buffer_size == 0) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    const quid_adapter_info_t* info = &adapter->info;
    int result = snprintf(buffer, buffer_size,
                         "Adapter: %s v%s\n"
                         "Network: %s (type %d)\n"
                         "Capabilities: 0x%08x\n"
                         "Author: %s\n"
                         "License: %s\n"
                         "Description: %s",
                         info->name, info->version,
                         info->network_name, info->network_type,
                         info->capabilities,
                         info->author, info->license,
                         info->description);

    return (result >= 0 && result < (int)buffer_size) ? QUID_SUCCESS : QUID_ERROR_BUFFER_TOO_SMALL;
}