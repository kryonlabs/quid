# QUID Adapter Development Guide

## Overview

QUID adapters enable network-specific functionality while maintaining complete separation from the core identity system. This guide provides comprehensive instructions for creating adapters that allow QUID identities to work with any network, protocol, or application.

## Adapter Architecture

### Core Principles

1. **Network Agnostic**: Core QUID knows nothing about specific networks
2. **Deterministic Derivation**: Same network keys generated from same master identity
3. **Ephemeral Operations**: Network keys derived on-demand, never stored
4. **Clean ABI**: Standardized interface works across programming languages
5. **Security First**: All operations must be constant-time and side-channel resistant

### Adapter Interface Specification

```c
#include <quid.h>

// Adapter interface versioning
#define QUID_ADAPTER_API_VERSION_1 1

// Adapter capability flags
#define QUID_CAP_SIGN_CHALLENGE      (1 << 0)  // Can sign authentication challenges
#define QUID_CAP_GENERATE_ADDRESS   (1 << 1)  // Can generate network addresses
#define QUID_CAP_SIGN_MESSAGE       (1 << 2)  // Can sign arbitrary messages
#define QUID_CAP_VERIFY_MESSAGE     (1 << 3)  // Can verify message signatures
#define QUID_CAP_DERIVE_SUBKEYS     (1 << 4)  // Can derive hierarchical keys
#define QUID_CAP_ENCRYPT            (1 << 5)  // Can perform encryption
#define QUID_CAP_DECRYPT            (1 << 6)  // Can perform decryption
#define QUID_CAP_OFFLINE_ONLY       (1 << 7)  // Works completely offline

// Adapter interface structure
typedef struct quid_adapter_interface {
    const char* network_id;            // "bitcoin", "ssh", "web", etc.
    const char* version;               // Adapter version (e.g., "1.0.0")
    uint32_t api_version;              // Interface version
    uint32_t capabilities;             // Bit flags for supported features

    // Key derivation from master identity
    quid_status_t (*derive_keys)(const mldsa_keypair_t* master_key,
                               const quid_context_t* context,
                               void** network_keys);

    // Challenge signing for authentication
    quid_status_t (*sign_challenge)(const void* network_keys,
                                  const uint8_t* challenge,
                                  size_t challenge_len,
                                  uint8_t* signature,
                                  size_t* sig_len);

    // Public key and address generation
    quid_status_t (*generate_address)(const void* network_keys,
                                    char* address,
                                    size_t address_len);

    // Message signing for transactions/operations
    quid_status_t (*sign_message)(const void* network_keys,
                                const uint8_t* message,
                                size_t message_len,
                                uint8_t* signature,
                                size_t* sig_len);

    // Message verification
    quid_status_t (*verify_message)(const void* network_keys,
                                  const uint8_t* message,
                                  size_t message_len,
                                  const uint8_t* signature,
                                  size_t sig_len);

    // Cleanup function for network-specific data
    void (*cleanup)(void* network_keys);

    // Optional: Advanced operations
    quid_status_t (*encrypt)(const void* network_keys,
                           const uint8_t* plaintext,
                           size_t plaintext_len,
                           uint8_t* ciphertext,
                           size_t* ciphertext_len);

    quid_status_t (*decrypt)(const void* network_keys,
                           const uint8_t* ciphertext,
                           size_t ciphertext_len,
                           uint8_t* plaintext,
                           size_t* plaintext_len);
} quid_adapter_t;
```

## Bitcoin Adapter Example

### Complete Implementation

```c
#include <quid.h>
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bitcoin-specific data structures
typedef struct {
    uint8_t private_key[32];           // ECDSA private key (derived)
    secp256k1_pubkey public_key;       // ECDSA public key
    uint8_t compressed_pubkey[33];     // Compressed public key
    char address[36];                  // Bitcoin address (base58check)
    bool initialized;                  // Initialization flag
} bitcoin_keys_t;

// Network-specific constants
#define BITCOIN_CONTEXT_STRING "bitcoin_derivation_context_v1"
#define BITCOIN_ADDRESS_VERSION 0x00   // Mainnet P2PKH
#define BITCOIN_WIF_VERSION 0x80       // Mainnet WIF

// Key derivation implementation
static quid_status_t bitcoin_derive_keys(const mldsa_keypair_t* master_key,
                                        const quid_context_t* context,
                                        void** network_keys) {
    bitcoin_keys_t* keys = NULL;

    // Allocate network-specific key structure
    keys = calloc(1, sizeof(bitcoin_keys_t));
    if (!keys) {
        return QUID_ERROR_MEMORY;
    }

    // Derive Bitcoin private key from ML-DSA master key
    quid_status_t status = quid_derive_network_keys(
        master_key,
        BITCOIN_CONTEXT_STRING,
        context->device_id,  // Use device ID as derivation info
        keys->private_key,
        sizeof(keys->private_key)
    );

    if (status != QUID_SUCCESS) {
        free(keys);
        return status;
    }

    // Initialize secp256k1 context
    secp256k1_context* secp_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (!secp_ctx) {
        free(keys);
        return QUID_ERROR_CRYPTO;
    }

    // Generate public key from private key
    if (!secp256k1_ec_pubkey_create(secp_ctx, &keys->public_key,
                                   keys->private_key)) {
        secp256k1_context_destroy(secp_ctx);
        free(keys);
        return QUID_ERROR_CRYPTO;
    }

    // Compress public key
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(secp_ctx, keys->compressed_pubkey,
                                 &pubkey_len, &keys->public_key,
                                 SECP256K1_EC_COMPRESSED);

    // Generate Bitcoin address
    status = bitcoin_generate_address_internal(keys, keys->address,
                                            sizeof(keys->address));

    secp256k1_context_destroy(secp_ctx);

    if (status != QUID_SUCCESS) {
        free(keys);
        return status;
    }

    keys->initialized = true;
    *network_keys = keys;

    return QUID_SUCCESS;
}

// Internal address generation
static quid_status_t bitcoin_generate_address_internal(bitcoin_keys_t* keys,
                                                    char* address,
                                                    size_t address_len) {
    if (address_len < 36) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // SHA256 hash of compressed public key
    uint8_t sha256_hash[32];
    sha256(keys->compressed_pubkey, 33, sha256_hash);

    // RIPEMD160 hash of SHA256 hash
    uint8_t ripemd160_hash[20];
    ripemd160(sha256_hash, 32, ripemd160_hash);

    // Add version byte (0x00 for mainnet)
    uint8_t versioned_hash[21];
    versioned_hash[0] = BITCOIN_ADDRESS_VERSION;
    memcpy(versioned_hash + 1, ripemd160_hash, 20);

    // Base58Check encoding
    if (!base58check_encode(versioned_hash, 21, address, address_len)) {
        return QUID_ERROR_CRYPTO;
    }

    return QUID_SUCCESS;
}

// Challenge signing implementation
static quid_status_t bitcoin_sign_challenge(const void* network_keys,
                                          const uint8_t* challenge,
                                          size_t challenge_len,
                                          uint8_t* signature,
                                          size_t* sig_len) {
    const bitcoin_keys_t* keys = (const bitcoin_keys_t*)network_keys;

    if (!keys->initialized || *sig_len < 64) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Initialize secp256k1 context
    secp256k1_context* secp_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN
    );
    if (!secp_ctx) {
        return QUID_ERROR_CRYPTO;
    }

    // Create message hash (double SHA256)
    uint8_t msg_hash[32];
    sha256(challenge, challenge_len, msg_hash);
    sha256(msg_hash, 32, msg_hash);

    // Sign the hash
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp_ctx, &sig, msg_hash,
                             keys->private_key, NULL, NULL)) {
        secp256k1_context_destroy(secp_ctx);
        return QUID_ERROR_CRYPTO;
    }

    // Normalize signature to lower-S form
    secp256k1_ecdsa_signature_normalize(secp_ctx, &sig, &sig);

    // Serialize signature in DER format
    size_t der_len = *sig_len;
    if (!secp256k1_ecdsa_signature_serialize_der(secp_ctx, signature,
                                               &der_len, &sig)) {
        secp256k1_context_destroy(secp_ctx);
        return QUID_ERROR_CRYPTO;
    }

    *sig_len = der_len;
    secp256k1_context_destroy(secp_ctx);

    return QUID_SUCCESS;
}

// Address generation implementation
static quid_status_t bitcoin_generate_address(const void* network_keys,
                                            char* address,
                                            size_t address_len) {
    const bitcoin_keys_t* keys = (const bitcoin_keys_t*)network_keys;

    if (!keys->initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Copy pre-generated address
    if (address_len < strlen(keys->address) + 1) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    strcpy(address, keys->address);
    return QUID_SUCCESS;
}

// Message signing implementation
static quid_status_t bitcoin_sign_message(const void* network_keys,
                                         const uint8_t* message,
                                         size_t message_len,
                                         uint8_t* signature,
                                         size_t* sig_len) {
    const bitcoin_keys_t* keys = (const bitcoin_keys_t*)network_keys;

    if (!keys->initialized) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // For Bitcoin message signing, we use the same method as challenge signing
    // but with a different message format
    return bitcoin_sign_challenge(network_keys, message, message_len,
                                 signature, sig_len);
}

// Cleanup implementation
static void bitcoin_cleanup(void* network_keys) {
    bitcoin_keys_t* keys = (bitcoin_keys_t*)network_keys;
    if (keys) {
        // Securely zero sensitive data
        volatile uint8_t* ptr = (volatile uint8_t*)keys->private_key;
        for (size_t i = 0; i < sizeof(keys->private_key); i++) {
            ptr[i] = 0;
        }

        memset(keys, 0, sizeof(bitcoin_keys_t));
        free(keys);
    }
}

// Bitcoin adapter definition
static quid_adapter_t bitcoin_adapter = {
    .network_id = "bitcoin",
    .version = "1.0.0",
    .api_version = QUID_ADAPTER_API_VERSION_1,
    .capabilities = QUID_CAP_SIGN_CHALLENGE |
                    QUID_CAP_GENERATE_ADDRESS |
                    QUID_CAP_SIGN_MESSAGE |
                    QUID_CAP_OFFLINE_ONLY,

    .derive_keys = bitcoin_derive_keys,
    .sign_challenge = bitcoin_sign_challenge,
    .generate_address = bitcoin_generate_address,
    .sign_message = bitcoin_sign_message,
    .verify_message = NULL,  // Not implemented in this example
    .cleanup = bitcoin_cleanup,
    .encrypt = NULL,
    .decrypt = NULL
};

// Adapter initialization function
QUID_API quid_status_t quid_bitcoin_adapter_init(void) {
    return quid_register_adapter(&bitcoin_adapter);
}
```

## SSH Adapter Example

```c
// SSH adapter using Ed25519 keys
typedef struct {
    uint8_t private_key[32];           // Ed25519 private key (derived)
    uint8_t public_key[32];            // Ed25519 public key
    char authorized_key_line[256];     // SSH authorized_keys format
    bool initialized;
} ssh_keys_t;

#define SSH_CONTEXT_STRING "ssh_key_derivation_v1"

static quid_status_t ssh_derive_keys(const mldsa_keypair_t* master_key,
                                    const quid_context_t* context,
                                    void** network_keys) {
    ssh_keys_t* keys = calloc(1, sizeof(ssh_keys_t));
    if (!keys) return QUID_ERROR_MEMORY;

    // Derive Ed25519 key from ML-DSA master key
    quid_status_t status = quid_derive_network_keys(
        master_key, SSH_CONTEXT_STRING, context->device_id,
        keys->private_key, sizeof(keys->private_key)
    );

    if (status != QUID_SUCCESS) {
        free(keys);
        return status;
    }

    // Generate Ed25519 public key
    ed25519_publickey(keys->private_key, keys->public_key);

    // Generate SSH authorized_keys line
    ssh_authorized_keys_format(keys->public_key, keys->authorized_key_line,
                             sizeof(keys->authorized_key_line));

    keys->initialized = true;
    *network_keys = keys;
    return QUID_SUCCESS;
}

static quid_status_t ssh_sign_challenge(const void* network_keys,
                                       const uint8_t* challenge,
                                       size_t challenge_len,
                                       uint8_t* signature,
                                       size_t* sig_len) {
    const ssh_keys_t* keys = (const ssh_keys_t*)network_keys;

    if (!keys->initialized || *sig_len < 64) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Ed25519 signing
    ed25519_sign(challenge, challenge_len, keys->private_key, signature);
    *sig_len = 64;

    return QUID_SUCCESS;
}

static quid_status_t ssh_generate_address(const void* network_keys,
                                         char* address,
                                         size_t address_len) {
    const ssh_keys_t* keys = (const ssh_keys_t*)network_keys;

    if (!keys->initialized || address_len < strlen(keys->authorized_key_line) + 1) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    strcpy(address, keys->authorized_key_line);
    return QUID_SUCCESS;
}

static void ssh_cleanup(void* network_keys) {
    ssh_keys_t* keys = (ssh_keys_t*)network_keys;
    if (keys) {
        // Secure zero
        volatile uint8_t* ptr = (volatile uint8_t*)keys->private_key;
        for (size_t i = 0; i < sizeof(keys->private_key); i++) {
            ptr[i] = 0;
        }

        memset(keys, 0, sizeof(ssh_keys_t));
        free(keys);
    }
}

static quid_adapter_t ssh_adapter = {
    .network_id = "ssh",
    .version = "1.0.0",
    .api_version = QUID_ADAPTER_API_VERSION_1,
    .capabilities = QUID_CAP_SIGN_CHALLENGE |
                    QUID_CAP_GENERATE_ADDRESS |
                    QUID_CAP_OFFLINE_ONLY,

    .derive_keys = ssh_derive_keys,
    .sign_challenge = ssh_sign_challenge,
    .generate_address = ssh_generate_address,
    .sign_message = ssh_sign_challenge,
    .verify_message = NULL,
    .cleanup = ssh_cleanup
};

QUID_API quid_status_t quid_ssh_adapter_init(void) {
    return quid_register_adapter(&ssh_adapter);
}
```

## WebAuthn Adapter Example

```c
// WebAuthn adapter for web authentication
typedef struct {
    uint8_t private_key[32];           // ECDSA P-256 private key
    uint8_t public_key[65];            // Uncompressed P-256 public key
    uint8_t credential_id[32];         // WebAuthn credential ID
    char origin[256];                  // Relying party origin
    bool initialized;
} webauthn_keys_t;

#define WEBAUTHN_CONTEXT_STRING "webauthn_derivation_v1"

static quid_status_t webauthn_derive_keys(const mldsa_keypair_t* master_key,
                                         const quid_context_t* context,
                                         void** network_keys) {
    webauthn_keys_t* keys = calloc(1, sizeof(webauthn_keys_t));
    if (!keys) return QUID_ERROR_MEMORY;

    // Extract origin from context
    strncpy(keys->origin, context->application_id, sizeof(keys->origin) - 1);

    // Derive P-256 key from ML-DSA master key
    quid_status_t status = quid_derive_network_keys(
        master_key, WEBAUTHN_CONTEXT_STRING, context->application_id,
        keys->private_key, sizeof(keys->private_key)
    );

    if (status != QUID_SUCCESS) {
        free(keys);
        return status;
    }

    // Generate P-256 public key
    p256_public_key(keys->private_key, keys->public_key);

    // Generate credential ID (hash of public key + origin)
    uint8_t credential_data[sizeof(keys->public_key) + sizeof(keys->origin)];
    memcpy(credential_data, keys->public_key, sizeof(keys->public_key));
    memcpy(credential_data + sizeof(keys->public_key), keys->origin,
           sizeof(keys->origin));

    sha256(credential_data, sizeof(credential_data), keys->credential_id);

    keys->initialized = true;
    *network_keys = keys;
    return QUID_SUCCESS;
}

static quid_status_t webauthn_sign_challenge(const void* network_keys,
                                            const uint8_t* challenge,
                                            size_t challenge_len,
                                            uint8_t* signature,
                                            size_t* sig_len) {
    const webauthn_keys_t* keys = (const webauthn_keys_t*)network_keys;

    if (!keys->initialized || *sig_len < 64) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Create WebAuthn client data JSON
    char client_data[512];
    snprintf(client_data, sizeof(client_data),
             "{\"type\":\"webauthn.get\",\"challenge\":\"%.*s\",\"origin\":\"%s\"}",
             (int)challenge_len, challenge, keys->origin);

    // Hash client data
    uint8_t client_data_hash[32];
    sha256((uint8_t*)client_data, strlen(client_data), client_data_hash);

    // Create authenticator data (simplified)
    uint8_t auth_data[32];
    memset(auth_data, 0, sizeof(auth_data));
    // RP ID hash would go here in real implementation

    // Concatenate auth_data + client_data_hash
    uint8_t message[sizeof(auth_data) + sizeof(client_data_hash)];
    memcpy(message, auth_data, sizeof(auth_data));
    memcpy(message + sizeof(auth_data), client_data_hash, sizeof(client_data_hash));

    // Sign with P-256
    p256_sign(message, sizeof(message), keys->private_key, signature);
    *sig_len = 64;

    return QUID_SUCCESS;
}

static quid_status_t webauthn_generate_address(const void* network_keys,
                                              char* address,
                                              size_t address_len) {
    const webauthn_keys_t* keys = (const webauthn_keys_t*)network_keys;

    if (!keys->initialized || address_len < 65) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Return base64url-encoded credential ID
    return base64url_encode(keys->credential_id, sizeof(keys->credential_id),
                           address, address_len);
}

static void webauthn_cleanup(void* network_keys) {
    webauthn_keys_t* keys = (webauthn_keys_t*)network_keys;
    if (keys) {
        volatile uint8_t* ptr = (volatile uint8_t*)keys->private_key;
        for (size_t i = 0; i < sizeof(keys->private_key); i++) {
            ptr[i] = 0;
        }

        memset(keys, 0, sizeof(webauthn_keys_t));
        free(keys);
    }
}

static quid_adapter_t webauthn_adapter = {
    .network_id = "webauthn",
    .version = "1.0.0",
    .api_version = QUID_ADAPTER_API_VERSION_1,
    .capabilities = QUID_CAP_SIGN_CHALLENGE |
                    QUID_CAP_GENERATE_ADDRESS |
                    QUID_CAP_OFFLINE_ONLY,

    .derive_keys = webauthn_derive_keys,
    .sign_challenge = webauthn_sign_challenge,
    .generate_address = webauthn_generate_address,
    .sign_message = webauthn_sign_challenge,
    .verify_message = NULL,
    .cleanup = webauthn_cleanup
};

QUID_API quid_status_t quid_webauthn_adapter_init(void) {
    return quid_register_adapter(&webauthn_adapter);
}
```

## Key Derivation Guidelines

### Security Requirements

1. **Deterministic**: Same master key + context = same derived key
2. **Domain Separation**: Different contexts produce unrelated keys
3. **Cryptographically Strong**: Use SHAKE256 or equivalent XOF
4. **Constant-Time**: Prevent timing attacks

### Recommended Derivation Function

```c
quid_status_t quid_derive_network_keys(const mldsa_keypair_t* master_key,
                                       const char* context_string,
                                       const char* derivation_info,
                                       uint8_t* derived_key,
                                       size_t derived_key_len) {
    // HKDF-like derivation using SHAKE256
    shake256_context ctx;
    shake256_init(&ctx);

    // Domain separation with context string
    shake256_absorb(&ctx, (uint8_t*)"QUID_KEY_DERIVATION_V1", 22);
    shake256_absorb(&ctx, (uint8_t*)context_string, strlen(context_string));

    // Include master private key
    shake256_absorb(&ctx, master_key->private_key, MLDSA_PRIVATE_KEYBYTES);

    // Add derivation information
    if (derivation_info && strlen(derivation_info) > 0) {
        shake256_absorb(&ctx, (uint8_t*)derivation_info, strlen(derivation_info));
    }

    // Generate derived key
    shake256_squeeze(&ctx, derived_key, derived_key_len);
    shake256_final(&ctx);

    return QUID_SUCCESS;
}
```

### Context String Guidelines

- Use descriptive names: `"bitcoin_derivation_context_v1"`
- Include version numbers for future compatibility
- Be consistent across implementations
- Document context strings in adapter specifications

## Adapter Registration

### Registration Process

```c
// In adapter initialization
quid_status_t my_adapter_init(void) {
    // Validate adapter structure
    if (!my_adapter.network_id || !my_adapter.derive_keys || !my_adapter.cleanup) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Register with QUID core
    quid_status_t status = quid_register_adapter(&my_adapter);
    if (status != QUID_SUCCESS) {
        return status;
    }

    // Perform adapter-specific initialization
    return my_adapter_specific_init();
}

// Load adapter dynamically
quid_status_t load_adapter_from_library(const char* library_path) {
    void* handle = dlopen(library_path, RTLD_LAZY);
    if (!handle) {
        return QUID_ERROR_HARDWARE;
    }

    typedef quid_status_t (*init_func_t)(void);
    init_func_t init_func = (init_func_t)dlsym(handle, "quid_adapter_init");

    if (!init_func) {
        dlclose(handle);
        return QUID_ERROR_INVALID_PARAMETER;
    }

    return init_func();
}
```

## Testing Guidelines

### Unit Testing

```c
void test_bitcoin_adapter(void) {
    quid_identity_t* identity = NULL;
    quid_auth_request_t request = {0};
    quid_auth_response_t response = {0};

    // Create test identity
    assert(quid_identity_create(&identity) == QUID_SUCCESS);

    // Initialize Bitcoin adapter
    assert(quid_bitcoin_adapter_init() == QUID_SUCCESS);

    // Prepare Bitcoin authentication request
    strcpy(request.context.network_type, "bitcoin");
    strcpy(request.context.application_id, "test-wallet");
    request.context.security_level = 3;

    // Generate random challenge
    quid_secure_random(request.challenge, sizeof(request.challenge));
    request.challenge_len = 32;

    // Test authentication
    assert(quid_authenticate(identity, &request, &response) == QUID_SUCCESS);

    // Verify signature (implementation-specific)
    assert(verify_bitcoin_signature(&response) == true);

    // Cleanup
    quid_identity_free(identity);
}
```

### Integration Testing

```c
void test_cross_platform_derivation(void) {
    // Test that same identity produces same Bitcoin address on different platforms
    quid_identity_t* identity1 = NULL;
    quid_identity_t* identity2 = NULL;

    // Create two identical identities from same seed
    uint8_t seed[32] = {0};  // Test seed
    assert(quid_identity_from_seed(&identity1, seed, sizeof(seed)) == QUID_SUCCESS);
    assert(quid_identity_from_seed(&identity2, seed, sizeof(seed)) == QUID_SUCCESS);

    // Derive Bitcoin keys on both
    bitcoin_keys_t* keys1 = NULL;
    bitcoin_keys_t* keys2 = NULL;

    quid_context_t context = {0};
    strcpy(context.network_type, "bitcoin");
    strcpy(context.application_id, "test");

    assert(bitcoin_derive_keys(&identity1->master_keypair, &context,
                              (void**)&keys1) == QUID_SUCCESS);
    assert(bitcoin_derive_keys(&identity2->master_keypair, &context,
                              (void**)&keys2) == QUID_SUCCESS);

    // Verify deterministic derivation
    assert(memcmp(keys1->private_key, keys2->private_key, 32) == 0);
    assert(strcmp(keys1->address, keys2->address) == 0);

    // Cleanup
    bitcoin_cleanup(keys1);
    bitcoin_cleanup(keys2);
    quid_identity_free(identity1);
    quid_identity_free(identity2);
}
```

## Performance Optimization

### Memory Management

```c
// Use memory pools for frequent allocations
typedef struct {
    bitcoin_keys_t keys[16];           // Pre-allocated key structures
    bool used[16];                     // Usage flags
    size_t next_free;                  // Next free slot
} bitcoin_key_pool_t;

static bitcoin_key_pool_t key_pool = {0};

static quid_status_t bitcoin_derive_keys_pooled(const mldsa_keypair_t* master_key,
                                               const quid_context_t* context,
                                               void** network_keys) {
    // Find free slot in pool
    size_t slot = key_pool.next_free;
    for (size_t i = 0; i < 16; i++) {
        size_t test_slot = (slot + i) % 16;
        if (!key_pool.used[test_slot]) {
            slot = test_slot;
            break;
        }
    }

    if (key_pool.used[slot]) {
        // Pool full, fall back to malloc
        return bitcoin_derive_keys_malloc(master_key, context, network_keys);
    }

    bitcoin_keys_t* keys = &key_pool.keys[slot];
    key_pool.used[slot] = true;
    key_pool.next_free = (slot + 1) % 16;

    // Initialize keys (reuse pooled memory)
    memset(keys, 0, sizeof(bitcoin_keys_t));

    // Continue with normal derivation...

    *network_keys = keys;
    return QUID_SUCCESS;
}
```

### Constant-Time Operations

```c
// Constant-time memory comparison
static int constant_time_memcmp(const void* a, const void* b, size_t len) {
    const volatile uint8_t* va = (const volatile uint8_t*)a;
    const volatile uint8_t* vb = (const volatile uint8_t*)b;
    uint8_t result = 0;

    for (size_t i = 0; i < len; i++) {
        result |= va[i] ^ vb[i];
    }

    return result;  // 0 if equal, non-zero if different
}

// Constant-time string length
static size_t constant_time_strlen(const char* str) {
    size_t len = 0;
    const char* p = str;

    // Find null terminator
    while (*p) {
        p++;
        len++;
    }

    return len;
}
```

## Security Considerations

### Side-Channel Protection

1. **Constant-Time Operations**: All cryptographic operations must be constant-time
2. **Memory Protection**: Use secure memory allocation for private keys
3. **Cache Isolation**: Avoid cache-timing attacks in key derivation
4. **Input Validation**: Validate all inputs to prevent injection attacks

### Error Handling

```c
// Secure error handling without information leakage
quid_status_t secure_derive_keys(const mldsa_keypair_t* master_key,
                                 const quid_context_t* context,
                                 void** network_keys) {
    // Validate inputs without revealing specific failure reasons
    if (!master_key || !context || !network_keys) {
        // Always return same error code for validation failures
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Use constant-time validation
    if (constant_time_memcmp(master_key->private_key,
                            zero_key, sizeof(zero_key)) == 0) {
        return QUID_ERROR_INVALID_PARAMETER;
    }

    // Continue with derivation...
}
```

### Audit Requirements

1. **Code Review**: Peer review of all cryptographic implementations
2. **Formal Verification**: Where possible, use formally verified algorithms
3. **Penetration Testing**: Regular security assessments
4. **Compliance**: Adherence to relevant security standards

This adapter development guide provides everything needed to create secure, performant adapters that extend QUID's quantum-resistant identity to any network or protocol.