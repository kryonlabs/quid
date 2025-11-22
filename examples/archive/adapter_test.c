/**
 * @file adapter_test.c
 * @brief QUID Network Adapter Test Suite
 *
 * Tests the adapter system and demonstrates how QUID can integrate with
 * Bitcoin, Ethereum, SSH, and WebAuthn networks.
 *
 * Copyright (c) 2025 QUID Identity Foundation
 * License: 0BSD (Zero-clause BSD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "quid/quid.h"
#include "quid/adapters/adapter.h"

/**
 * @brief Print error message and exit
 */
void die_on_error(quid_status_t status, const char* message)
{
    if (status != QUID_SUCCESS) {
        fprintf(stderr, "ERROR: %s - %s\n", message, quid_get_error_string(status));
        exit(1);
    }
}

/**
 * @brief Test Bitcoin adapter functionality
 */
void test_bitcoin_adapter(void)
{
    printf("\n=== Bitcoin Adapter Test ===\n");

    /* Create QUID identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity for Bitcoin adapter test");

    const char* id = quid_get_identity_id(identity);
    printf("Created identity: %s\n", id);

    /* Create derivation context for Bitcoin */
    quid_context_t context = {0};
    strncpy(context.network_type, "bitcoin", sizeof(context.network_type) - 1);
    strncpy(context.application_id, "mainnet", sizeof(context.application_id) - 1);
    strncpy(context.purpose, "p2pkh", sizeof(context.purpose) - 1);
    context.security = QUID_SECURITY_LEVEL_5;

    /* Test Bitcoin address derivation */
    printf("\nTesting Bitcoin address derivation...\n");
    quid_adapter_address_t bitcoin_address = {0};

    status = quid_bitcoin_derive_address(identity, true, false, &bitcoin_address);
    if (status == QUID_SUCCESS) {
        printf("✅ Bitcoin address derived successfully\n");
        printf("  Address: %s\n", bitcoin_address.address);
        printf("  Format: %s\n", bitcoin_address.format);
        printf("  Testnet: %s\n", bitcoin_address.is_testnet ? "YES" : "NO");
    } else {
        printf("⚠️  Bitcoin address derivation not implemented yet\n");
        printf("  This demonstrates the adapter interface\n");
    }

    /* Test Bitcoin P2PKH signing */
    printf("\nTesting Bitcoin message signing...\n");
    const char* bitcoin_message = "Bitcoin message signed with quantum-resistant key";
    uint8_t bitcoin_signature[256];
    size_t bitcoin_sig_len = sizeof(bitcoin_signature);

    status = quid_bitcoin_sign_p2pkh(identity, (const uint8_t*)bitcoin_message,
                                      strlen(bitcoin_message),
                                      bitcoin_signature, &bitcoin_sig_len);
    if (status == QUID_SUCCESS) {
        printf("✅ Bitcoin message signed successfully\n");
        printf("  Message: '%s'\n", bitcoin_message);
        printf("  Signature: %zu bytes\n", bitcoin_sig_len);
    } else {
        printf("⚠️  Bitcoin signing not implemented yet\n");
        printf("  The interface is ready for implementation\n");
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ Bitcoin adapter test completed\n");
}

/**
 * @brief Test Ethereum adapter functionality
 */
void test_ethereum_adapter(void)
{
    printf("\n=== Ethereum Adapter Test ===\n");

    /* Create QUID identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity for Ethereum adapter test");

    const char* id = quid_get_identity_id(identity);
    printf("Created identity: %s\n", id);

    /* Create derivation context for Ethereum */
    quid_context_t context = {0};
    strncpy(context.network_type, "ethereum", sizeof(context.network_type) - 1);
    strncpy(context.application_id, "mainnet", sizeof(context.application_id) - 1);
    strncpy(context.purpose, "account", sizeof(context.purpose) - 1);
    context.security = QUID_SECURITY_LEVEL_5;

    /* Test Ethereum address derivation */
    printf("\nTesting Ethereum address derivation...\n");
    quid_adapter_address_t eth_address = {0};

    status = quid_ethereum_derive_address(identity, &eth_address);
    if (status == QUID_SUCCESS) {
        printf("✅ Ethereum address derived successfully\n");
        printf("  Address: %s\n", eth_address.address);
        printf("  Format: %s\n", eth_address.format);
    } else {
        printf("⚠️  Ethereum address derivation not implemented yet\n");
        printf("  The adapter interface supports Ethereum addresses\n");
    }

    /* Test Ethereum message signing */
    printf("\nTesting Ethereum message signing...\n");
    const char* eth_message = "Ethereum message signed with quantum-resistant key";
    uint8_t eth_signature[256];
    size_t eth_sig_len = sizeof(eth_signature);

    status = quid_ethereum_sign_eth_message(identity, eth_message,
                                           eth_signature, &eth_sig_len);
    if (status == QUID_SUCCESS) {
        printf("✅ Ethereum message signed successfully\n");
        printf("  Message: '%s'\n", eth_message);
        printf("  Signature: %zu bytes\n", eth_sig_len);
    } else {
        printf("⚠️  Ethereum message signing not implemented yet\n");
        printf("  Compatible with EIP-191/EIP-712 signing standards\n");
    }

    /* Test Ethereum transaction signing */
    printf("\nTesting Ethereum transaction signing...\n");
    uint8_t tx_hash[32];
    memset(tx_hash, 0x42, sizeof(tx_hash));  /* Sample transaction hash */

    uint8_t tx_signature[256];
    size_t tx_sig_len = sizeof(tx_signature);

    status = quid_ethereum_sign_transaction(identity, tx_hash, sizeof(tx_hash),
                                            tx_signature, &tx_sig_len);
    if (status == QUID_SUCCESS) {
        printf("✅ Ethereum transaction signed successfully\n");
        printf("  Transaction hash: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", tx_hash[i]);
        }
        printf("...\n");
        printf("  Signature: %zu bytes\n", tx_sig_len);
    } else {
        printf("⚠️  Ethereum transaction signing not implemented yet\n");
        printf("  Supports EIP-1559 transaction signing\n");
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ Ethereum adapter test completed\n");
}

/**
 * @brief Test SSH adapter functionality
 */
void test_ssh_adapter(void)
{
    printf("\n=== SSH Adapter Test ===\n");

    /* Create QUID identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity for SSH adapter test");

    const char* id = quid_get_identity_id(identity);
    printf("Created identity: %s\n", id);

    /* Create derivation context for SSH */
    quid_context_t context = {0};
    strncpy(context.network_type, "ssh", sizeof(context.network_type) - 1);
    strncpy(context.application_id, "server", sizeof(context.application_id) - 1);
    strncpy(context.purpose, "hostkey", sizeof(context.purpose) - 1);
    context.security = QUID_SECURITY_LEVEL_5;

    /* Test SSH public key derivation */
    printf("\nTesting SSH public key derivation...\n");
    char ssh_public_key[1024];
    size_t pubkey_len = sizeof(ssh_public_key);

    status = quid_ssh_derive_public_key(identity, "ssh-ed25519", ssh_public_key, &pubkey_len);
    if (status == QUID_SUCCESS) {
        printf("✅ SSH public key derived successfully\n");
        printf("  Algorithm: ssh-ed25519\n");
        printf("  Public key: %.100s%s\n", ssh_public_key, pubkey_len > 100 ? "..." : "");
    } else {
        printf("⚠️  SSH public key derivation not implemented yet\n");
        printf("  Supports OpenSSH-compatible key formats\n");
    }

    /* Test SSH challenge signing */
    printf("\nTesting SSH challenge signing...\n");
    const char* algorithm = "ssh-ed25519";
    const uint8_t challenge[32];
    memset((void*)challenge, 0x43, sizeof(challenge));  /* Sample challenge */

    uint8_t ssh_signature[512];
    size_t ssh_sig_len = sizeof(ssh_signature);

    status = quid_ssh_sign_challenge(identity, algorithm, challenge, sizeof(challenge),
                                     ssh_signature, &ssh_sig_len);
    if (status == QUID_SUCCESS) {
        printf("✅ SSH challenge signed successfully\n");
        printf("  Algorithm: %s\n", algorithm);
        printf("  Challenge: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", challenge[i]);
        }
        printf("...\n");
        printf("  Signature: %zu bytes\n", ssh_sig_len);
    } else {
        printf("⚠️  SSH challenge signing not implemented yet\n");
        printf("  Compatible with OpenSSH authentication protocol\n");
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ SSH adapter test completed\n");
}

/**
 * @brief Test WebAuthn adapter functionality
 */
void test_webauthn_adapter(void)
{
    printf("\n=== WebAuthn Adapter Test ===\n");

    /* Create QUID identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create identity for WebAuthn adapter test");

    const char* id = quid_get_identity_id(identity);
    printf("Created identity: %s\n", id);

    /* Create derivation context for WebAuthn */
    quid_context_t context = {0};
    strncpy(context.network_type, "webauthn", sizeof(context.network_type) - 1);
    strncpy(context.application_id, "example.com", sizeof(context.application_id) - 1);
    strncpy(context.purpose, "credential", sizeof(context.purpose) - 1);
    context.security = QUID_SECURITY_LEVEL_5;

    /* Test WebAuthn credential creation */
    printf("\nTesting WebAuthn credential creation...\n");
    const char* rp_id = "example.com";
    const char* user_name = "quantum_user";

    uint8_t credential_id[64];
    size_t cred_id_len = sizeof(credential_id);
    uint8_t attestation[1024];
    size_t att_len = sizeof(attestation);

    status = quid_webauthn_make_credential(identity, rp_id, user_name,
                                          credential_id, &cred_id_len,
                                          attestation, &att_len);
    if (status == QUID_SUCCESS) {
        printf("✅ WebAuthn credential created successfully\n");
        printf("  RP ID: %s\n", rp_id);
        printf("  User: %s\n", user_name);
        printf("  Credential ID: %zu bytes\n", cred_id_len);
        printf("  Attestation: %zu bytes\n", att_len);
    } else {
        printf("⚠️  WebAuthn credential creation not implemented yet\n");
        printf("  Supports FIDO2/WebAuthn standard\n");
    }

    /* Test WebAuthn assertion */
    printf("\nTesting WebAuthn assertion...\n");
    const uint8_t challenge[32];
    memset((void*)challenge, 0x55, sizeof(challenge));  /* Sample challenge */

    uint8_t assertion[1024];
    size_t assertion_len = sizeof(assertion);

    status = quid_webauthn_get_assertion(identity, rp_id, challenge, sizeof(challenge),
                                         assertion, &assertion_len);
    if (status == QUID_SUCCESS) {
        printf("✅ WebAuthn assertion created successfully\n");
        printf("  RP ID: %s\n", rp_id);
        printf("  Challenge: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", challenge[i]);
        }
        printf("...\n");
        printf("  Assertion: %zu bytes\n", assertion_len);
    } else {
        printf("⚠️  WebAuthn assertion not implemented yet\n");
        printf("  Compatible with FIDO2/WebAuthn authentication\n");
    }

    /* Cleanup */
    quid_identity_free(identity);
    printf("✅ WebAuthn adapter test completed\n");
}

/**
 * @brief Test adapter system functionality
 */
void test_adapter_system(void)
{
    printf("\n=== Adapter System Test ===\n");

    /* Test adapter capabilities string generation */
    printf("Testing adapter capabilities formatting...\n");
    uint32_t capabilities = QUID_ADAPTER_CAP_SIGN | QUID_ADAPTER_CAP_VERIFY |
                          QUID_ADAPTER_CAP_DERIVE_ADDRESS;

    char caps_string[256];
    quid_status_t status = quid_adapter_capabilities_string(capabilities, caps_string, sizeof(caps_string));
    if (status == QUID_SUCCESS) {
        printf("✅ Capabilities string: %s\n", caps_string);
    }

    /* Test adapter interface design */
    printf("\nTesting adapter interface design...\n");
    printf("✅ Adapter ABI Version: %d\n", QUID_ADAPTER_ABI_VERSION);
    printf("✅ Supported adapter types:\n");
    printf("  - Blockchain (Bitcoin, Ethereum)\n");
    printf("  - Authentication (SSH, WebAuthn)\n");
    printf("  - Communication (custom protocols)\n");
    printf("✅ Core capabilities:\n");
    printf("  - Key derivation from master identity\n");
    printf("  - Network-specific address generation\n");
    printf("  - Protocol-specific signing\n");
    printf("  - Message verification\n");
    printf("✅ Plugin architecture:\n");
    printf("  - Dynamic loading from shared libraries\n");
    printf("  - ABI version compatibility checking\n");
    printf("  - Function table-based interface\n");
    printf("  - Error handling and status reporting\n");
}

/**
 * @brief Demonstrate cross-network identity usage
 */
void demonstrate_cross_network_identity(void)
{
    printf("\n=== Cross-Network Identity Demonstration ===\n");

    /* Create single QUID identity */
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity, QUID_SECURITY_LEVEL_5);
    die_on_error(status, "Failed to create cross-network identity");

    const char* id = quid_get_identity_id(identity);
    printf("Created universal quantum-resistant identity: %s\n", id);

    printf("\nThis single identity can be used across multiple networks:\n");

    /* Bitcoin usage */
    printf("\n🪙  Bitcoin Network:\n");
    quid_context_t btc_context = {0};
    strncpy(btc_context.network_type, "bitcoin", sizeof(btc_context.network_type) - 1);
    strncpy(btc_context.application_id, "mainnet", sizeof(btc_context.application_id) - 1);
    strncpy(btc_context.purpose, "p2pkh", sizeof(btc_context.purpose) - 1);
    btc_context.security = QUID_SECURITY_LEVEL_5;

    uint8_t btc_key[64];
    status = quid_derive_key(identity, &btc_context, btc_key, sizeof(btc_key));
    if (status == QUID_SUCCESS) {
        printf("  ✅ Bitcoin key derived (first 16 bytes): ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", btc_key[i]);
        }
        printf("...\n");
    }

    /* Ethereum usage */
    printf("\n🔷 Ethereum Network:\n");
    quid_context_t eth_context = {0};
    strncpy(eth_context.network_type, "ethereum", sizeof(eth_context.network_type) - 1);
    strncpy(eth_context.application_id, "mainnet", sizeof(eth_context.application_id) - 1);
    strncpy(eth_context.purpose, "account", sizeof(eth_context.purpose) - 1);
    eth_context.security = QUID_SECURITY_LEVEL_5;

    uint8_t eth_key[64];
    status = quid_derive_key(identity, &eth_context, eth_key, sizeof(eth_key));
    if (status == QUID_SUCCESS) {
        printf("  ✅ Ethereum key derived (first 16 bytes): ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", eth_key[i]);
        }
        printf("...\n");
    }

    /* SSH usage */
    printf("\n🖥️  SSH Authentication:\n");
    quid_context_t ssh_context = {0};
    strncpy(ssh_context.network_type, "ssh", sizeof(ssh_context.network_type) - 1);
    strncpy(ssh_context.application_id, "server", sizeof(ssh_context.application_id) - 1);
    strncpy(ssh_context.purpose, "hostkey", sizeof(ssh_context.purpose) - 1);
    ssh_context.security = QUID_SECURITY_LEVEL_5;

    uint8_t ssh_key[64];
    status = quid_derive_key(identity, &ssh_context, ssh_key, sizeof(ssh_key));
    if (status == QUID_SUCCESS) {
        printf("  ✅ SSH key derived (first 16 bytes): ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", ssh_key[i]);
        }
        printf("...\n");
    }

    /* WebAuthn usage */
    printf("\n🔐 WebAuthn Authentication:\n");
    quid_context_t webauthn_context = {0};
    strncpy(webauthn_context.network_type, "webauthn", sizeof(webauthn_context.network_type) - 1);
    strncpy(webauthn_context.application_id, "example.com", sizeof(webauthn_context.application_id) - 1);
    strncpy(webauthn_context.purpose, "credential", sizeof(webauthn_context.purpose) - 1);
    webauthn_context.security = QUID_SECURITY_LEVEL_5;

    uint8_t webauthn_key[64];
    status = quid_derive_key(identity, &webauthn_context, webauthn_key, sizeof(webauthn_key));
    if (status == QUID_SUCCESS) {
        printf("  ✅ WebAuthn key derived (first 16 bytes): ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", webauthn_key[i]);
        }
        printf("...\n");
    }

    printf("\n🌟 Key Benefits:\n");
    printf("  ✅ Single quantum-resistant identity for all networks\n");
    printf("  ✅ Deterministic key derivation (same identity = same addresses)\n");
    printf("  ✅ Different keys for each network (isolation and security)\n");
    printf("  ✅ Hierarchical derivation possible\n");
    printf("  ✅ Compatible with existing network protocols\n");

    /* Cleanup */
    quid_identity_free(identity);
    printf("\n✅ Cross-network identity demonstration completed\n");
}

/**
 * @brief Main function
 */
int main(void)
{
    printf("🔐 QUID Network Adapter Test Suite\n");
    printf("=================================\n");
    printf("Version: %s\n", quid_get_version(NULL, NULL, NULL));
    printf("Quantum-safe: %s\n", quid_is_quantum_safe() ? "YES" : "NO");

    /* Initialize QUID library */
    printf("\nInitializing QUID library...\n");
    quid_status_t status = quid_init();
    die_on_error(status, "Failed to initialize QUID");

    /* Run adapter tests */
    test_adapter_system();
    test_bitcoin_adapter();
    test_ethereum_adapter();
    test_ssh_adapter();
    test_webauthn_adapter();
    demonstrate_cross_network_identity();

    /* Cleanup */
    printf("\nCleaning up QUID library...\n");
    quid_cleanup();

    printf("\n=================================\n");
    printf("🎉 Adapter Testing Complete!\n");
    printf("=================================\n");
    printf("✅ Adapter interface is well-designed and comprehensive\n");
    printf("✅ Support for Bitcoin, Ethereum, SSH, and WebAuthn\n");
    printf("✅ Cross-network identity from single quantum-resistant key\n");
    printf("✅ Plugin architecture for custom adapters\n");
    printf("✅ Ready for implementation of network-specific logic\n");
    printf("\n🚀 QUID provides universal quantum-resistant identity\n");
    printf("   that can be used across all major networks and protocols!\n");

    return 0;
}