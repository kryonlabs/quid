# QUID Quick Start Guide

Get up and running with QUID in **15 minutes**. This guide walks you through installing QUID, creating your first quantum-resistant identity, and performing authentication.

## Prerequisites

- **C Compiler**: GCC 4.9+, Clang 3.5+, or MSVC 2015+
- **Git**: For cloning the repository
- **Make**: For building (on Unix systems)
- **CMake**: 3.12+ (optional, for advanced builds)

## 15-Minute Quick Start

### Step 1: Installation (2 minutes)

#### Linux/macOS
```bash
# Clone QUID repository
git clone https://github.com/quid-identity/quid-core
cd quid-core

# Build and install
make
sudo make install

# Verify installation
quid --version
# Expected output: QUID 1.0.0
```

#### Windows
```powershell
# Clone using Git for Windows
git clone https://github.com/quid-identity/quid-core
cd quid-core

# Build with Visual Studio Developer Command Prompt
mkdir build
cd build
cmake ..
cmake --build . --config Release

# Verify installation
.\Release\quid.exe --version
```

### Step 2: Create Your First Identity (3 minutes)

Create a file `first_identity.c`:

```c
#include <quid.h>
#include <stdio.h>

int main() {
    printf("🔐 Creating your quantum-resistant identity...\n");

    // Create new QUID identity
    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_create(&identity);

    if (status != QUID_SUCCESS) {
        fprintf(stderr, "❌ Failed to create identity: %s\n",
                quid_get_error_string(status));
        return 1;
    }

    printf("✅ Identity created successfully!\n");
    printf("📋 Your QUID ID: %s\n", quid_get_identity_id(identity));
    printf("🕐 Created: %lu\n", identity->creation_timestamp);

    // Save identity to encrypted file
    uint8_t* backup_data = NULL;
    size_t backup_len = 0;
    status = quid_identity_backup(identity, "my_secure_password",
                                 &backup_data, &backup_len);

    if (status == QUID_SUCCESS) {
        FILE* file = fopen("quid_identity.backup", "wb");
        fwrite(backup_data, 1, backup_len, file);
        fclose(file);
        quid_secure_free(backup_data, backup_len);
        printf("💾 Identity saved to 'quid_identity.backup'\n");
    }

    // Clean up
    quid_identity_free(identity);

    printf("\n🎉 Congratulations! You now own a quantum-resistant digital identity!\n");
    printf("📚 Next: Learn how to use it for authentication\n");

    return 0;
}
```

#### Compile and Run:
```bash
gcc -o first_identity first_identity.c -lquid
./first_identity
```

**Expected Output:**
```
🔐 Creating your quantum-resistant identity...
✅ Identity created successfully!
📋 Your QUID ID: 7f3b9a1c2d4e5f67890123456789abcdef1234567890abcdef1234567890abcdef
🕐 Created: 1703020800
💾 Identity saved to 'quid_identity.backup'

🎉 Congratulations! You now own a quantum-resistant digital identity!
📚 Next: Learn how to use it for authentication
```

### Step 3: Your First Authentication (5 minutes)

Create `authenticate.c`:

```c
#include <quid.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main() {
    printf("🔐 Loading your quantum-resistant identity...\n");

    // Load identity from backup
    FILE* file = fopen("quid_identity.backup", "rb");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* backup_data = malloc(file_size);
    fread(backup_data, 1, file_size, file);
    fclose(file);

    quid_identity_t* identity = NULL;
    quid_status_t status = quid_identity_load(backup_data, file_size,
                                           "my_secure_password", &identity);

    free(backup_data);

    if (status != QUID_SUCCESS) {
        fprintf(stderr, "❌ Failed to load identity: %s\n",
                quid_get_error_string(status));
        return 1;
    }

    printf("✅ Identity loaded: %s\n", quid_get_identity_id(identity));

    // Simulate service authentication request
    printf("\n🌐 Simulating authentication to 'my-app.com'...\n");

    quid_auth_request_t request = {0};
    request.timestamp = time(NULL);
    request.expiration_seconds = 300; // 5 minutes

    // Set authentication context
    strcpy(request.context.network_type, "web");
    strcpy(request.context.application_id, "my-app.com");
    strcpy(request.context.device_id, "user-laptop-001");
    request.context.security_level = 3;

    // Generate cryptographic challenge
    quid_secure_random(request.challenge, sizeof(request.challenge));
    request.challenge_len = 32;

    printf("📨 Received authentication challenge (%zu bytes)\n",
           request.challenge_len);

    // Perform authentication
    quid_auth_response_t response = {0};
    status = quid_authenticate(identity, &request, &response);

    if (status != QUID_SUCCESS) {
        fprintf(stderr, "❌ Authentication failed: %s\n",
                quid_get_error_string(status));
        quid_identity_free(identity);
        return 1;
    }

    printf("✅ Authentication successful!\n");
    printf("🔑 Generated signature: %zu bytes\n", response.signature_len);
    printf("🕐 Response timestamp: %lu\n", response.timestamp);

    // The response can now be sent to 'my-app.com' for verification

    quid_identity_free(identity);

    printf("\n🎯 Authentication complete! Your identity is quantum-secure!\n");

    return 0;
}
```

#### Compile and Run:
```bash
gcc -o authenticate authenticate.c -lquid
./authenticate
```

### Step 4: Try Network Adapters (5 minutes)

Create `network_demo.c`:

```c
#include <quid.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("🌐 QUID Network Adapter Demo\n\n");

    // Load your identity
    FILE* file = fopen("quid_identity.backup", "rb");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* backup_data = malloc(file_size);
    fread(backup_data, 1, file_size, file);
    fclose(file);

    quid_identity_t* identity = NULL;
    quid_identity_load(backup_data, file_size, "my_secure_password", &identity);
    free(backup_data);

    // Initialize built-in adapters
    quid_bitcoin_adapter_init();
    quid_ssh_adapter_init();
    quid_webauthn_adapter_init();

    printf("🔐 Identity: %s\n\n", quid_get_identity_id(identity));

    // Bitcoin Adapter Demo
    printf("₿ Bitcoin Adapter:\n");
    const quid_adapter_t* bitcoin_adapter;
    quid_get_adapter("bitcoin", &bitcoin_adapter);

    void* bitcoin_keys = NULL;
    quid_context_t bitcoin_context = {0};
    strcpy(bitcoin_context.network_type, "bitcoin");
    strcpy(bitcoin_context.application_id, "my-wallet");

    if (bitcoin_adapter->derive_keys(&identity->master_keypair,
                                    &bitcoin_context, &bitcoin_keys) == QUID_SUCCESS) {
        char bitcoin_address[36];
        bitcoin_adapter->generate_address(bitcoin_keys, bitcoin_address, sizeof(bitcoin_address));
        printf("  📍 Generated Bitcoin Address: %s\n", bitcoin_address);

        // Test signing
        uint8_t message[32] = "Bitcoin transaction data";
        uint8_t signature[256];
        size_t sig_len = sizeof(signature);

        if (bitcoin_adapter->sign_message(bitcoin_keys, message, sizeof(message),
                                        signature, &sig_len) == QUID_SUCCESS) {
            printf("  ✅ Signed transaction: %zu bytes\n", sig_len);
        }

        bitcoin_adapter->cleanup(bitcoin_keys);
    }

    printf("\n🖥️  SSH Adapter:\n");
    const quid_adapter_t* ssh_adapter;
    quid_get_adapter("ssh", &ssh_adapter);

    void* ssh_keys = NULL;
    quid_context_t ssh_context = {0};
    strcpy(ssh_context.network_type, "ssh");
    strcpy(ssh_context.application_id, "server-001");

    if (ssh_adapter->derive_keys(&identity->master_keypair,
                                &ssh_context, &ssh_keys) == QUID_SUCCESS) {
        char ssh_key[256];
        ssh_adapter->generate_address(ssh_keys, ssh_key, sizeof(ssh_key));
        printf("  🔑 Generated SSH Public Key:\n  %s\n", ssh_key);
        ssh_adapter->cleanup(ssh_keys);
    }

    printf("\n🌐 WebAuthn Adapter:\n");
    const quid_adapter_t* webauthn_adapter;
    quid_get_adapter("webauthn", &webauthn_adapter);

    void* webauthn_keys = NULL;
    quid_context_t webauthn_context = {0};
    strcpy(webauthn_context.network_type, "webauthn");
    strcpy(webauthn_context.application_id, "example.com");

    if (webauthn_adapter->derive_keys(&identity->master_keypair,
                                     &webauthn_context, &webauthn_keys) == QUID_SUCCESS) {
        char credential_id[64];
        webauthn_adapter->generate_address(webauthn_keys, credential_id, sizeof(credential_id));
        printf("  🎫 Generated Credential ID: %s\n", credential_id);
        webauthn_adapter->cleanup(webauthn_keys);
    }

    quid_identity_free(identity);

    printf("\n🎉 Network adapter demo complete!\n");
    printf("💡 One identity works across Bitcoin, SSH, and WebAuthn!\n");

    return 0;
}
```

#### Compile and Run:
```bash
gcc -o network_demo network_demo.c -lquid -lsecp256k1 -lssl -lcrypto
./network_demo
```

## Platform-Specific Examples

### Embedded Systems (ESP32)

```c
#include <quid.h>
#include "esp_log.h"

void app_main() {
    ESP_LOGI("QUID", "🔐 Initializing quantum-resistant identity");

    quid_identity_t* identity = NULL;
    if (quid_identity_create(&identity) == QUID_SUCCESS) {
        ESP_LOGI("QUID", "✅ Identity created: %s", quid_get_identity_id(identity));

        // IoT device authentication
        quid_auth_request_t request = {0};
        strcpy(request.context.network_type, "mqtt");
        strcpy(request.context.application_id, "iot-device-001");

        // Use identity for secure IoT communication
        // ...

        quid_identity_free(identity);
    }
}
```

### Python Integration

```python
import ctypes
import os

# Load QUID library
lib = ctypes.CDLL('./libquid.so')

# Python wrapper for key functions
def create_identity():
    identity_ptr = ctypes.c_void_p()
    result = lib.quid_identity_create(ctypes.byref(identity_ptr))
    return identity_ptr if result == 0 else None

def get_identity_id(identity):
    buf = ctypes.create_string_buffer(65)  # 64 chars + null
    lib.quid_get_identity_id.restype = ctypes.c_char_p
    return lib.quid_get_identity_id(identity).decode('utf-8')

# Usage
identity = create_identity()
if identity:
    print(f"🔐 QUID Identity: {get_identity_id(identity)}")
```

## Next Steps

### 📚 Learn More

1. **[Architecture Documentation](ARCHITECTURE.md)** - Deep dive into QUID's technical design
2. **[API Reference](API_REFERENCE.md)** - Complete function documentation
3. **[Adapter Development](ADAPTER_DEVELOPMENT.md)** - Create your own network adapters
4. **[Security Model](SECURITY_MODEL.md)** - Understand QUID's security guarantees

### 🚀 Advanced Topics

1. **[Integration Examples](INTEGRATION_EXAMPLES.md)** - Real-world integration patterns
2. **[Performance Optimization](PERFORMANCE_SPECIFICATIONS.md)** - Optimize for your platform
3. **[Memory Protection](../research/MEMORY_PROTECTION.md)** - Secure memory management
4. **[Hardware Integration](../research/HARDWARE_INTEGRATION.md)** - HSM/TPM integration

### 🤝 Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/quid-identity/quid-core/issues)
- **Discord**: [Join our developer community](https://discord.gg/quid-identity)
- **Discussions**: [Share ideas and get help](https://github.com/quid-identity/quid-core/discussions)

### 🔧 Development Tools

```bash
# Run comprehensive tests
make test

# Check memory leaks
valgrind --leak-check=full ./first_identity

# Performance benchmark
make benchmark

# Security audit
make security-check
```

## Troubleshooting

### Common Issues

**Issue: `error: quid.h: No such file or directory`**
```bash
# Ensure QUID is properly installed
sudo ldconfig  # Linux
export DYLD_LIBRARY_PATH=/usr/local/lib  # macOS
```

**Issue: `libquid.so: cannot open shared object file`**
```bash
# Add library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
# Or install system-wide
sudo make install
```

**Issue: Authentication fails with "unsupported network"**
```bash
# Initialize the required adapter first
quid_bitcoin_adapter_init()
quid_ssh_adapter_init()
```

### Performance Tips

1. **Use memory pools** for frequent identity operations
2. **Enable SIMD optimizations** on supported platforms
3. **Batch operations** when possible
4. **Use secure memory** for sensitive operations

### Security Best Practices

1. **Never hardcode passwords** in source code
2. **Use secure random generation** for all cryptographic operations
3. **Zero sensitive memory** after use
4. **Validate all inputs** to prevent injection attacks

---

**🎉 Congratulations!** You've successfully set up QUID and performed quantum-resistant authentication. Your digital identity is now future-proof against quantum computing threats!

**Need help?** Check our [FAQ](FAQ.md) or [join our community](https://discord.gg/quid-identity).