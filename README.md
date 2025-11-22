# QUID - Quantum-Resistant Universal Identity

A production-ready quantum-resistant identity system providing universal digital identity across Bitcoin, Ethereum, SSH, WebAuthn, and other networks.

## 🚀 Quick Start

### Build
```bash
cmake .
make
```

### Run Examples
```bash
./build/examples/simple_identity     # Basic identity operations
./build/examples/production_test     # Production readiness validation
./build/examples/adapter_demo        # Cross-network key derivation
./build/examples/quid_demo          # Comprehensive system demo
```

### Run Tests
```bash
./build/tests/test_identity         # Core identity tests
./build/tests/test_backup           # Backup system tests
./scripts/end_to_end_test.sh        # Full system validation
```

## 🔐 Features

- **Quantum-Resistant**: ML-DSA (CRYSTALS-Dilithium) cryptography
- **Universal Identity**: Single identity for all networks
- **Cross-Network**: Bitcoin, Ethereum, SSH, WebAuthn compatible
- **Production Ready**: Comprehensive testing and validation
- **Memory Safe**: No buffer overflows or memory corruption
- **High Performance**: Sub-millisecond operations

## 📁 Project Structure

```
├── include/quid/          # Public headers
├── src/                   # Source code
│   ├── core/             # Core identity operations
│   ├── utils/            # Cryptographic utilities
│   └── adapters/         # Network adapters
├── examples/             # Example programs
├── tests/                # Test suite
├── scripts/              # Build and test scripts
├── docs/                 # Documentation
├── PQClean/              # Quantum-resistant cryptography
└── phc-winner-argon2/    # Password hashing
```

## 🧪 Testing

The QUID system includes comprehensive testing:

- **Unit Tests**: Core functionality validation
- **Integration Tests**: Cross-component testing
- **Production Tests**: Real-world scenario validation
- **End-to-End Tests**: Complete system validation

Run the complete test suite:
```bash
./scripts/end_to_end_test.sh
```

## 📚 Documentation

- Core docs: see `docs/` for architecture, developer guides, and security notes
- Whitepaper: `whitepaper/WHITEPAPER_V2.md`

## 🛡️ Security

- NIST-standardized ML-DSA post-quantum cryptography
- AES-256-GCM encryption for backups
- Memory-safe implementation
- Comprehensive input validation
- Side-channel attack resistant

## 📄 License

0BSD (Zero-clause BSD) - Permissive free software license

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## 🌐 Support

- GitHub Issues: [quid-identity/quid](https://github.com/quid-identity/quid)
- Documentation: [docs/](docs/)
- Community: [Discussions](https://github.com/quid-identity/quid/discussions)
