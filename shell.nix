{ pkgs ? import <nixpkgs> {} }:

let
  # Build tools
  nativeTools = with pkgs; [
    cmake
    pkg-config
    git
    clang
    clang-tools-extra
    gnumake
    gcc
  ];

  # Libraries
  libs = with pkgs; [
    openssl
    libsodium
  ];

  # Development and debugging tools
  devTools = with pkgs; [
    gdb
    valgrind
    strace
    ltrace
    binutils
    coreutils
  ];

  # Optional: testing tools
  testTools = with pkgs; [
    lcov
    python3
  ];
in
pkgs.mkShell {
  name = "quid-dev-shell";
  buildInputs = nativeTools ++ libs ++ devTools ++ testTools;

  # OpenSSL environment variables for CMake
  OPENSSL_ROOT_DIR = "${pkgs.openssl.dev}";
  OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
  OPENSSL_CRYPTO_LIBRARY = "${pkgs.openssl.out}/lib/libcrypto.so";
  OPENSSL_SSL_LIBRARY = "${pkgs.openssl.out}/lib/libssl.so";

  # Libsodium environment variables
  LIBSODIUM_ROOT_DIR = "${pkgs.libsodium.dev}";

  shellHook = ''
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           QUID Quantum-Safe Identity Library              ║"
    echo "║                  Development Shell                        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📦 Build Environment:"
    echo "   - CMake: $(cmake --version | head -n1)"
    echo "   - Compiler: ${CC:-gcc}"
    echo "   - OpenSSL: ${pkgs.openssl.version}"
    echo "   - Libsodium: ${pkgs.libsodium.version}"
    echo ""
    echo "🔧 Available Commands:"
    echo "   - cmake -S . -B build     Configure the build"
    echo "   - cmake --build build     Compile the project"
    echo "   - cd build && ctest       Run tests"
    echo ""
    echo "🧪 Quick Start:"
    echo "   mkdir -p build && cd build"
    echo "   cmake .."
    echo "   make -j\$(nproc)"
    echo "   ./tests/test_auth"
    echo "   ./tests/test_identity"
    echo "   ./tests/test_integration_complete"
    echo ""

    # Make sure CMake can find OpenSSL and libsodium
    export CMAKE_PREFIX_PATH="${pkgs.lib.makeSearchPath "lib/cmake" libs}:${pkgs.lib.makeLibraryPath libs}:$CMAKE_PREFIX_PATH"
    export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPath "lib/pkgconfig" libs}:${pkgs.lib.makeSearchPath "share/pkgconfig" libs}:$PKG_CONFIG_PATH"

    # Use clang by default (can override with CC=gcc)
    export CC=clang
    export CXX=clang++

    # Library path for running tests without installing
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath libs}:$LD_LIBRARY_PATH"

    # Enable core dumps for debugging
    ulimit -c unlimited 2>/dev/null || true

    echo "✅ Environment ready! Happy hacking!"
    echo ""
  '';
}
