cmake_minimum_required(VERSION 3.16)
project(QUID VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(QUID_BUILD_TESTS "Build test suite" ON)
option(QUID_BUILD_EXAMPLES "Build example programs" ON)
option(QUID_BUILD_DOCS "Build documentation" ON)
option(QUID_ENABLE_HARDENING "Enable security hardening" ON)
option(QUID_USE_SYSTEM_MLDSA "Use system ML-DSA library" OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4)
    if(QUID_ENABLE_HARDENING)
        add_compile_options(/GS /sdl)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    if(QUID_ENABLE_HARDENING)
        add_compile_options(-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie)
    endif()
endif()

# Define macros
add_definitions(-DQUID_VERSION_MAJOR=${PROJECT_VERSION_MAJOR})
add_definitions(-DQUID_VERSION_MINOR=${PROJECT_VERSION_MINOR})
add_definitions(-DQUID_VERSION_PATCH=${PROJECT_VERSION_PATCH})

# Include directories
include_directories(include)
include_directories(PQClean/common)

# Link libraries
if(UNIX AND NOT APPLE)
    set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES} -pthread")
endif()

find_package(OpenSSL REQUIRED)

# Source files
set(QUID_CORE_SOURCES
    src/core/identity.c
    src/core/auth.c
    src/core/adapter_loader.c
    src/core/backup.c
    src/utils/crypto.c
    src/utils/memory.c
    src/utils/random.c
    src/utils/validation.c
    phc-winner-argon2/src/argon2.c
    phc-winner-argon2/src/core.c
    phc-winner-argon2/src/thread.c
    phc-winner-argon2/src/blake2/blake2b.c
    phc-winner-argon2/src/encoding.c
    # PQClean ML-DSA implementations
    PQClean/common/fips202.c
    PQClean/crypto_sign/ml-dsa-44/clean/sign.c
    PQClean/crypto_sign/ml-dsa-44/clean/packing.c
    PQClean/crypto_sign/ml-dsa-44/clean/poly.c
    PQClean/crypto_sign/ml-dsa-44/clean/polyvec.c
    PQClean/crypto_sign/ml-dsa-44/clean/ntt.c
    PQClean/crypto_sign/ml-dsa-44/clean/reduce.c
    PQClean/crypto_sign/ml-dsa-44/clean/rounding.c
    PQClean/crypto_sign/ml-dsa-44/clean/symmetric-shake.c
    PQClean/crypto_sign/ml-dsa-65/clean/sign.c
    PQClean/crypto_sign/ml-dsa-65/clean/packing.c
    PQClean/crypto_sign/ml-dsa-65/clean/poly.c
    PQClean/crypto_sign/ml-dsa-65/clean/polyvec.c
    PQClean/crypto_sign/ml-dsa-65/clean/ntt.c
    PQClean/crypto_sign/ml-dsa-65/clean/reduce.c
    PQClean/crypto_sign/ml-dsa-65/clean/rounding.c
    PQClean/crypto_sign/ml-dsa-65/clean/symmetric-shake.c
    PQClean/crypto_sign/ml-dsa-87/clean/sign.c
    PQClean/crypto_sign/ml-dsa-87/clean/packing.c
    PQClean/crypto_sign/ml-dsa-87/clean/poly.c
    PQClean/crypto_sign/ml-dsa-87/clean/polyvec.c
    PQClean/crypto_sign/ml-dsa-87/clean/ntt.c
    PQClean/crypto_sign/ml-dsa-87/clean/reduce.c
    PQClean/crypto_sign/ml-dsa-87/clean/rounding.c
    PQClean/crypto_sign/ml-dsa-87/clean/symmetric-shake.c
)

# Adapter sources (commented out until interface issues are resolved)
# set(QUID_ADAPTER_SOURCES
#     adapters/bitcoin.c
#     adapters/ssh.c
#     adapters/webauthn.c
# )

# Create static library
add_library(quid_static STATIC ${QUID_CORE_SOURCES})
target_include_directories(quid_static PUBLIC include phc-winner-argon2/include phc-winner-argon2/src)
set_target_properties(quid_static PROPERTIES OUTPUT_NAME quid)

# Create shared library
add_library(quid_shared SHARED ${QUID_CORE_SOURCES})
target_include_directories(quid_shared PUBLIC include phc-winner-argon2/include phc-winner-argon2/src)
set_target_properties(quid_shared PROPERTIES OUTPUT_NAME quid)

# Link libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(quid_static pthread)
    target_link_libraries(quid_shared pthread)
endif()

target_link_libraries(quid_static OpenSSL::Crypto)
target_link_libraries(quid_shared OpenSSL::Crypto)

# ML-DSA dependency
if(QUID_USE_SYSTEM_MLDSA)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(MLDSA REQUIRED libml-dsa)
    target_include_directories(quid_static PRIVATE ${MLDSA_INCLUDE_DIRS})
    target_include_directories(quid_shared PRIVATE ${MLDSA_INCLUDE_DIRS})
    target_link_libraries(quid_static ${MLDSA_LIBRARIES})
    target_link_libraries(quid_shared ${MLDSA_LIBRARIES})
else()
    # Add bundled ML-DSA implementation
    # TODO: Add ML-DSA submodule or bundled implementation
    message(STATUS "Using bundled ML-DSA implementation")
endif()

# Install targets
install(TARGETS quid_static quid_shared
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)

# Build examples
if(QUID_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Build tests
if(QUID_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Skip documentation build for now (no CMakeLists.txt in docs)
# if(QUID_BUILD_DOCS)
#     add_subdirectory(docs)
# endif()
