cmake_minimum_required(VERSION 3.16)
project(QUID VERSION 1.0.0 LANGUAGES C)
enable_language(ASM)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
# Build all targets as position-independent to allow shared library creation
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build options
option(QUID_BUILD_TESTS "Build test suite" ON)
option(QUID_BUILD_EXAMPLES "Build example programs" ON)
option(QUID_BUILD_DOCS "Build documentation" ON)
option(QUID_ENABLE_HARDENING "Enable security hardening" ON)
option(QUID_USE_SYSTEM_MLDSA "Use system ML-DSA library" OFF)
option(QUID_ENABLE_AVX2 "Use AVX2 ML-DSA implementations when available" OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4)
    if(QUID_ENABLE_HARDENING)
        add_compile_options(/GS /sdl)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    if(QUID_ENABLE_HARDENING)
        add_compile_options(-D_FORTIFY_SOURCE=2 -fstack-protector-strong)
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

# Find Libsodium for adapter implementations
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSODIUM libsodium)
endif()

# Fallback to find_package if pkg-config failed
if(NOT LIBSODIUM_FOUND)
    find_package(LIBSODIUM)
endif()

if(LIBSODIUM_FOUND)
    message(STATUS "Found Libsodium: ${LIBSODIUM_VERSION}")
else()
    message(WARNING "Libsodium not found - adapters will not be built")
endif()

# ML-DSA implementation selection (clean by default, AVX2 when available)
set(QUID_MLDSA_VARIANT clean)
set(QUID_MLDSA_EXTRA_FLAGS "")
set(QUID_MLDSA_IMPL_NAME CLEAN)
if(QUID_ENABLE_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-mavx2" HAS_MAVX2)
    check_c_compiler_flag("-mbmi2" HAS_BMI2)
    if(HAS_MAVX2 AND HAS_BMI2)
        set(QUID_MLDSA_VARIANT avx2)
        set(QUID_MLDSA_EXTRA_FLAGS "-mavx2;-mbmi2;-mpopcnt")
        set(QUID_MLDSA_IMPL_NAME AVX2)
        message(STATUS "Using AVX2 ML-DSA implementations")
    else()
        message(STATUS "AVX2 not available; using clean ML-DSA implementations")
    endif()
endif()

# Source files
if(QUID_MLDSA_VARIANT STREQUAL "avx2")
    set(QUID_MLDSA_SOURCES
        PQClean/crypto_sign/ml-dsa-44/avx2/sign.c
        PQClean/crypto_sign/ml-dsa-44/avx2/packing.c
        PQClean/crypto_sign/ml-dsa-44/avx2/poly.c
        PQClean/crypto_sign/ml-dsa-44/avx2/polyvec.c
        PQClean/crypto_sign/ml-dsa-44/avx2/rounding.c
        PQClean/crypto_sign/ml-dsa-44/avx2/symmetric-shake.c
        PQClean/crypto_sign/ml-dsa-44/avx2/rejsample.c
        PQClean/crypto_sign/ml-dsa-44/avx2/fips202x4.c
        PQClean/crypto_sign/ml-dsa-44/avx2/consts.c
        PQClean/crypto_sign/ml-dsa-44/avx2/ntt.S
        PQClean/crypto_sign/ml-dsa-44/avx2/invntt.S
        PQClean/crypto_sign/ml-dsa-44/avx2/pointwise.S
        PQClean/crypto_sign/ml-dsa-44/avx2/shuffle.S
        PQClean/crypto_sign/ml-dsa-44/avx2/f1600x4.S
        PQClean/crypto_sign/ml-dsa-65/avx2/sign.c
        PQClean/crypto_sign/ml-dsa-65/avx2/packing.c
        PQClean/crypto_sign/ml-dsa-65/avx2/poly.c
        PQClean/crypto_sign/ml-dsa-65/avx2/polyvec.c
        PQClean/crypto_sign/ml-dsa-65/avx2/rounding.c
        PQClean/crypto_sign/ml-dsa-65/avx2/symmetric-shake.c
        PQClean/crypto_sign/ml-dsa-65/avx2/rejsample.c
        PQClean/crypto_sign/ml-dsa-65/avx2/fips202x4.c
        PQClean/crypto_sign/ml-dsa-65/avx2/consts.c
        PQClean/crypto_sign/ml-dsa-65/avx2/ntt.S
        PQClean/crypto_sign/ml-dsa-65/avx2/invntt.S
        PQClean/crypto_sign/ml-dsa-65/avx2/pointwise.S
        PQClean/crypto_sign/ml-dsa-65/avx2/shuffle.S
        PQClean/crypto_sign/ml-dsa-65/avx2/f1600x4.S
        PQClean/crypto_sign/ml-dsa-87/avx2/sign.c
        PQClean/crypto_sign/ml-dsa-87/avx2/packing.c
        PQClean/crypto_sign/ml-dsa-87/avx2/poly.c
        PQClean/crypto_sign/ml-dsa-87/avx2/polyvec.c
        PQClean/crypto_sign/ml-dsa-87/avx2/rounding.c
        PQClean/crypto_sign/ml-dsa-87/avx2/symmetric-shake.c
        PQClean/crypto_sign/ml-dsa-87/avx2/rejsample.c
        PQClean/crypto_sign/ml-dsa-87/avx2/fips202x4.c
        PQClean/crypto_sign/ml-dsa-87/avx2/consts.c
        PQClean/crypto_sign/ml-dsa-87/avx2/ntt.S
        PQClean/crypto_sign/ml-dsa-87/avx2/invntt.S
        PQClean/crypto_sign/ml-dsa-87/avx2/pointwise.S
        PQClean/crypto_sign/ml-dsa-87/avx2/shuffle.S
        PQClean/crypto_sign/ml-dsa-87/avx2/f1600x4.S
    )
else()
    set(QUID_MLDSA_SOURCES
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
endif()

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
    phc-winner-argon2/src/ref.c
    phc-winner-argon2/src/thread.c
    phc-winner-argon2/src/blake2/blake2b.c
    phc-winner-argon2/src/encoding.c
    PQClean/common/fips202.c
    ${QUID_MLDSA_SOURCES}
)

# Adapter sources - now enabled with static linking
set(QUID_ADAPTER_SOURCES
    adapters/bitcoin.c
    adapters/ssh.c
    adapters/webauthn.c
)

# Add adapter sources to core sources
list(APPEND QUID_CORE_SOURCES ${QUID_ADAPTER_SOURCES})

# Create static library
add_library(quid_static STATIC ${QUID_CORE_SOURCES})
target_include_directories(quid_static PUBLIC include phc-winner-argon2/include phc-winner-argon2/src)
set_target_properties(quid_static PROPERTIES OUTPUT_NAME quid)
target_compile_definitions(quid_static PRIVATE QUID_MLDSA_IMPL=${QUID_MLDSA_IMPL_NAME})
if(QUID_MLDSA_VARIANT STREQUAL "avx2")
    target_compile_options(quid_static PRIVATE ${QUID_MLDSA_EXTRA_FLAGS})
    set(QUID_MLDSA_AVX2_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/PQClean/crypto_sign/ml-dsa-44/avx2
        ${CMAKE_CURRENT_SOURCE_DIR}/PQClean/crypto_sign/ml-dsa-65/avx2
        ${CMAKE_CURRENT_SOURCE_DIR}/PQClean/crypto_sign/ml-dsa-87/avx2
    )
    foreach(asm_dir ${QUID_MLDSA_AVX2_DIRS})
        target_compile_options(quid_static PRIVATE $<$<COMPILE_LANGUAGE:ASM>:-I${asm_dir}>)
    endforeach()
endif()

# Create shared library
add_library(quid_shared SHARED ${QUID_CORE_SOURCES})
target_include_directories(quid_shared PUBLIC include phc-winner-argon2/include phc-winner-argon2/src)
set_target_properties(quid_shared PROPERTIES OUTPUT_NAME quid)
target_compile_definitions(quid_shared PRIVATE QUID_MLDSA_IMPL=${QUID_MLDSA_IMPL_NAME})
if(QUID_MLDSA_VARIANT STREQUAL "avx2")
    target_compile_options(quid_shared PRIVATE ${QUID_MLDSA_EXTRA_FLAGS})
    foreach(asm_dir ${QUID_MLDSA_AVX2_DIRS})
        target_compile_options(quid_shared PRIVATE $<$<COMPILE_LANGUAGE:ASM>:-I${asm_dir}>)
    endforeach()
endif()

# Link libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(quid_static pthread)
    target_link_libraries(quid_shared pthread)
endif()

target_link_libraries(quid_static OpenSSL::Crypto)
target_link_libraries(quid_shared OpenSSL::Crypto)

# Link Libsodium if available
if(LIBSODIUM_FOUND)
    target_include_directories(quid_static PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_include_directories(quid_shared PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
    target_link_libraries(quid_static ${LIBSODIUM_LIBRARIES})
    target_link_libraries(quid_shared ${LIBSODIUM_LIBRARIES})
    target_compile_definitions(quid_static PRIVATE QUID_HAVE_LIBSODIUM=1)
    target_compile_definitions(quid_shared PRIVATE QUID_HAVE_LIBSODIUM=1)
endif()

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
