# Fuzzing harnesses for QUID
# These are not built by default - use -DQUID_BUILD_FUZZERS=ON

option(QUID_BUILD_FUZZERS "Build fuzzing harnesses" OFF)

if(QUID_BUILD_FUZZERS)
    # Standalone fuzzing test (for verification)
    add_executable(fuzz_identity_test fuzz_identity.c)
    target_link_libraries(fuzz_identity_test quid_static)

    set_target_properties(fuzz_identity_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/fuzzing"
    )

    # AFL++ fuzzer (requires AFL compiler)
    if(CMAKE_C_COMPILER MATCHES "afl")
        add_executable(fuzz_identity_afl fuzz_identity.c)
        target_link_libraries(fuzz_identity_afl quid_static)
        target_compile_definitions(fuzz_identity_afl PRIVATE __AFL_HAVE_MANUAL_CONTROL=1)

        set_target_properties(fuzz_identity_afl PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/fuzzing"
        )
    endif()

    # libFuzzer target (requires clang with -fsanitize=fuzzer)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz_identity_libfuzzer fuzz_identity.c)
        target_link_libraries(fuzz_identity_libfuzzer quid_static)
        target_compile_options(fuzz_identity_libfuzzer PRIVATE -fsanitize=fuzzer -fsanitize=address)

        set_target_properties(fuzz_identity_libfuzzer PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/fuzzing"
        )
    endif()

    message(STATUS "Fuzzing harnesses configured")
endif()

# Fuzzing dictionary for structured inputs
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzzing.dict"
    "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.dict"
    COPYONLY
)
