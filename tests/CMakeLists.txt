# Tests CMakeLists.txt for QUID - Essential Tests Only

# Enable testing
enable_testing()

# Identity unit tests
add_executable(test_identity test_identity.c)
target_link_libraries(test_identity quid_static)

# Backup/restore tests
add_executable(test_backup test_backup.c)
target_link_libraries(test_backup quid_static)

# Auth proof tests
add_executable(test_auth test_auth.c)
target_link_libraries(test_auth quid_static)

# Complete integration tests
add_executable(test_integration_complete test_integration_complete.c)
target_link_libraries(test_integration_complete quid_static)

# Set output directories
set_target_properties(test_identity PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

set_target_properties(test_backup PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

set_target_properties(test_auth PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

set_target_properties(test_integration_complete PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

# Add essential tests to CTest
add_test(NAME IdentityTests COMMAND test_identity)
add_test(NAME BackupTests COMMAND test_backup)
add_test(NAME AuthTests COMMAND test_auth)
add_test(NAME CompleteIntegrationTests COMMAND test_integration_complete)

# Set test properties
set_tests_properties(IdentityTests PROPERTIES
    TIMEOUT 30
    PASS_REGULAR_EXPRESSION "All tests passed"
)

set_tests_properties(BackupTests PROPERTIES
    TIMEOUT 120
    PASS_REGULAR_EXPRESSION "All backup tests passed"
)

set_tests_properties(AuthTests PROPERTIES
    TIMEOUT 30
    PASS_REGULAR_EXPRESSION "Auth tests passed"
)

set_tests_properties(CompleteIntegrationTests PROPERTIES
    TIMEOUT 180
    PASS_REGULAR_EXPRESSION "ALL INTEGRATION TESTS PASSED"
)

# Test configuration
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/test_config.h"
    @ONLY
)

# Include test configuration for essential tests
target_include_directories(test_identity PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(test_backup PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(test_auth PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(test_integration_complete PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

# Install essential tests (optional)
if(QUID_INSTALL_TESTS)
    install(TARGETS test_identity test_backup test_auth test_integration_complete
        RUNTIME DESTINATION lib/quid/tests
    )
endif()
