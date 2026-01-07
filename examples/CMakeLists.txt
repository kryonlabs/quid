# Examples CMakeLists.txt for QUID

# Essential examples only
add_executable(simple_identity simple_identity.c)
target_link_libraries(simple_identity quid_static)

# Backup simple test
add_executable(backup_simple_test backup_simple_test.c)
target_link_libraries(backup_simple_test quid_static)

# Production readiness test
add_executable(production_test production_test.c)
target_link_libraries(production_test quid_static)

# Adapter demonstration
add_executable(adapter_demo adapter_demo.c)
target_link_libraries(adapter_demo quid_static)

# Comprehensive QUID demo
add_executable(quid_demo quid_demo.c)
target_link_libraries(quid_demo quid_static)

# CLI utility
add_executable(quid_cli quid_cli.c)
target_link_libraries(quid_cli quid_static)

# Set output directory
set_target_properties(simple_identity PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

set_target_properties(backup_simple_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

set_target_properties(production_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

set_target_properties(adapter_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

set_target_properties(quid_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

set_target_properties(quid_cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)

# Install essential examples
install(TARGETS simple_identity backup_simple_test production_test adapter_demo quid_demo quid_cli
    RUNTIME DESTINATION bin/quid-examples
)

# Copy essential example source files for reference
install(FILES simple_identity.c backup_simple_test.c production_test.c adapter_demo.c quid_demo.c quid_cli.c
    DESTINATION share/quid/examples
)
