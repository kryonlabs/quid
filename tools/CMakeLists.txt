# Simple CLI utility for QUID operations

add_executable(quidctl quidctl.c)
target_link_libraries(quidctl quid_static)
set_target_properties(quidctl PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
)
