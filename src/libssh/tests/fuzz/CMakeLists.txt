project(fuzzing CXX)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_executable(ssh_server_fuzzer ssh_server_fuzzer.cpp)
    set_target_properties(ssh_server_fuzzer
        PROPERTIES
            COMPILE_FLAGS "-fsanitize=fuzzer"
            LINK_FLAGS "-fsanitize=fuzzer")
endif()
