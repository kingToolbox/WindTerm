project(test_server C)

if (WITH_SERVER AND UNIX AND NOT WIN32)

find_package(socket_wrapper)

set(server_SRCS
    main.c
)

add_library(testserver STATIC
            test_server.c
            default_cb.c)

set(LIBSSH_SERVER_TESTS
#    torture_server_kbdint
)

include_directories(${libssh_SOURCE_DIR}/include
                    ${libssh_BINARY_DIR}/include
                    ${libssh_BINARY_DIR})

if (ARGP_INCLUDE_DIR)
    include_directories(${ARGP_INCLUDE_DIR})
endif ()

if (UNIX AND NOT WIN32)
    add_executable(test_server ${server_SRCS})
    target_compile_options(test_server PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(test_server
                          testserver
                          ssh::ssh
                          ${ARGP_LIBRARY}
                          util)
endif ()

endif (WITH_SERVER AND UNIX AND NOT WIN32)
