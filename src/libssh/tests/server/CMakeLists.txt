project(servertests C)

if (WITH_SERVER AND UNIX AND NOT WIN32)

find_package(socket_wrapper)

add_subdirectory(test_server)

set(LIBSSH_SERVER_TESTS
    torture_server
    torture_server_auth_kbdint
    torture_server_config
)

include_directories(${libssh_SOURCE_DIR}/include
                    ${libssh_BINARY_DIR}/include
                    ${libssh_BINARY_DIR}
                    test_server)

if (ARGP_INCLUDE_DIR)
    include_directories(${ARGP_INCLUDE_DIR})
endif ()

foreach(_SRV_TEST ${LIBSSH_SERVER_TESTS})
    add_cmocka_test(${_SRV_TEST}
                    SOURCES ${_SRV_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TORTURE_LIBRARY} testserver util
    )

    if (OSX)
        set_property(
            TEST
                ${_SRV_TEST}
            PROPERTY
            ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${SOCKET_WRAPPER_LIBRARY})
    else ()
        set_property(
            TEST
                ${_SRV_TEST}
            PROPERTY
                ENVIRONMENT ${TORTURE_ENVIRONMENT})
    endif()
endforeach()

endif (WITH_SERVER AND UNIX AND NOT WIN32)
