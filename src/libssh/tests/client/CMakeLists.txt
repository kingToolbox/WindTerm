project(clienttests C)

find_package(socket_wrapper)

set(LIBSSH_CLIENT_TESTS
    torture_algorithms
    torture_client_config
    torture_connect
    torture_hostkey
    torture_auth
    torture_rekey
    torture_forward
    torture_knownhosts
    torture_knownhosts_verify
    torture_proxycommand
    torture_session
    torture_request_env
    torture_client_global_requests)

find_program(SCP_EXECUTABLE NAMES scp)
if (SCP_EXECUTABLE)
    set(LIBSSH_CLIENT_TESTS
        ${LIBSSH_CLIENT_TESTS}
        torture_scp)
endif()

if (DEFAULT_C_NO_DEPRECATION_FLAGS)
    set_source_files_properties(torture_knownhosts.c
                                PROPERTIES
                                    COMPILE_FLAGS ${DEFAULT_C_NO_DEPRECATION_FLAGS})
endif()

if (WITH_SFTP)
    if (WITH_BENCHMARKS)
        set(SFTP_BENCHMARK_TESTS
            torture_sftp_benchmark)
    endif()
    set(LIBSSH_CLIENT_TESTS
        ${LIBSSH_CLIENT_TESTS}
        torture_sftp_ext
        torture_sftp_canonicalize_path
        torture_sftp_dir
        torture_sftp_read
        torture_sftp_fsync
        ${SFTP_BENCHMARK_TESTS})
endif (WITH_SFTP)

foreach(_CLI_TEST ${LIBSSH_CLIENT_TESTS})
    add_cmocka_test(${_CLI_TEST}
                    SOURCES ${_CLI_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TORTURE_LIBRARY}
    )

    if (OSX)
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
            ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${SOCKET_WRAPPER_LIBRARY})
    else ()
        set_property(
            TEST
                ${_CLI_TEST}
            PROPERTY
                ENVIRONMENT ${TORTURE_ENVIRONMENT})
    endif()
endforeach()
