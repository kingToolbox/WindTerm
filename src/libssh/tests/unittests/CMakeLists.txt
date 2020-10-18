project(unittests C)

include_directories(${OPENSSL_INCLUDE_DIR})

set(LIBSSH_UNIT_TESTS
    torture_buffer
    torture_bytearray
    torture_callbacks
    torture_crypto
    torture_init
    torture_list
    torture_misc
    torture_config
    torture_options
    torture_isipaddr
    torture_knownhosts_parsing
    torture_hashes
    torture_packet_filter
    torture_temp_dir
    torture_temp_file
    torture_push_pop_dir
    torture_session_keys
    torture_tokens
)

set(LIBSSH_THREAD_UNIT_TESTS
    torture_rand
    torture_threads_init
    torture_threads_buffer
    torture_threads_crypto
)

if (UNIX AND NOT WIN32)
    set(LIBSSH_UNIT_TESTS
        ${LIBSSH_UNIT_TESTS}
        # this uses a socketpair
        torture_packet
        # requires ssh-keygen
        torture_keyfiles
        torture_pki
        torture_pki_rsa
        torture_pki_ed25519
        # requires /dev/null
        torture_channel
    )

    if (WITH_SERVER)
        set(LIBSSH_UNIT_TESTS
            ${LIBSSH_UNIT_TESTS}
            torture_bind_config)

        if (WITH_GEX)
            set(LIBSSH_UNIT_TESTS
                ${LIBSSH_UNIT_TESTS}
                torture_moduli)
        endif()
    endif()


    if (HAVE_DSA)
        set(LIBSSH_UNIT_TESTS
            ${LIBSSH_UNIT_TESTS}
            torture_pki_dsa
        )
    endif()

    if (HAVE_ECC)
        set(LIBSSH_UNIT_TESTS
            ${LIBSSH_UNIT_TESTS}
            torture_pki_ecdsa
        )
    endif()

    set(LIBSSH_THREAD_UNIT_TESTS
        ${LIBSSH_THREAD_UNIT_TESTS}
        # requires pthread
        torture_threads_pki_rsa
    )
    # Not working correctly
    #if (WITH_SERVER)
    #    add_cmocka_test(torture_server_x11 torture_server_x11.c ${TEST_TARGET_LIBRARIES})
    #endif (WITH_SERVER)
endif (UNIX AND NOT WIN32)

foreach(_UNIT_TEST ${LIBSSH_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()

if (CMAKE_USE_PTHREADS_INIT)
    foreach(_UNIT_TEST ${LIBSSH_THREAD_UNIT_TESTS})
        add_cmocka_test(${_UNIT_TEST}
                        SOURCES ${_UNIT_TEST}.c
                        COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                        LINK_LIBRARIES ${TEST_TARGET_LIBRARIES} Threads::Threads
        )
    endforeach()
endif ()

