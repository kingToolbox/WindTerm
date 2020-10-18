project(pkd C)

if (WITH_SERVER AND UNIX AND NOT WIN32)

    include_directories(${libssh_SOURCE_DIR}/include
                        ${libssh_BINARY_DIR}/include
                        ${CMOCKA_INCLUDE_DIR}
                        ${ZLIB_INCLUDE_DIR}
                        ${CMAKE_BINARY_DIR}
                        ${libssh_SOURCE_DIR}/src
                        ${CMAKE_CURRENT_SOURCE_DIR})

set(pkd_hello_src
  pkd_daemon.c
  pkd_hello.c
  pkd_keyutil.c
  pkd_util.c
)

set(pkd_libs
    ${CMOCKA_LIBRARY}
    ssh::static
    ${ARGP_LIBRARIES}
    pthread
)

add_executable(pkd_hello ${pkd_hello_src})
target_compile_options(pkd_hello PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
target_link_libraries(pkd_hello ${pkd_libs})

#
# pkd_hello_i1 runs only one iteration per algorithm combination for
# sake of speeding up overall test run time.  More iterations can be
# specified with `-i` and may be helpful for chasing down bugs that
# are not 100% reproducible.
#
add_test(pkd_hello_i1 ${CMAKE_CURRENT_BINARY_DIR}/pkd_hello -e -o -i1 -w /tmp/pkd_socket_wrapper_XXXXXX)

#
# pkd_hello_rekey is used to test server-side implementation of rekeying.
#
add_test(pkd_hello_rekey ${CMAKE_CURRENT_BINARY_DIR}/pkd_hello -t torture_pkd_openssh_rsa_rsa_default -i1 --rekey=16 -v -v -v -w /tmp/pkd_socket_wrapper_XXXXXX)

#
# Configure environment for cwrap socket wrapper.
#
find_package(socket_wrapper 1.1.5 REQUIRED)
if (OSX)
    set(PKD_ENVIRONMENT "DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${SOCKET_WRAPPER_LIBRARY}")
else ()
    set(PKD_ENVIRONMENT "LD_PRELOAD=${SOCKET_WRAPPER_LIBRARY}")
endif ()
message(STATUS "PKD_ENVIRONMENT=${PKD_ENVIRONMENT}")
set_property(TEST pkd_hello_i1 PROPERTY ENVIRONMENT ${PKD_ENVIRONMENT})

endif (WITH_SERVER AND UNIX AND NOT WIN32)
