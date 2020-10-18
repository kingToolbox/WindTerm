project(libssh-tests C)

if (BSD OR SOLARIS OR OSX)
    find_package(Argp)
endif (BSD OR SOLARIS OR OSX)

set(TORTURE_LIBRARY torture)

include_directories(${OPENSSL_INCLUDE_DIR}
                    ${CMOCKA_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR}
                    ${libssh_BINARY_DIR}/include
                    ${libssh_BINARY_DIR}
                    ${libssh_SOURCE_DIR}/src
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_BINARY_DIR}/tests)

set(TORTURE_LINK_LIBRARIES
    ${CMOCKA_LIBRARY}
    ssh::static)

# create test library
add_library(${TORTURE_LIBRARY}
            STATIC
                cmdline.c
                torture.c
                torture_key.c
                torture_pki.c
                torture_cmocka.c)
target_link_libraries(${TORTURE_LIBRARY} ${TORTURE_LINK_LIBRARIES})
target_compile_options(${TORTURE_LIBRARY} PRIVATE
                       -DSSH_PING_EXECUTABLE="${CMAKE_CURRENT_BINARY_DIR}/ssh_ping"
)

if (ARGP_LIBRARY)
    target_link_libraries(${TORTURE_LIBRARY}
        ${ARGP_LIBRARY}
    )
endif()

set(TEST_TARGET_LIBRARIES
    ${TORTURE_LIBRARY}
    ${TORTURE_LINK_LIBRARIES}
)

add_subdirectory(unittests)

# OpenSSH Capabilities are required for all unit tests
find_program(SSH_EXECUTABLE NAMES ssh)
if (SSH_EXECUTABLE)
    execute_process(COMMAND ${SSH_EXECUTABLE} -V ERROR_VARIABLE OPENSSH_VERSION_STR)
    string(REGEX REPLACE "^.*OpenSSH_([0-9]).[0-9].*$" "\\1" OPENSSH_VERSION_MAJOR "${OPENSSH_VERSION_STR}")
    string(REGEX REPLACE "^.*OpenSSH_[0-9].([0-9]).*$" "\\1" OPENSSH_VERSION_MINOR "${OPENSSH_VERSION_STR}")
    set(OPENSSH_VERSION "${OPENSSH_VERSION_MAJOR}.${OPENSSH_VERSION_MINOR}")
    if("${OPENSSH_VERSION}" VERSION_LESS "6.3")
        # ssh - Q was introduced in 6.3
        message("Version less than 6.3, hardcoding cipher list")
        set(OPENSSH_CIPHERS "aes128-ctr\naes192-ctr\naes256-ctr\narcfour256\narcfour128\naes128-gcm@openssh.com\naes256-gcm@openssh.com\naes128-cbc\n3des-cbc\nblowfish-cbc\ncast128-cbc\naes192-cbc\naes256-cbc\narcfour\nrijndael-cbc@lysator.liu.se\n")
        set(OPENSSH_MACS "hmac-md5-etm@openssh.com\nhmac-sha1-etm@openssh.com\numac-64-etm@openssh.com\numac-128-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\nhmac-sha2-512-etm@openssh.com\nhmac-ripemd160-etm@openssh.com\nhmac-sha1-96-etm@openssh.com\nhmac-md5-96-etm@openssh.com\nhmac-md5\nhmac-sha1\numac-64@openssh.com\numac-128@openssh.com\nhmac-sha2-256\nhmac-sha2-512\nhmac-ripemd160\nhmac-ripemd160@openssh.com\nhmac-sha1-96\nhmac-md5-96\n")
        set(OPENSSH_KEX "ecdh-sha2-nistp256\necdh-sha2-nistp384\necdh-sha2-nistp521\ndiffie-hellman-group-exchange-sha256\ndiffie-hellman-group-exchange-sha1\ndiffie-hellman-group14-sha1\ndiffie-hellman-group1-sha1\n")
        set(OPENSSH_KEYS "ssh-rsa\nssh-dss\necdsa-sha2-nistp256\n")
    else()
        execute_process(COMMAND ${SSH_EXECUTABLE} -Q cipher OUTPUT_VARIABLE OPENSSH_CIPHERS)
        execute_process(COMMAND ${SSH_EXECUTABLE} -Q mac OUTPUT_VARIABLE OPENSSH_MACS)
        execute_process(COMMAND ${SSH_EXECUTABLE} -Q kex OUTPUT_VARIABLE OPENSSH_KEX)
        execute_process(COMMAND ${SSH_EXECUTABLE} -Q key OUTPUT_VARIABLE OPENSSH_KEYS)
        execute_process(COMMAND ${SSH_EXECUTABLE} -Q sig OUTPUT_VARIABLE OPENSSH_SIGS ERROR_QUIET)

        # We need both of them, but lets get rid of duplicate items presented in both lists
        # to avoid processing too long arguments in pkd
        set(OPENSSH_KEYS "${OPENSSH_KEYS}${OPENSSH_SIGS}")
        string(REPLACE "\n" ";" OPENSSH_KEYS "${OPENSSH_KEYS}")
        list(REMOVE_DUPLICATES OPENSSH_KEYS)
        string(REPLACE ";" "\n" OPENSSH_KEYS "${OPENSSH_KEYS}")
    endif()

    set(SSH_ALGORITHMS
        3des-cbc aes128-cbc aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se aes128-ctr aes192-ctr
        aes256-ctr aes128-gcm@openssh.com aes256-gcm@openssh.com chacha20-poly1305@openssh.com
        hmac-sha1 hmac-sha1-96 hmac-sha2-256 hmac-sha2-512 hmac-md5 hmac-md5-96 umac-64@openssh.com
        umac-128@openssh.com hmac-sha1-etm@openssh.com hmac-sha1-96-etm@openssh.com
        hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com hmac-md5-etm@openssh.com
        hmac-md5-96-etm@openssh.com umac-64-etm@openssh.com umac-128-etm@openssh.com
        diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group14-sha256
        diffie-hellman-group16-sha512 diffie-hellman-group18-sha512 diffie-hellman-group-exchange-sha1
        diffie-hellman-group-exchange-sha256 ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521
        curve25519-sha256 curve25519-sha256@libssh.org
        ssh-ed25519 ssh-ed25519-cert-v01@openssh.com ssh-rsa ssh-dss
        ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521
        ssh-rsa-cert-v01@openssh.com ssh-dss-cert-v01@openssh.com
        ecdsa-sha2-nistp256-cert-v01@openssh.com ecdsa-sha2-nistp384-cert-v01@openssh.com
        ecdsa-sha2-nistp521-cert-v01@openssh.com
        )
    foreach(ALGORITHM ${SSH_ALGORITHMS})
        string(TOUPPER ${ALGORITHM} VARNAME)
        string(REGEX REPLACE "[-@.]" "_" VARNAME "OPENSSH_${VARNAME}")

        # Match the current algorithm into the complete list of OpenSSH supported algorithms.
        # If matching, create an OPENSSH_CIPHER_NAME variable.
        string(REGEX MATCH ".*${ALGORITHM}\n" "${VARNAME}" "${OPENSSH_CIPHERS}${OPENSSH_MACS}${OPENSSH_KEX}${OPENSSH_KEYS}")
    endforeach(ALGORITHM)

    string(STRIP "${OPENSSH_CIPHERS}" OPENSSH_CIPHERS)
    string(STRIP "${OPENSSH_MACS}" OPENSSH_MACS)
    string(STRIP "${OPENSSH_KEX}" OPENSSH_KEX)
    string(STRIP "${OPENSSH_KEYS}" OPENSSH_KEYS)
    string(REPLACE "\n" "," OPENSSH_CIPHERS "${OPENSSH_CIPHERS}")
    string(REPLACE "\n" "," OPENSSH_MACS "${OPENSSH_MACS}")
    string(REPLACE "\n" "," OPENSSH_KEX "${OPENSSH_KEX}")
    string(REPLACE "\n" "," OPENSSH_KEYS "${OPENSSH_KEYS}")

endif()

find_program(SSHD_EXECUTABLE
             NAME
                sshd
             PATHS
                /sbin
                /usr/sbin
                /usr/local/sbin)

if (CLIENT_TESTING OR SERVER_TESTING)
    find_package(socket_wrapper 1.1.5 REQUIRED)
    find_package(nss_wrapper 1.1.2 REQUIRED)
    find_package(uid_wrapper 1.2.0 REQUIRED)
    find_package(pam_wrapper 1.0.1 REQUIRED)

    if (NOT SSHD_EXECUTABLE)
        message(SEND_ERROR "Could not find sshd which is required for client testing")
    endif()
    find_program(NC_EXECUTABLE
                 NAME
                    nc
                 PATHS
                    /bin
                    /usr/bin
                    /usr/local/bin)

    find_program(SSH_EXECUTABLE NAMES ssh)
    if (SSH_EXECUTABLE)
        execute_process(COMMAND ${SSH_EXECUTABLE} -V ERROR_VARIABLE OPENSSH_VERSION_STR)
        string(REGEX REPLACE "^.*OpenSSH_([0-9]).[0-9].*$" "\\1" OPENSSH_VERSION_MAJOR "${OPENSSH_VERSION_STR}")
        string(REGEX REPLACE "^.*OpenSSH_[0-9].([0-9]).*$" "\\1" OPENSSH_VERSION_MINOR "${OPENSSH_VERSION_STR}")
        add_definitions(-DOPENSSH_VERSION_MAJOR=${OPENSSH_VERSION_MAJOR} -DOPENSSH_VERSION_MINOR=${OPENSSH_VERSION_MINOR})
    endif()

    set(LOCAL_USER "nobody")
    set(LOCAL_UID "65533")
    find_program(ID_EXECUTABLE NAMES id)
    find_program(WHO_EXECUTABLE NAMES whoami)
    if (ID_EXECUTABLE AND WHO_EXECUTABLE)
        execute_process(COMMAND ${WHO_EXECUTABLE} OUTPUT_VARIABLE LOCAL_USER OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process(COMMAND ${ID_EXECUTABLE} -u OUTPUT_VARIABLE LOCAL_UID OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()

    # chroot_wrapper
    add_library(chroot_wrapper SHARED chroot_wrapper.c)
    set(CHROOT_WRAPPER_LIBRARY ${libssh_BINARY_DIR}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}chroot_wrapper${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(TEST_TARGET_LIBRARIES
        ${TEST_TARGET_LIBRARIES}
        chroot_wrapper
    )

    # ssh_ping
    add_executable(ssh_ping ssh_ping.c)
    target_compile_options(ssh_ping PRIVATE ${DEFAULT_C_COMPILE_FLAGS})
    target_link_libraries(ssh_ping ssh::ssh)

    # homedir will be used in passwd
    set(HOMEDIR ${CMAKE_CURRENT_BINARY_DIR}/home)

    ### Setup nss_wrapper
    configure_file(etc/passwd.in ${CMAKE_CURRENT_BINARY_DIR}/etc/passwd @ONLY)
    configure_file(etc/shadow.in ${CMAKE_CURRENT_BINARY_DIR}/etc/shadow @ONLY)
    configure_file(etc/group.in ${CMAKE_CURRENT_BINARY_DIR}/etc/group @ONLY)
    configure_file(etc/hosts.in ${CMAKE_CURRENT_BINARY_DIR}/etc/hosts @ONLY)

    ### Setup pam_wrapper
    configure_file(etc/pam_matrix_passdb.in ${CMAKE_CURRENT_BINARY_DIR}/etc/pam_matrix_passdb @ONLY)
    configure_file(etc/pam.d/sshd.in ${CMAKE_CURRENT_BINARY_DIR}/etc/pam.d/sshd @ONLY)


    set(TORTURE_ENVIRONMENT "LD_PRELOAD=${SOCKET_WRAPPER_LIBRARY}:${NSS_WRAPPER_LIBRARY}:${UID_WRAPPER_LIBRARY}:${PAM_WRAPPER_LIBRARY}:${CHROOT_WRAPPER_LIBRARY}")
    list(APPEND TORTURE_ENVIRONMENT UID_WRAPPER=1 UID_WRAPPER_ROOT=1)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_PASSWD=${CMAKE_CURRENT_BINARY_DIR}/etc/passwd)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_SHADOW=${CMAKE_CURRENT_BINARY_DIR}/etc/shadow)
    list(APPEND TORTURE_ENVIRONMENT NSS_WRAPPER_GROUP=${CMAKE_CURRENT_BINARY_DIR}/etc/group)
    list(APPEND TORTURE_ENVIRONMENT PAM_WRAPPER_SERVICE_DIR=${CMAKE_CURRENT_BINARY_DIR}/etc/pam.d)

    # Give bob some keys
    file(COPY keys/id_rsa DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_ecdsa DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_ecdsa.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_ed25519 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_ed25519.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)

    # Allow to auth with bob's public keys on alice account
    configure_file(keys/id_rsa.pub ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys @ONLY)
    # append ECDSA public key
    file(READ keys/id_ecdsa.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # append ed25519 public key
    file(READ keys/id_ed25519.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # Copy the signed key to an alternative directory in bob's homedir.
    file(COPY keys/certauth/id_rsa DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh_cert/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/certauth/id_rsa.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh_cert/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/certauth/id_rsa-cert.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh_cert/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)

    message(STATUS "TORTURE_ENVIRONMENT=${TORTURE_ENVIRONMENT}")
endif ()

configure_file(tests_config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/tests_config.h)

if (WITH_BENCHMARKS)
    add_subdirectory(benchmarks)
endif ()

if (CLIENT_TESTING)
    add_subdirectory(client)
endif ()

if (WITH_SERVER AND SERVER_TESTING)
    add_subdirectory(pkd)
    add_subdirectory(server)
endif ()

if (FUZZ_TESTING)
    add_subdirectory(fuzz)
endif()
