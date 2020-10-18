include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckStructHasMember)
include(TestBigEndian)

set(PACKAGE ${PROJECT_NAME})
set(VERSION ${PROJECT_VERSION})
set(SYSCONFDIR ${CMAKE_INSTALL_SYSCONFDIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

if(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)
    compiler_dumpversion(GNUCC_VERSION)
    if (NOT GNUCC_VERSION EQUAL 34)
        set(CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
        check_c_source_compiles(
"void __attribute__((visibility(\"default\"))) test() {}
int main(void){ return 0; }
" WITH_VISIBILITY_HIDDEN)
        unset(CMAKE_REQUIRED_FLAGS)
    endif (NOT GNUCC_VERSION EQUAL 34)
endif(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)

# HEADER FILES
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${ARGP_INCLUDE_DIR})
check_include_file(argp.h HAVE_ARGP_H)
unset(CMAKE_REQUIRED_INCLUDES)

check_include_file(pty.h HAVE_PTY_H)
check_include_file(utmp.h HAVE_UTMP_H)
check_include_file(termios.h HAVE_TERMIOS_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(util.h HAVE_UTIL_H)
check_include_file(libutil.h HAVE_LIBUTIL_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/utime.h HAVE_SYS_UTIME_H)
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_include_file(glob.h HAVE_GLOB_H)
check_include_file(valgrind/valgrind.h HAVE_VALGRIND_VALGRIND_H)

if (WIN32)
  check_include_file(io.h HAVE_IO_H)

  check_include_files("winsock2.h;ws2tcpip.h;wspiapi.h" HAVE_WSPIAPI_H)
  if (NOT HAVE_WSPIAPI_H)
    message(STATUS "WARNING: Without wspiapi.h, this build will only work on Windows XP and newer versions")
  endif (NOT HAVE_WSPIAPI_H)
  check_include_files("winsock2.h;ws2tcpip.h" HAVE_WS2TCPIP_H)
endif (WIN32)

if (OPENSSL_FOUND)
    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/des.h HAVE_OPENSSL_DES_H)
    if (NOT HAVE_OPENSSL_DES_H)
        message(FATAL_ERROR "Could not detect openssl/des.h")
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/aes.h HAVE_OPENSSL_AES_H)
    if (NOT HAVE_OPENSSL_AES_H)
        message(FATAL_ERROR "Could not detect openssl/aes.h")
    endif()

    if (WITH_BLOWFISH_CIPHER)
        set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
        check_include_file(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ecdh.h HAVE_OPENSSL_ECDH_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ec.h HAVE_OPENSSL_EC_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ecdsa.h HAVE_OPENSSL_ECDSA_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_aes_128_ctr HAVE_OPENSSL_EVP_AES_CTR)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_aes_128_cbc HAVE_OPENSSL_EVP_AES_CBC)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_aes_128_gcm HAVE_OPENSSL_EVP_AES_GCM)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(CRYPTO_THREADID_set_callback HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(CRYPTO_ctr128_encrypt HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_CIPHER_CTX_new HAVE_OPENSSL_EVP_CIPHER_CTX_NEW)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_KDF_CTX_new_id HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(FIPS_mode HAVE_OPENSSL_FIPS_MODE)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(RAND_priv_bytes HAVE_OPENSSL_RAND_PRIV_BYTES)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_DigestSign HAVE_OPENSSL_EVP_DIGESTSIGN)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_DigestVerify HAVE_OPENSSL_EVP_DIGESTVERIFY)

    check_function_exists(OPENSSL_ia32cap_loc HAVE_OPENSSL_IA32CAP_LOC)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_symbol_exists(EVP_PKEY_ED25519 "openssl/evp.h" FOUND_OPENSSL_ED25519)

    if (HAVE_OPENSSL_EVP_DIGESTSIGN AND HAVE_OPENSSL_EVP_DIGESTVERIFY AND
        FOUND_OPENSSL_ED25519)
        set(HAVE_OPENSSL_ED25519 1)
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_symbol_exists(EVP_PKEY_X25519 "openssl/evp.h" HAVE_OPENSSL_X25519)

    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif()

if (CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H 1)
endif (CMAKE_HAVE_PTHREAD_H)

if (NOT WITH_GCRYPT AND NOT WITH_MBEDTLS)
    if (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)
        set(HAVE_OPENSSL_ECC 1)
    endif (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)

    if (HAVE_OPENSSL_ECC)
        set(HAVE_ECC 1)
    endif (HAVE_OPENSSL_ECC)
endif ()

if (NOT WITH_MBEDTLS)
    set(HAVE_DSA 1)
endif (NOT WITH_MBEDTLS)

# FUNCTIONS

check_function_exists(isblank HAVE_ISBLANK)
check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(strndup HAVE_STRNDUP)
check_function_exists(strtoull HAVE_STRTOULL)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)

if (HAVE_GLOB_H)
    check_struct_has_member(glob_t gl_flags glob.h HAVE_GLOB_GL_FLAGS_MEMBER)
    check_function_exists(glob HAVE_GLOB)
endif (HAVE_GLOB_H)

if (NOT WIN32)
  check_function_exists(vsnprintf HAVE_VSNPRINTF)
  check_function_exists(snprintf HAVE_SNPRINTF)
endif (NOT WIN32)

if (WIN32)
    check_symbol_exists(vsnprintf "stdio.h" HAVE_VSNPRINTF)
    check_symbol_exists(snprintf "stdio.h" HAVE_SNPRINTF)

    check_symbol_exists(_vsnprintf_s "stdio.h" HAVE__VSNPRINTF_S)
    check_symbol_exists(_vsnprintf "stdio.h" HAVE__VSNPRINTF)
    check_symbol_exists(_snprintf "stdio.h" HAVE__SNPRINTF)
    check_symbol_exists(_snprintf_s "stdio.h" HAVE__SNPRINTF_S)

    if (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)
        check_symbol_exists(ntohll winsock2.h HAVE_NTOHLL)
        check_symbol_exists(htonll winsock2.h HAVE_HTONLL)

        set(CMAKE_REQUIRED_LIBRARIES ws2_32)
        check_symbol_exists(select "winsock2.h;ws2tcpip.h" HAVE_SELECT)
        check_symbol_exists(poll "winsock2.h;ws2tcpip.h" HAVE_SELECT)
        # The getaddrinfo function is defined to the WspiapiGetAddrInfo inline function
        check_symbol_exists(getaddrinfo "winsock2.h;ws2tcpip.h" HAVE_GETADDRINFO)
        unset(CMAKE_REQUIRED_LIBRARIES)
    endif (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)

    check_function_exists(_strtoui64 HAVE__STRTOUI64)

    set(HAVE_SELECT TRUE)

    check_symbol_exists(SecureZeroMemory "windows.h" HAVE_SECURE_ZERO_MEMORY)
else (WIN32)
    check_function_exists(poll HAVE_POLL)
    check_function_exists(select HAVE_SELECT)
    check_function_exists(getaddrinfo HAVE_GETADDRINFO)

    check_symbol_exists(ntohll arpa/inet.h HAVE_NTOHLL)
    check_symbol_exists(htonll arpa/inet.h HAVE_HTONLL)
endif (WIN32)


if (UNIX)
    if (NOT LINUX)
        # libsocket (Solaris)
        check_library_exists(socket getaddrinfo "" HAVE_LIBSOCKET)
        if (HAVE_LIBSOCKET)
            set(HAVE_GETADDRINFO TRUE)
            set(_REQUIRED_LIBRARIES ${_REQUIRED_LIBRARIES} socket)
        endif (HAVE_LIBSOCKET)

        # libnsl/inet_pton (Solaris)
        check_library_exists(nsl inet_pton "" HAVE_LIBNSL)
        if (HAVE_LIBNSL)
            set(_REQUIRED_LIBRARIES ${_REQUIRED_LIBRARIES} nsl)
        endif (HAVE_LIBNSL)

        # librt
        check_library_exists(rt nanosleep "" HAVE_LIBRT)
    endif (NOT LINUX)

    check_library_exists(rt clock_gettime "" HAVE_CLOCK_GETTIME)
    if (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)
        set(_REQUIRED_LIBRARIES ${_REQUIRED_LIBRARIES} rt)
    endif (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)

    check_library_exists(util forkpty "" HAVE_LIBUTIL)
    check_function_exists(cfmakeraw HAVE_CFMAKERAW)
    check_function_exists(__strtoull HAVE___STRTOULL)
endif (UNIX)

set(LIBSSH_REQUIRED_LIBRARIES ${_REQUIRED_LIBRARIES} CACHE INTERNAL "libssh required system libraries")

# LIBRARIES
if (OPENSSL_FOUND)
  set(HAVE_LIBCRYPTO 1)
endif (OPENSSL_FOUND)

if (GCRYPT_FOUND)
    set(HAVE_LIBGCRYPT 1)
    if (GCRYPT_VERSION VERSION_GREATER "1.4.6")
        set(HAVE_GCRYPT_ECC 1)
        set(HAVE_ECC 1)
    endif (GCRYPT_VERSION VERSION_GREATER "1.4.6")
endif (GCRYPT_FOUND)

if (MBEDTLS_FOUND)
    set(HAVE_LIBMBEDCRYPTO 1)
    set(HAVE_ECC 1)
endif (MBEDTLS_FOUND)

if (CMAKE_USE_PTHREADS_INIT)
    set(HAVE_PTHREAD 1)
endif (CMAKE_USE_PTHREADS_INIT)

if (UNIT_TESTING)
    if (CMOCKA_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${CMOCKA_LIBRARIES})
        check_function_exists(cmocka_set_test_filter HAVE_CMOCKA_SET_TEST_FILTER)
        unset(CMAKE_REQUIRED_LIBRARIES)
    endif ()
endif ()

# OPTIONS
check_c_source_compiles("
__thread int tls;

int main(void) {
    return 0;
}" HAVE_GCC_THREAD_LOCAL_STORAGE)

check_c_source_compiles("
__declspec(thread) int tls;

int main(void) {
    return 0;
}" HAVE_MSC_THREAD_LOCAL_STORAGE)

###########################################################
# For detecting attributes we need to treat warnings as
# errors
if (UNIX OR MINGW)
    # Get warnings for attributs
    check_c_compiler_flag("-Wattributes" REQUIRED_FLAGS_WERROR)
    if (REQUIRED_FLAGS_WERROR)
        string(APPEND CMAKE_REQUIRED_FLAGS "-Wattributes ")
    endif()

    # Turn warnings into errors
    check_c_compiler_flag("-Werror" REQUIRED_FLAGS_WERROR)
    if (REQUIRED_FLAGS_WERROR)
        string(APPEND CMAKE_REQUIRED_FLAGS "-Werror ")
    endif()
endif ()

check_c_source_compiles("
void test_constructor_attribute(void) __attribute__ ((constructor));

void test_constructor_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_CONSTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
void test_destructor_attribute(void) __attribute__ ((destructor));

void test_destructor_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_DESTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
#define FALL_THROUGH __attribute__((fallthrough))

int main(void) {
    int i = 2;

    switch (i) {
    case 0:
        FALL_THROUGH;
    case 1:
        break;
    default:
        break;
    }

    return 0;
}" HAVE_FALLTHROUGH_ATTRIBUTE)

if (NOT WIN32)
    check_c_source_compiles("
    #define __unused __attribute__((unused))

    static int do_nothing(int i __unused)
    {
        return 0;
    }

    int main(void)
    {
        int i;

        i = do_nothing(5);
        if (i > 5) {
            return 1;
        }

        return 0;
    }" HAVE_UNUSED_ATTRIBUTE)
endif()

check_c_source_compiles("
#include <string.h>

int main(void)
{
    char buf[] = \"This is some content\";

    memset(buf, '\\\\0', sizeof(buf)); __asm__ volatile(\"\" : : \"g\"(&buf) : \"memory\");

    return 0;
}" HAVE_GCC_VOLATILE_MEMORY_PROTECTION)

check_c_source_compiles("
#include <stdio.h>
int main(void) {
    printf(\"%s\", __func__);
    return 0;
}" HAVE_COMPILER__FUNC__)

check_c_source_compiles("
#include <stdio.h>
int main(void) {
    printf(\"%s\", __FUNCTION__);
    return 0;
}" HAVE_COMPILER__FUNCTION__)

# This is only available with OpenBSD's gcc implementation */
if (OPENBSD)
check_c_source_compiles("
#define ARRAY_LEN 16
void test_attr(const unsigned char *k)
    __attribute__((__bounded__(__minbytes__, 2, 16)));

int main(void) {
    return 0;
}" HAVE_GCC_BOUNDED_ATTRIBUTE)
endif(OPENBSD)

# Stop treating warnings as errors
unset(CMAKE_REQUIRED_FLAGS)

# Check for version script support
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/conftest.map" "VERS_1 {
        global: sym;
};
VERS_2 {
        global: sym;
} VERS_1;
")

set(CMAKE_REQUIRED_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_BINARY_DIR}/conftest.map\"")
check_c_source_compiles("int main(void) { return 0; }" HAVE_LD_VERSION_SCRIPT)
unset(CMAKE_REQUIRED_FLAGS)
file(REMOVE "${CMAKE_CURRENT_BINARY_DIR}/conftest.map")

if (WITH_DEBUG_CRYPTO)
  set(DEBUG_CRYPTO 1)
endif (WITH_DEBUG_CRYPTO)

if (WITH_DEBUG_PACKET)
  set(DEBUG_PACKET 1)
endif (WITH_DEBUG_PACKET)

if (WITH_DEBUG_CALLTRACE)
  set(DEBUG_CALLTRACE 1)
endif (WITH_DEBUG_CALLTRACE)

if (WITH_GSSAPI AND NOT GSSAPI_FOUND)
    set(WITH_GSSAPI 0)
endif (WITH_GSSAPI AND NOT GSSAPI_FOUND)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)
