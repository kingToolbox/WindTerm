/* Name of package */
#cmakedefine PACKAGE "${PROJECT_NAME}"

/* Version number of package */
#cmakedefine VERSION "${PROJECT_VERSION}"

#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/* Global bind configuration file path */
#cmakedefine GLOBAL_BIND_CONFIG "${GLOBAL_BIND_CONFIG}"

/* Global client configuration file path */
#cmakedefine GLOBAL_CLIENT_CONFIG "${GLOBAL_CLIENT_CONFIG}"

/************************** HEADER FILES *************************/

/* Define to 1 if you have the <argp.h> header file. */
#cmakedefine HAVE_ARGP_H 1

/* Define to 1 if you have the <aprpa/inet.h> header file. */
#cmakedefine HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <glob.h> header file. */
#cmakedefine HAVE_GLOB_H 1

/* Define to 1 if you have the <valgrind/valgrind.h> header file. */
#cmakedefine HAVE_VALGRIND_VALGRIND_H 1

/* Define to 1 if you have the <pty.h> header file. */
#cmakedefine HAVE_PTY_H 1

/* Define to 1 if you have the <utmp.h> header file. */
#cmakedefine HAVE_UTMP_H 1

/* Define to 1 if you have the <util.h> header file. */
#cmakedefine HAVE_UTIL_H 1

/* Define to 1 if you have the <libutil.h> header file. */
#cmakedefine HAVE_LIBUTIL_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#cmakedefine HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/utime.h> header file. */
#cmakedefine HAVE_SYS_UTIME_H 1

/* Define to 1 if you have the <io.h> header file. */
#cmakedefine HAVE_IO_H 1

/* Define to 1 if you have the <termios.h> header file. */
#cmakedefine HAVE_TERMIOS_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H 1

/* Define to 1 if you have the <openssl/aes.h> header file. */
#cmakedefine HAVE_OPENSSL_AES_H 1

/* Define to 1 if you have the <wspiapi.h> header file. */
#cmakedefine HAVE_WSPIAPI_H 1

/* Define to 1 if you have the <openssl/blowfish.h> header file. */
#cmakedefine HAVE_OPENSSL_BLOWFISH_H 1

/* Define to 1 if you have the <openssl/des.h> header file. */
#cmakedefine HAVE_OPENSSL_DES_H 1

/* Define to 1 if you have the <openssl/ecdh.h> header file. */
#cmakedefine HAVE_OPENSSL_ECDH_H 1

/* Define to 1 if you have the <openssl/ec.h> header file. */
#cmakedefine HAVE_OPENSSL_EC_H 1

/* Define to 1 if you have the <openssl/ecdsa.h> header file. */
#cmakedefine HAVE_OPENSSL_ECDSA_H 1

/* Define to 1 if you have the <pthread.h> header file. */
#cmakedefine HAVE_PTHREAD_H 1

/* Define to 1 if you have eliptic curve cryptography in openssl */
#cmakedefine HAVE_OPENSSL_ECC 1

/* Define to 1 if you have eliptic curve cryptography in gcrypt */
#cmakedefine HAVE_GCRYPT_ECC 1

/* Define to 1 if you have eliptic curve cryptography */
#cmakedefine HAVE_ECC 1

/* Define to 1 if you have DSA */
#cmakedefine HAVE_DSA 1

/* Define to 1 if you have gl_flags as a glob_t sturct member */
#cmakedefine HAVE_GLOB_GL_FLAGS_MEMBER 1

/* Define to 1 if you have OpenSSL with Ed25519 support */
#cmakedefine HAVE_OPENSSL_ED25519 1

/* Define to 1 if you have OpenSSL with X25519 support */
#cmakedefine HAVE_OPENSSL_X25519 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `EVP_aes128_ctr' function. */
#cmakedefine HAVE_OPENSSL_EVP_AES_CTR 1

/* Define to 1 if you have the `EVP_aes128_cbc' function. */
#cmakedefine HAVE_OPENSSL_EVP_AES_CBC 1

/* Define to 1 if you have the `EVP_aes128_gcm' function. */
#cmakedefine HAVE_OPENSSL_EVP_AES_GCM 1

/* Define to 1 if you have the `CRYPTO_THREADID_set_callback' function. */
#cmakedefine HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK 1

/* Define to 1 if you have the `CRYPTO_ctr128_encrypt' function. */
#cmakedefine HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT 1

/* Define to 1 if you have the `EVP_CIPHER_CTX_new' function. */
#cmakedefine HAVE_OPENSSL_EVP_CIPHER_CTX_NEW 1

/* Define to 1 if you have the `EVP_KDF_CTX_new_id' function. */
#cmakedefine HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID 1

/* Define to 1 if you have the `FIPS_mode' function. */
#cmakedefine HAVE_OPENSSL_FIPS_MODE 1

/* Define to 1 if you have the `EVP_DigestSign' function. */
#cmakedefine HAVE_OPENSSL_EVP_DIGESTSIGN 1

/* Define to 1 if you have the `EVP_DigestVerify' function. */
#cmakedefine HAVE_OPENSSL_EVP_DIGESTVERIFY 1

/* Define to 1 if you have the `OPENSSL_ia32cap_loc' function. */
#cmakedefine HAVE_OPENSSL_IA32CAP_LOC 1

/* Define to 1 if you have the `snprintf' function. */
#cmakedefine HAVE_SNPRINTF 1

/* Define to 1 if you have the `_snprintf' function. */
#cmakedefine HAVE__SNPRINTF 1

/* Define to 1 if you have the `_snprintf_s' function. */
#cmakedefine HAVE__SNPRINTF_S 1

/* Define to 1 if you have the `vsnprintf' function. */
#cmakedefine HAVE_VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf' function. */
#cmakedefine HAVE__VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf_s' function. */
#cmakedefine HAVE__VSNPRINTF_S 1

/* Define to 1 if you have the `isblank' function. */
#cmakedefine HAVE_ISBLANK 1

/* Define to 1 if you have the `strncpy' function. */
#cmakedefine HAVE_STRNCPY 1

/* Define to 1 if you have the `strndup' function. */
#cmakedefine HAVE_STRNDUP 1

/* Define to 1 if you have the `cfmakeraw' function. */
#cmakedefine HAVE_CFMAKERAW 1

/* Define to 1 if you have the `getaddrinfo' function. */
#cmakedefine HAVE_GETADDRINFO 1

/* Define to 1 if you have the `poll' function. */
#cmakedefine HAVE_POLL 1

/* Define to 1 if you have the `select' function. */
#cmakedefine HAVE_SELECT 1

/* Define to 1 if you have the `clock_gettime' function. */
#cmakedefine HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the `ntohll' function. */
#cmakedefine HAVE_NTOHLL 1

/* Define to 1 if you have the `htonll' function. */
#cmakedefine HAVE_HTONLL 1

/* Define to 1 if you have the `strtoull' function. */
#cmakedefine HAVE_STRTOULL 1

/* Define to 1 if you have the `__strtoull' function. */
#cmakedefine HAVE___STRTOULL 1

/* Define to 1 if you have the `_strtoui64' function. */
#cmakedefine HAVE__STRTOUI64 1

/* Define to 1 if you have the `glob' function. */
#cmakedefine HAVE_GLOB 1

/* Define to 1 if you have the `explicit_bzero' function. */
#cmakedefine HAVE_EXPLICIT_BZERO 1

/* Define to 1 if you have the `memset_s' function. */
#cmakedefine HAVE_MEMSET_S 1

/* Define to 1 if you have the `SecureZeroMemory' function. */
#cmakedefine HAVE_SECURE_ZERO_MEMORY 1

/* Define to 1 if you have the `cmocka_set_test_filter' function. */
#cmakedefine HAVE_CMOCKA_SET_TEST_FILTER 1

/*************************** LIBRARIES ***************************/

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#cmakedefine HAVE_LIBCRYPTO 1

/* Define to 1 if you have the `gcrypt' library (-lgcrypt). */
#cmakedefine HAVE_LIBGCRYPT 1

/* Define to 1 if you have the 'mbedTLS' library (-lmbedtls). */
#cmakedefine HAVE_LIBMBEDCRYPTO 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#cmakedefine HAVE_PTHREAD 1

/* Define to 1 if you have the `cmocka' library (-lcmocka). */
#cmakedefine HAVE_CMOCKA 1

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_GCC_THREAD_LOCAL_STORAGE 1
#cmakedefine HAVE_MSC_THREAD_LOCAL_STORAGE 1

#cmakedefine HAVE_FALLTHROUGH_ATTRIBUTE 1
#cmakedefine HAVE_UNUSED_ATTRIBUTE 1

#cmakedefine HAVE_CONSTRUCTOR_ATTRIBUTE 1
#cmakedefine HAVE_DESTRUCTOR_ATTRIBUTE 1

#cmakedefine HAVE_GCC_VOLATILE_MEMORY_PROTECTION 1

#cmakedefine HAVE_COMPILER__FUNC__ 1
#cmakedefine HAVE_COMPILER__FUNCTION__ 1

#cmakedefine HAVE_GCC_BOUNDED_ATTRIBUTE 1

/* Define to 1 if you want to enable GSSAPI */
#cmakedefine WITH_GSSAPI 1

/* Define to 1 if you want to enable ZLIB */
#cmakedefine WITH_ZLIB 1

/* Define to 1 if you want to enable SFTP */
#cmakedefine WITH_SFTP 1

/* Define to 1 if you want to enable server support */
#cmakedefine WITH_SERVER 1

/* Define to 1 if you want to enable DH group exchange algorithms */
#cmakedefine WITH_GEX 1

/* Define to 1 if you want to enable blowfish cipher support */
#cmakedefine WITH_BLOWFISH_CIPHER 1

/* Define to 1 if you want to enable debug output for crypto functions */
#cmakedefine DEBUG_CRYPTO 1

/* Define to 1 if you want to enable debug output for packet functions */
#cmakedefine DEBUG_PACKET 1

/* Define to 1 if you want to enable pcap output support (experimental) */
#cmakedefine WITH_PCAP 1

/* Define to 1 if you want to enable calltrace debug output */
#cmakedefine DEBUG_CALLTRACE 1

/* Define to 1 if you want to enable NaCl support */
#cmakedefine WITH_NACL 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
