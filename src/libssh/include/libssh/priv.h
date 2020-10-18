/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * priv.h file
 * This include file contains everything you shouldn't deal with in
 * user programs. Consider that anything in this file might change
 * without notice; libssh.h file will keep backward compatibility
 * on binary & source
 */

#ifndef _LIBSSH_PRIV_H
#define _LIBSSH_PRIV_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if !defined(HAVE_STRTOULL)
# if defined(HAVE___STRTOULL)
#  define strtoull __strtoull
# elif defined(HAVE__STRTOUI64)
#  define strtoull _strtoui64
# elif defined(__hpux) && defined(__LP64__)
#  define strtoull strtoul
# else
#  error "no strtoull function found"
# endif
#endif /* !defined(HAVE_STRTOULL) */

#if !defined(HAVE_STRNDUP)
char *strndup(const char *s, size_t n);
#endif /* ! HAVE_STRNDUP */

#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef bswap_32
#define bswap_32(x) \
    ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

#ifdef _WIN32

/* Imitate define of inttypes.h */
# ifndef PRIdS
#  define PRIdS "Id"
# endif

# ifndef PRIu64
#  if __WORDSIZE == 64
#   define PRIu64 "lu"
#  else
#   define PRIu64 "llu"
#  endif /* __WORDSIZE */
# endif /* PRIu64 */

# ifndef PRIu32
#  define PRIu32 "u"
# endif /* PRIu32 */

# ifndef PRIx64
#  if __WORDSIZE == 64
#   define PRIx64 "lx"
#  else
#   define PRIx64 "llx"
#  endif /* __WORDSIZE */
# endif /* PRIx64 */

# ifndef PRIx32
#  define PRIx32 "x"
# endif /* PRIx32 */

# ifdef _MSC_VER
#  include <stdio.h>
#  include <stdarg.h> /* va_copy define check */

/* On Microsoft compilers define inline to __inline on all others use inline */
#  undef inline
#  define inline __inline

#  ifndef va_copy
#   define va_copy(dest, src) (dest = src)
#  endif

#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp
#  if ! defined(HAVE_ISBLANK)
#   define isblank(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')
#  endif

#  define usleep(X) Sleep(((X)+1000)/1000)

#  undef strtok_r
#  define strtok_r strtok_s

#  if defined(HAVE__SNPRINTF_S)
#   undef snprintf
#   define snprintf(d, n, ...) _snprintf_s((d), (n), _TRUNCATE, __VA_ARGS__)
#  else /* HAVE__SNPRINTF_S */
#   if defined(HAVE__SNPRINTF)
#     undef snprintf
#     define snprintf _snprintf
#   else /* HAVE__SNPRINTF */
#    if !defined(HAVE_SNPRINTF)
#     error "no snprintf compatible function found"
#    endif /* HAVE_SNPRINTF */
#   endif /* HAVE__SNPRINTF */
#  endif /* HAVE__SNPRINTF_S */

#  if defined(HAVE__VSNPRINTF_S)
#   undef vsnprintf
#   define vsnprintf(s, n, f, v) _vsnprintf_s((s), (n), _TRUNCATE, (f), (v))
#  else /* HAVE__VSNPRINTF_S */
#   if defined(HAVE__VSNPRINTF)
#    undef vsnprintf
#    define vsnprintf _vsnprintf
#   else
#    if !defined(HAVE_VSNPRINTF)
#     error "No vsnprintf compatible function found"
#    endif /* HAVE_VSNPRINTF */
#   endif /* HAVE__VSNPRINTF */
#  endif /* HAVE__VSNPRINTF_S */

#  ifndef _SSIZE_T_DEFINED
#   undef ssize_t
#   include <BaseTsd.h>
    typedef _W64 SSIZE_T ssize_t;
#   define _SSIZE_T_DEFINED
#  endif /* _SSIZE_T_DEFINED */

# endif /* _MSC_VER */

struct timeval;
int gettimeofday(struct timeval *__p, void *__t);

#define _XCLOSESOCKET closesocket

#else /* _WIN32 */

#include <unistd.h>
#define PRIdS "zd"

#define _XCLOSESOCKET close

#endif /* _WIN32 */

#include "libssh/libssh.h"
#include "libssh/callbacks.h"

/* some constants */
#ifndef MAX_PACKAT_LEN
#define MAX_PACKET_LEN 262144
#endif
#ifndef ERROR_BUFFERLEN
#define ERROR_BUFFERLEN 1024
#endif

#ifndef CLIENT_BANNER_SSH2
#define CLIENT_BANNER_SSH2 "SSH-2.0-libssh_" SSH_STRINGIFY(LIBSSH_VERSION)
#endif /* CLIENT_BANNER_SSH2 */

#ifndef KBDINT_MAX_PROMPT
#define KBDINT_MAX_PROMPT 256 /* more than openssh's :) */
#endif
#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 4096
#endif

#ifndef HAVE_COMPILER__FUNC__
# ifdef HAVE_COMPILER__FUNCTION__
#  define __func__ __FUNCTION__
# else
#  error "Your system must provide a __func__ macro"
# endif
#endif

#if defined(HAVE_GCC_THREAD_LOCAL_STORAGE)
# define LIBSSH_THREAD __thread
#elif defined(HAVE_MSC_THREAD_LOCAL_STORAGE)
# define LIBSSH_THREAD __declspec(thread)
#else
# define LIBSSH_THREAD
#endif

/*
 * This makes sure that the compiler doesn't optimize out the code
 *
 * Use it in a macro where the provided variable is 'x'.
 */
#if defined(HAVE_GCC_VOLATILE_MEMORY_PROTECTION)
# define LIBSSH_MEM_PROTECTION __asm__ volatile("" : : "r"(&(x)) : "memory")
#else
# define LIBSSH_MEM_PROTECTION
#endif

/* forward declarations */
struct ssh_common_struct;
struct ssh_kex_struct;

enum ssh_digest_e {
    SSH_DIGEST_AUTO=0,
    SSH_DIGEST_SHA1=1,
    SSH_DIGEST_SHA256,
    SSH_DIGEST_SHA384,
    SSH_DIGEST_SHA512,
};

int ssh_get_key_params(ssh_session session,
                       ssh_key *privkey,
                       enum ssh_digest_e *digest);

/* LOGGING */
void ssh_log_function(int verbosity,
                      const char *function,
                      const char *buffer);
#define SSH_LOG(priority, ...) \
    _ssh_log(priority, __func__, __VA_ARGS__)

/* LEGACY */
void ssh_log_common(struct ssh_common_struct *common,
                    int verbosity,
                    const char *function,
                    const char *format, ...) PRINTF_ATTRIBUTE(4, 5);


/* ERROR HANDLING */

/* error handling structure */
struct error_struct {
    int error_code;
    char error_buffer[ERROR_BUFFERLEN];
};

#define ssh_set_error(error, code, ...) \
    _ssh_set_error(error, code, __func__, __VA_ARGS__)
void _ssh_set_error(void *error,
                    int code,
                    const char *function,
                    const char *descr, ...) PRINTF_ATTRIBUTE(4, 5);

#define ssh_set_error_oom(error) \
    _ssh_set_error_oom(error, __func__)
void _ssh_set_error_oom(void *error, const char *function);

#define ssh_set_error_invalid(error) \
    _ssh_set_error_invalid(error, __func__)
void _ssh_set_error_invalid(void *error, const char *function);

void ssh_reset_error(void *error);

/* server.c */
#ifdef WITH_SERVER
int ssh_auth_reply_default(ssh_session session,int partial);
int ssh_auth_reply_success(ssh_session session, int partial);
#endif
/* client.c */

int ssh_send_banner(ssh_session session, int is_server);

/* connect.c */
socket_t ssh_connect_host_nonblocking(ssh_session session, const char *host,
		const char *bind_addr, int port);

/* in base64.c */
ssh_buffer base64_to_bin(const char *source);
uint8_t *bin_to_base64(const uint8_t *source, size_t len);

/* gzip.c */
int compress_buffer(ssh_session session,ssh_buffer buf);
int decompress_buffer(ssh_session session,ssh_buffer buf, size_t maxlen);

/* match.c */
int match_pattern_list(const char *string, const char *pattern,
    unsigned int len, int dolower);
int match_hostname(const char *host, const char *pattern, unsigned int len);

/* connector.c */
int ssh_connector_set_event(ssh_connector connector, ssh_event event);
int ssh_connector_remove_event(ssh_connector connector);

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

/** Free memory space */
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *s, size_t n);
#endif /* !HAVE_EXPLICIT_BZERO */

/**
 * This is a hack to fix warnings. The idea is to use this everywhere that we
 * get the "discarding const" warning by the compiler. That doesn't actually
 * fix the real issue, but marks the place and you can search the code for
 * discard_const.
 *
 * Please use this macro only when there is no other way to fix the warning.
 * We should use this function in only in a very few places.
 *
 * Also, please call this via the discard_const_p() macro interface, as that
 * makes the return type safe.
 */
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

/**
 * Type-safe version of discard_const
 */
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))

/**
 * Get the argument cound of variadic arguments
 */
/*
 * Since MSVC 2010 there is a bug in passing __VA_ARGS__ to subsequent
 * macros as a single token, which results in:
 *    warning C4003: not enough actual parameters for macro '_VA_ARG_N'
 *  and incorrect behavior. This fixes issue.
 */
#define VA_APPLY_VARIADIC_MACRO(macro, tuple) macro tuple

#define __VA_NARG__(...) \
        (__VA_NARG_(__VA_ARGS__, __RSEQ_N()))
#define __VA_NARG_(...) \
        VA_APPLY_VARIADIC_MACRO(__VA_ARG_N, (__VA_ARGS__))
#define __VA_ARG_N( \
         _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
        _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
        _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
        _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
        _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
        _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
        _61,_62,_63,N,...) N
#define __RSEQ_N() \
        63, 62, 61, 60,                         \
        59, 58, 57, 56, 55, 54, 53, 52, 51, 50, \
        49, 48, 47, 46, 45, 44, 43, 42, 41, 40, \
        39, 38, 37, 36, 35, 34, 33, 32, 31, 30, \
        29, 28, 27, 26, 25, 24, 23, 22, 21, 20, \
        19, 18, 17, 16, 15, 14, 13, 12, 11, 10, \
         9,  8,  7,  6,  5,  4,  3,  2,  1,  0

#define CLOSE_SOCKET(s) do { if ((s) != SSH_INVALID_SOCKET) { _XCLOSESOCKET(s); (s) = SSH_INVALID_SOCKET;} } while(0)

#ifndef HAVE_HTONLL
# ifdef WORDS_BIGENDIAN
#  define htonll(x) (x)
# else
#  define htonll(x) \
    (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# endif
#endif

#ifndef HAVE_NTOHLL
# ifdef WORDS_BIGENDIAN
#  define ntohll(x) (x)
# else
#  define ntohll(x) \
    (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
# endif
#endif

#ifndef FALL_THROUGH
# ifdef HAVE_FALLTHROUGH_ATTRIBUTE
#  define FALL_THROUGH __attribute__ ((fallthrough))
# else /* HAVE_FALLTHROUGH_ATTRIBUTE */
#  define FALL_THROUGH
# endif /* HAVE_FALLTHROUGH_ATTRIBUTE */
#endif /* FALL_THROUGH */

#ifndef __attr_unused__
# ifdef HAVE_UNUSED_ATTRIBUTE
#  define __attr_unused__ __attribute__((unused))
# else /* HAVE_UNUSED_ATTRIBUTE */
#  define __attr_unused__
# endif /* HAVE_UNUSED_ATTRIBUTE */
#endif /* __attr_unused__ */

#ifndef UNUSED_PARAM
#define UNUSED_PARAM(param) param __attr_unused__
#endif /* UNUSED_PARAM */

#ifndef UNUSED_VAR
#define UNUSED_VAR(var) __attr_unused__ var
#endif /* UNUSED_VAR */

void ssh_agent_state_free(void *data);

bool is_ssh_initialized(void);

#endif /* _LIBSSH_PRIV_H */
