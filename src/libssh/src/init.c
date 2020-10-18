/*
 * init.c - initialization and finalization of the library
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"
#include "libssh/priv.h"
#include "libssh/socket.h"
#include "libssh/dh.h"
#include "libssh/poll.h"
#include "libssh/threads.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

/* Declare static mutex */
static SSH_MUTEX ssh_init_mutex = SSH_MUTEX_STATIC_INIT;

/* Counter for initializations */
static int _ssh_initialized = 0;

/* Cache the returned value */
static int _ssh_init_ret = 0;

void libssh_constructor(void) CONSTRUCTOR_ATTRIBUTE;
void libssh_destructor(void) DESTRUCTOR_ATTRIBUTE;

static int _ssh_init(unsigned constructor) {

    int rc = 0;

    if (!constructor) {
        ssh_mutex_lock(&ssh_init_mutex);
    }

    _ssh_initialized++;

    if (_ssh_initialized > 1) {
        rc = _ssh_init_ret;
        goto _ret;
    }

    rc = ssh_threads_init();
    if (rc) {
        goto _ret;
    }

    rc = ssh_crypto_init();
    if (rc) {
        goto _ret;
    }

    rc = ssh_dh_init();
    if (rc) {
        goto _ret;
    }

    rc = ssh_socket_init();
    if (rc) {
        goto _ret;
    }

_ret:
    _ssh_init_ret = rc;

    if (!constructor) {
        ssh_mutex_unlock(&ssh_init_mutex);
    }

    return rc;
}

/**
 * @brief Initialize global cryptographic data structures.
 *
 * This functions is automatically called when the library is loaded.
 *
 */
void libssh_constructor(void)
{

    int rc;

    rc = _ssh_init(1);

    if (rc < 0) {
        fprintf(stderr, "Error in auto_init()\n");
    }

    return;
}

/**
 * @defgroup libssh The libssh API
 *
 * The libssh library is implementing the SSH protocols and some of its
 * extensions. This group of functions is mostly used to implement an SSH
 * client.
 * Some function are needed to implement an SSH server too.
 *
 * @{
 */

/**
 * @brief Initialize global cryptographic data structures.
 *
 * Since version 0.8.0, when libssh is dynamically linked, it is not necessary
 * to call this function on systems which are fully supported with regards to
 * threading (that is, system with pthreads available).
 *
 * If libssh is statically linked, it is necessary to explicitly call ssh_init()
 * before calling any other provided API, and it is necessary to explicitly call
 * ssh_finalize() to free the allocated resources before exiting.
 *
 * If the library is already initialized, increments the _ssh_initialized
 * counter and return the error code cached in _ssh_init_ret.
 *
 * @returns             SSH_OK on success, SSH_ERROR if an error occurred.
 *
 * @see ssh_finalize()
 */
int ssh_init(void) {
    return _ssh_init(0);
}

static int _ssh_finalize(unsigned destructor) {

    if (!destructor) {
        ssh_mutex_lock(&ssh_init_mutex);

        if (_ssh_initialized > 1) {
            _ssh_initialized--;
            goto _ret;
        }

        if (_ssh_initialized == 1) {
            if (_ssh_init_ret < 0) {
                goto _ret;
            }
        }
    }

    /* If the counter reaches zero or it is the destructor calling, finalize */
    ssh_dh_finalize();
    ssh_crypto_finalize();
    ssh_socket_cleanup();
    /* It is important to finalize threading after CRYPTO because
     * it still depends on it */
    ssh_threads_finalize();

    _ssh_initialized = 0;

_ret:
    if (!destructor) {
        ssh_mutex_unlock(&ssh_init_mutex);
    }
    return 0;
}

/**
 * @brief Finalize and cleanup all libssh and cryptographic data structures.
 *
 * This function is automatically called when the library is unloaded.
 *
 */
void libssh_destructor(void)
{
    int rc;

    rc = _ssh_finalize(1);

    if (rc < 0) {
        fprintf(stderr, "Error in libssh_destructor()\n");
    }
}

/**
 * @brief Finalize and cleanup all libssh and cryptographic data structures.
 *
 * Since version 0.8.0, when libssh is dynamically linked, it is not necessary
 * to call this function, since it is automatically called when the library is
 * unloaded.
 *
 * If libssh is statically linked, it is necessary to explicitly call ssh_init()
 * before calling any other provided API, and it is necessary to explicitly call
 * ssh_finalize() to free the allocated resources before exiting.
 *
 * If ssh_init() is called explicitly, then ssh_finalize() must be called
 * explicitly.
 *
 * When called, decrements the counter _ssh_initialized. If the counter reaches
 * zero, then the libssh and cryptographic data structures are cleaned up.
 *
 * @returns             0 on success, -1 if an error occurred.
 *
 * @see ssh_init()
 */
int ssh_finalize(void) {
    return _ssh_finalize(0);
}

#ifdef _WIN32

#if defined(_MSC_VER) && !defined(LIBSSH_STATIC)
/* Library constructor and destructor */
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD fdwReason,
                    LPVOID lpvReserved)
{
    int rc = 0;

    switch(fdwReason) {
    case DLL_PROCESS_ATTACH:
        rc = _ssh_init(1);
        if (rc != 0) {
            fprintf(stderr, "DllMain: ssh_init failed!");
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        _ssh_finalize(1);
        break;
    default:
        break;
    }

    return TRUE;
}
#endif /* _MSC_VER && !LIBSSH_STATIC */

#endif /* _WIN32 */

/**
 * @internal
 * @brief Return whether the library is initialized
 *
 * @returns true if the library is initialized; false otherwise.
 *
 * @see ssh_init()
 */
bool is_ssh_initialized() {

    bool is_initialized = false;

    ssh_mutex_lock(&ssh_init_mutex);
    is_initialized = _ssh_initialized > 0;
    ssh_mutex_unlock(&ssh_init_mutex);

    return is_initialized;
}

/** @} */
