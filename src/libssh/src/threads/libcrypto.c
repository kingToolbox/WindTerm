/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Anderson Toshiyuki Sasaki
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
#include "libssh/crypto.h"
#include "libssh/threads.h"
#include <libssh/callbacks.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000)

int crypto_thread_init(struct ssh_threads_callbacks_struct *cb)
{
    (void) cb;
    return SSH_OK;
}

void crypto_thread_finalize(void)
{
    return;
}

#else

static struct ssh_threads_callbacks_struct *user_callbacks = NULL;

static void **libcrypto_mutexes;

void libcrypto_lock_callback(int mode, int i, const char *file, int line);

void libcrypto_lock_callback(int mode, int i, const char *file, int line)
{
    (void)file;
    (void)line;

    if (mode & CRYPTO_LOCK) {
        user_callbacks->mutex_lock(&libcrypto_mutexes[i]);
    } else {
        user_callbacks->mutex_unlock(&libcrypto_mutexes[i]);
    }
}

#ifdef HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK
static void libcrypto_THREADID_callback(CRYPTO_THREADID *id)
{
    unsigned long thread_id = (*user_callbacks->thread_id)();

    CRYPTO_THREADID_set_numeric(id, thread_id);
}
#endif /* HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK */

int crypto_thread_init(struct ssh_threads_callbacks_struct *cb)
{
    int n = CRYPTO_num_locks();
    int cmp;
    int i;

    if (cb == NULL) {
        return SSH_OK;
    }

    if (user_callbacks != NULL) {
        crypto_thread_finalize();
    }

    user_callbacks = cb;

    cmp = strcmp(user_callbacks->type, "threads_noop");
    if (cmp == 0) {
        return SSH_OK;
    }

    libcrypto_mutexes = calloc(n, sizeof(void *));
    if (libcrypto_mutexes == NULL) {
        return SSH_ERROR;
    }

    for (i = 0; i < n; ++i){
        user_callbacks->mutex_init(&libcrypto_mutexes[i]);
    }

#ifdef HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK
    CRYPTO_THREADID_set_callback(libcrypto_THREADID_callback);
#else
    CRYPTO_set_id_callback(user_callbacks->thread_id);
#endif

    CRYPTO_set_locking_callback(libcrypto_lock_callback);

    return SSH_OK;
}

void crypto_thread_finalize(void)
{
    int n = CRYPTO_num_locks();
    int i;

    if (libcrypto_mutexes == NULL) {
        return;
    }

#ifdef HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK
    CRYPTO_THREADID_set_callback(NULL);
#else
    CRYPTO_set_id_callback(NULL);
#endif

    CRYPTO_set_locking_callback(NULL);

    for (i = 0; i < n; ++i) {
            user_callbacks->mutex_destroy(&libcrypto_mutexes[i]);
    }
    SAFE_FREE(libcrypto_mutexes);
}

#endif
