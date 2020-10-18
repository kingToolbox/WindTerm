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

#if (GCRYPT_VERSION_NUMBER >= 0x010600)
/* libgcrypt >= 1.6 does not support custom callbacks */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

int crypto_thread_init(struct ssh_threads_callbacks_struct *user_callbacks)
{
    (void) user_callbacks;

    return SSH_OK;
}

#else
/* Libgcrypt < 1.6 specific way of handling thread callbacks */

static struct gcry_thread_cbs gcrypt_threads_callbacks;

int crypto_thread_init(struct ssh_threads_callbacks_struct *user_callbacks)
{
    int cmp;

    if (user_callbacks == NULL) {
        return SSH_OK;
    }

    cmp = strcmp(user_callbacks->type, "threads_noop");
    if (cmp == 0) {
        gcrypt_threads_callbacks.option= GCRY_THREAD_OPTION_VERSION << 8 ||
        GCRY_THREAD_OPTION_DEFAULT;
    } else {
        gcrypt_threads_callbacks.option= GCRY_THREAD_OPTION_VERSION << 8 ||
        GCRY_THREAD_OPTION_USER;
    }

    gcrypt_threads_callbacks.mutex_init = user_callbacks->mutex_init;
    gcrypt_threads_callbacks.mutex_destroy = user_callbacks->mutex_destroy;
    gcrypt_threads_callbacks.mutex_lock = user_callbacks->mutex_lock;
    gcrypt_threads_callbacks.mutex_unlock = user_callbacks->mutex_unlock;
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcrypt_threads_callbacks);

    return SSH_OK;
}

#endif /* GCRYPT_VERSION_NUMBER */

void crypto_thread_finalize(void)
{
    return;
}
