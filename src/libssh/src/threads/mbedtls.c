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

#include <mbedtls/threading.h>

int crypto_thread_init(struct ssh_threads_callbacks_struct *user_callbacks)
{
    int cmp;

    if (user_callbacks == NULL) {
        return SSH_OK;
    }

    cmp = strcmp(user_callbacks->type, "threads_noop");
    if (cmp == 0) {
        return SSH_OK;
    }
#ifdef MBEDTLS_THREADING_ALT
    else {
        if (user_callbacks != NULL) {
            crypto_thread_finalize();
        }

        mbedtls_threading_set_alt(user_callbacks->mutex_init,
                                  user_callbacks->mutex_destroy,
                                  user_callbacks->mutex_lock,
                                  user_callbacks->mutex_unlock);
    }
#elif defined MBEDTLS_THREADING_PTHREAD
    return SSH_OK;
#else
    return SSH_ERROR;
#endif
}

void crypto_thread_finalize(void)
{
#ifdef MBEDTLS_THREADING_ALT
    mbedtls_threading_free_alt();
#endif
    return;
}
