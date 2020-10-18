/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

/**
 * @defgroup libssh_threads The SSH threading functions.
 * @ingroup libssh
 *
 * Threading with libssh
 * @{
 */

#include "config.h"

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/threads.h"

static struct ssh_threads_callbacks_struct *user_callbacks = NULL;

/** @internal
 * @brief inits the threading with the backend cryptographic libraries
 */

int ssh_threads_init(void)
{
    static int threads_initialized = 0;
    int rc;

    if (threads_initialized) {
        return SSH_OK;
    }

    /* first initialize the user_callbacks with our default handlers if not
     * already the case
     */
    if (user_callbacks == NULL){
        user_callbacks = ssh_threads_get_default();
    }

    /* Then initialize the crypto libraries threading callbacks */
    rc = crypto_thread_init(user_callbacks);
    if (rc == SSH_OK) {
        threads_initialized = 1;
    }
    return rc;
}

void ssh_threads_finalize(void)
{
    crypto_thread_finalize();
}

int ssh_threads_set_callbacks(struct ssh_threads_callbacks_struct *cb)
{

    int rc;

    if (user_callbacks != NULL) {
        crypto_thread_finalize();
    }

    user_callbacks = cb;

    rc = crypto_thread_init(user_callbacks);

    return rc;
}

const char *ssh_threads_get_type(void)
{
    if (user_callbacks != NULL) {
        return user_callbacks->type;
    }
    return NULL;
}

/**
 * @}
 */
