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

#include "config.h"
#include "libssh/threads.h"
#include <libssh/callbacks.h>

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

static int ssh_pthread_mutex_init (void **mutex)
{
    int rc = 0;

    if (mutex == NULL) {
        return EINVAL;
    }

    *mutex = malloc(sizeof(pthread_mutex_t));
    if (*mutex == NULL) {
        return ENOMEM;
    }

    rc = pthread_mutex_init ((pthread_mutex_t *)*mutex, NULL);
    if (rc){
        free (*mutex);
        *mutex = NULL;
    }

    return rc;
}

static int ssh_pthread_mutex_destroy (void **mutex)
{

    int rc = 0;

    if (mutex == NULL) {
        return EINVAL;
    }

    rc = pthread_mutex_destroy ((pthread_mutex_t *)*mutex);

    free (*mutex);
    *mutex = NULL;

    return rc;
}

static int ssh_pthread_mutex_lock (void **mutex)
{
    return pthread_mutex_lock((pthread_mutex_t *)*mutex);
}

static int ssh_pthread_mutex_unlock (void **mutex)
{
    return pthread_mutex_unlock((pthread_mutex_t *)*mutex);
}

static unsigned long ssh_pthread_thread_id (void)
{
#if defined(_WIN32) && !defined(__WINPTHREADS_VERSION)
    return (unsigned long) pthread_self().p;
#else
    return (unsigned long) pthread_self();
#endif
}

static struct ssh_threads_callbacks_struct ssh_threads_pthread =
{
    .type = "threads_pthread",
    .mutex_init = ssh_pthread_mutex_init,
    .mutex_destroy = ssh_pthread_mutex_destroy,
    .mutex_lock = ssh_pthread_mutex_lock,
    .mutex_unlock = ssh_pthread_mutex_unlock,
    .thread_id = ssh_pthread_thread_id
};

/* Threads interface implementation */

#if (HAVE_PTHREAD)
void ssh_mutex_lock(SSH_MUTEX *mutex)
{
    int rc;

    if (mutex == NULL) {
        exit(EINVAL);
    }

    rc = pthread_mutex_lock(mutex);

    if (rc) {
        exit(rc);
    }
}

void ssh_mutex_unlock(SSH_MUTEX *mutex)
{
    int rc;

    if (mutex == NULL) {
        exit(EINVAL);
    }

    rc = pthread_mutex_unlock(mutex);

    if (rc) {
        exit(rc);
    }
}

struct ssh_threads_callbacks_struct *ssh_threads_get_default(void)
{
    return &ssh_threads_pthread;
}
#endif

struct ssh_threads_callbacks_struct *ssh_threads_get_pthread(void)
{
    return &ssh_threads_pthread;
}
