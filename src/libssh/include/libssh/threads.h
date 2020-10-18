/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#ifndef THREADS_H_
#define THREADS_H_

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#if HAVE_PTHREAD

#include <pthread.h>
#define SSH_MUTEX pthread_mutex_t

#if defined(PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP)
#define SSH_MUTEX_STATIC_INIT PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#else
#define SSH_MUTEX_STATIC_INIT PTHREAD_MUTEX_INITIALIZER
#endif

#elif (defined _WIN32) || (defined _WIN64)

#include <windows.h>
#include <winbase.h>
#define SSH_MUTEX CRITICAL_SECTION *
#define SSH_MUTEX_STATIC_INIT NULL

#else

# define SSH_MUTEX void *
#define SSH_MUTEX_STATIC_INIT NULL

#endif

int ssh_threads_init(void);
void ssh_threads_finalize(void);
const char *ssh_threads_get_type(void);

void ssh_mutex_lock(SSH_MUTEX *mutex);
void ssh_mutex_unlock(SSH_MUTEX *mutex);

struct ssh_threads_callbacks_struct *ssh_threads_get_default(void);
int crypto_thread_init(struct ssh_threads_callbacks_struct *user_callbacks);
void crypto_thread_finalize(void);

#endif /* THREADS_H_ */
