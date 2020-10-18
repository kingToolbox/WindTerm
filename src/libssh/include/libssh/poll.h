/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef POLL_H_
#define POLL_H_

#include "config.h"

#ifdef HAVE_POLL

#include <poll.h>
typedef struct pollfd ssh_pollfd_t;

#else /* HAVE_POLL */

/* poll emulation support */

typedef struct ssh_pollfd_struct {
  socket_t fd;      /* file descriptor */
  short events;     /* requested events */
  short revents;    /* returned events */
} ssh_pollfd_t;

typedef unsigned long int nfds_t;

#ifdef _WIN32

#ifndef POLLRDNORM
#define POLLRDNORM  0x0100
#endif
#ifndef POLLRDBAND
#define POLLRDBAND  0x0200
#endif
#ifndef POLLIN
#define POLLIN      (POLLRDNORM | POLLRDBAND)
#endif
#ifndef POLLPRI
#define POLLPRI     0x0400
#endif

#ifndef POLLWRNORM
#define POLLWRNORM  0x0010
#endif
#ifndef POLLOUT
#define POLLOUT     (POLLWRNORM)
#endif
#ifndef POLLWRBAND
#define POLLWRBAND  0x0020
#endif

#ifndef POLLERR
#define POLLERR     0x0001
#endif
#ifndef POLLHUP
#define POLLHUP     0x0002
#endif
#ifndef POLLNVAL
#define POLLNVAL    0x0004
#endif

#else /* _WIN32 */

/* poll.c */
#ifndef POLLIN
#define POLLIN    0x001  /* There is data to read.  */
#endif
#ifndef POLLPRI
#define POLLPRI   0x002  /* There is urgent data to read.  */
#endif
#ifndef POLLOUT
#define POLLOUT   0x004  /* Writing now will not block.  */
#endif

#ifndef POLLERR
#define POLLERR   0x008  /* Error condition.  */
#endif
#ifndef POLLHUP
#define POLLHUP   0x010  /* Hung up.  */
#endif
#ifndef POLLNVAL
#define POLLNVAL  0x020  /* Invalid polling request.  */
#endif

#ifndef POLLRDNORM
#define POLLRDNORM  0x040 /* mapped to read fds_set */
#endif
#ifndef POLLRDBAND
#define POLLRDBAND  0x080 /* mapped to exception fds_set */
#endif
#ifndef POLLWRNORM
#define POLLWRNORM  0x100 /* mapped to write fds_set */
#endif
#ifndef POLLWRBAND
#define POLLWRBAND  0x200 /* mapped to write fds_set */
#endif

#endif /* WIN32 */
#endif /* HAVE_POLL */

void ssh_poll_init(void);
void ssh_poll_cleanup(void);
int ssh_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout);
typedef struct ssh_poll_ctx_struct *ssh_poll_ctx;
typedef struct ssh_poll_handle_struct *ssh_poll_handle;

/**
 * @brief SSH poll callback. This callback will be used when an event
 *                      caught on the socket.
 *
 * @param p             Poll object this callback belongs to.
 * @param fd            The raw socket.
 * @param revents       The current poll events on the socket.
 * @param userdata      Userdata to be passed to the callback function.
 *
 * @return              0 on success, < 0 if you removed the poll object from
 *                      its poll context.
 */
typedef int (*ssh_poll_callback)(ssh_poll_handle p, socket_t fd, int revents,
    void *userdata);

struct ssh_socket_struct;

ssh_poll_handle ssh_poll_new(socket_t fd, short events, ssh_poll_callback cb,
    void *userdata);
void ssh_poll_free(ssh_poll_handle p);
ssh_poll_ctx ssh_poll_get_ctx(ssh_poll_handle p);
short ssh_poll_get_events(ssh_poll_handle p);
void ssh_poll_set_events(ssh_poll_handle p, short events);
void ssh_poll_add_events(ssh_poll_handle p, short events);
void ssh_poll_remove_events(ssh_poll_handle p, short events);
socket_t ssh_poll_get_fd(ssh_poll_handle p);
void ssh_poll_set_fd(ssh_poll_handle p, socket_t fd);
void ssh_poll_set_callback(ssh_poll_handle p, ssh_poll_callback cb, void *userdata);
ssh_poll_ctx ssh_poll_ctx_new(size_t chunk_size);
void ssh_poll_ctx_free(ssh_poll_ctx ctx);
int ssh_poll_ctx_add(ssh_poll_ctx ctx, ssh_poll_handle p);
int ssh_poll_ctx_add_socket (ssh_poll_ctx ctx, struct ssh_socket_struct *s);
void ssh_poll_ctx_remove(ssh_poll_ctx ctx, ssh_poll_handle p);
int ssh_poll_ctx_dopoll(ssh_poll_ctx ctx, int timeout);
ssh_poll_ctx ssh_poll_get_default_ctx(ssh_session session);
int ssh_event_add_poll(ssh_event event, ssh_poll_handle p);
void ssh_event_remove_poll(ssh_event event, ssh_poll_handle p);

#endif /* POLL_H_ */
