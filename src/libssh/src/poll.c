/*
 * poll.c - poll wrapper
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2003-2013 by Aris Adamantiadis
 * Copyright (c) 2009 Aleksandar Kanchev
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

#include <errno.h>
#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/poll.h"
#include "libssh/socket.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#ifdef WITH_SERVER
#include "libssh/server.h"
#endif


#ifndef SSH_POLL_CTX_CHUNK
#define SSH_POLL_CTX_CHUNK			5
#endif

/**
 * @defgroup libssh_poll The SSH poll functions.
 * @ingroup libssh
 *
 * Add a generic way to handle sockets asynchronously.
 *
 * It's based on poll objects, each of which store a socket, its events and a
 * callback, which gets called whenever an event is set. The poll objects are
 * attached to a poll context, which should be allocated on per thread basis.
 *
 * Polling the poll context will poll all the attached poll objects and call
 * their callbacks (handlers) if any of the socket events are set. This should
 * be done within the main loop of an application.
 *
 * @{
 */

struct ssh_poll_handle_struct {
  ssh_poll_ctx ctx;
  ssh_session session;
  union {
    socket_t fd;
    size_t idx;
  } x;
  short events;
  int lock;
  ssh_poll_callback cb;
  void *cb_data;
};

struct ssh_poll_ctx_struct {
  ssh_poll_handle *pollptrs;
  ssh_pollfd_t *pollfds;
  size_t polls_allocated;
  size_t polls_used;
  size_t chunk_size;
};

#ifdef HAVE_POLL
#include <poll.h>

void ssh_poll_init(void) {
    return;
}

void ssh_poll_cleanup(void) {
    return;
}

int ssh_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout) {
  return poll((struct pollfd *) fds, nfds, timeout);
}

#else /* HAVE_POLL */

typedef int (*poll_fn)(ssh_pollfd_t *, nfds_t, int);
static poll_fn ssh_poll_emu;

#include <sys/types.h>
#include <stdbool.h>

#ifdef _WIN32
#ifndef STRICT
#define STRICT
#endif /* STRICT */

#include <time.h>
#include <windows.h>
#include <winsock2.h>
#else /* _WIN32 */
#include <sys/select.h>
#include <sys/socket.h>

# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# endif

#endif /* _WIN32 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static bool bsd_socket_not_connected(int sock_err)
{
    switch (sock_err) {
#ifdef _WIN32
    case WSAENOTCONN:
#else
    case ENOTCONN:
#endif
        return true;
    default:
        return false;
    }

    return false;
}

static bool bsd_socket_reset(int sock_err)
{
    switch (sock_err) {
#ifdef _WIN32
    case WSAECONNABORTED:
    case WSAECONNRESET:
    case WSAENETRESET:
    case WSAESHUTDOWN:
    case WSAECONNREFUSED:
    case WSAETIMEDOUT:
#else
    case ECONNABORTED:
    case ECONNRESET:
    case ENETRESET:
    case ESHUTDOWN:
#endif
        return true;
    default:
        return false;
    }

    return false;
}

static short bsd_socket_compute_revents(int fd, short events)
{
    int save_errno = errno;
    int sock_errno = errno;
    char data[64] = {0};
    short revents = 0;
    int flags = MSG_PEEK;
    int ret;

#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif

    /* support for POLLHUP */
#ifdef _WIN32
    WSASetLastError(0);
#endif

    ret = recv(fd, data, 64, flags);

    errno = save_errno;

#ifdef _WIN32
    sock_errno = WSAGetLastError();
    WSASetLastError(0);
#endif

    if (ret > 0 || bsd_socket_not_connected(sock_errno)) {
        revents = (POLLIN | POLLRDNORM) & events;
    } else if (ret == 0 || bsd_socket_reset(sock_errno)) {
        errno = sock_errno;
        revents = POLLHUP;
    } else {
        revents = POLLERR;
    }

    return revents;
}

/*
 * This is a poll(2)-emulation using select for systems not providing a native
 * poll implementation.
 *
 * Keep in mind that select is terribly inefficient. The interface is simply not
 * meant to be used with maximum descriptor value greater, say, 32 or so.  With
 * a value as high as 1024 on Linux you'll pay dearly in every single call.
 * poll() will be orders of magnitude faster.
 */
static int bsd_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout)
{
    fd_set readfds, writefds, exceptfds;
    struct timeval tv, *ptv = NULL;
    socket_t max_fd;
    int rc;
    nfds_t i;

    if (fds == NULL) {
        errno = EFAULT;
        return -1;
    }

    ZERO_STRUCT(readfds);
    FD_ZERO(&readfds);
    ZERO_STRUCT(writefds);
    FD_ZERO(&writefds);
    ZERO_STRUCT(exceptfds);
    FD_ZERO(&exceptfds);

    /* compute fd_sets and find largest descriptor */
    for (rc = -1, max_fd = 0, i = 0; i < nfds; i++) {
        if (fds[i].fd == SSH_INVALID_SOCKET) {
            continue;
        }
#ifndef _WIN32
        if (fds[i].fd >= FD_SETSIZE) {
            rc = -1;
            break;
        }
#endif

        if (fds[i].events & (POLLIN | POLLRDNORM)) {
            FD_SET (fds[i].fd, &readfds);
        }
        if (fds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
            FD_SET (fds[i].fd, &writefds);
        }
        if (fds[i].events & (POLLPRI | POLLRDBAND)) {
            FD_SET (fds[i].fd, &exceptfds);
        }
        if (fds[i].fd > max_fd &&
                (fds[i].events & (POLLIN | POLLOUT | POLLPRI |
                                  POLLRDNORM | POLLRDBAND |
                                  POLLWRNORM | POLLWRBAND))) {
            max_fd = fds[i].fd;
            rc = 0;
        }
    }

    if (max_fd == SSH_INVALID_SOCKET || rc == -1) {
        errno = EINVAL;
        return -1;
    }

    if (timeout < 0) {
        ptv = NULL;
    } else {
        ptv = &tv;
        if (timeout == 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
        }
    }

    rc = select(max_fd + 1, &readfds, &writefds, &exceptfds, ptv);
    if (rc < 0) {
        return -1;
    }
    /* A timeout occured */
    if (rc == 0) {
        return 0;
    }

    for (rc = 0, i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            fds[i].revents = 0;

            if (FD_ISSET(fds[i].fd, &readfds)) {
                fds[i].revents = bsd_socket_compute_revents(fds[i].fd,
                                                            fds[i].events);
            }
            if (FD_ISSET(fds[i].fd, &writefds)) {
                fds[i].revents |= fds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND);
            }

            if (FD_ISSET(fds[i].fd, &exceptfds)) {
                fds[i].revents |= fds[i].events & (POLLPRI | POLLRDBAND);
            }

            if (fds[i].revents != 0) {
                rc++;
            }
        } else {
            fds[i].revents = POLLNVAL;
        }
    }

    return rc;
}

void ssh_poll_init(void) {
    ssh_poll_emu = bsd_poll;
}

void ssh_poll_cleanup(void) {
    ssh_poll_emu = bsd_poll;
}

int ssh_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout) {
    return (ssh_poll_emu)(fds, nfds, timeout);
}

#endif /* HAVE_POLL */

/**
 * @brief  Allocate a new poll object, which could be used within a poll context.
 *
 * @param  fd           Socket that will be polled.
 * @param  events       Poll events that will be monitored for the socket. i.e.
 *                      POLLIN, POLLPRI, POLLOUT
 * @param  cb           Function to be called if any of the events are set.
 *                      The prototype of cb is:
 *                      int (*ssh_poll_callback)(ssh_poll_handle p, socket_t fd,
 *                                                 int revents, void *userdata);
 * @param  userdata     Userdata to be passed to the callback function. NULL if
 *                      not needed.
 *
 * @return              A new poll object, NULL on error
 */

ssh_poll_handle ssh_poll_new(socket_t fd, short events, ssh_poll_callback cb,
    void *userdata) {
    ssh_poll_handle p;

    p = malloc(sizeof(struct ssh_poll_handle_struct));
    if (p == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(p);

    p->x.fd = fd;
    p->events = events;
    p->cb = cb;
    p->cb_data = userdata;

    return p;
}


/**
 * @brief  Free a poll object.
 *
 * @param  p            Pointer to an already allocated poll object.
 */

void ssh_poll_free(ssh_poll_handle p) {
	if(p->ctx != NULL){
		ssh_poll_ctx_remove(p->ctx,p);
		p->ctx=NULL;
	}
  SAFE_FREE(p);
}

/**
 * @brief  Get the poll context of a poll object.
 *
 * @param  p            Pointer to an already allocated poll object.
 *
 * @return              Poll context or NULL if the poll object isn't attached.
 */
ssh_poll_ctx ssh_poll_get_ctx(ssh_poll_handle p) {
  return p->ctx;
}

/**
 * @brief  Get the events of a poll object.
 *
 * @param  p            Pointer to an already allocated poll object.
 *
 * @return              Poll events.
 */
short ssh_poll_get_events(ssh_poll_handle p) {
  return p->events;
}

/**
 * @brief  Set the events of a poll object. The events will also be propagated
 *         to an associated poll context.
 *
 * @param  p            Pointer to an already allocated poll object.
 * @param  events       Poll events.
 */
void ssh_poll_set_events(ssh_poll_handle p, short events) {
  p->events = events;
  if (p->ctx != NULL && !p->lock) {
    p->ctx->pollfds[p->x.idx].events = events;
  }
}

/**
 * @brief  Set the file descriptor of a poll object. The FD will also be propagated
 *         to an associated poll context.
 *
 * @param  p            Pointer to an already allocated poll object.
 * @param  fd       New file descriptor.
 */
void ssh_poll_set_fd(ssh_poll_handle p, socket_t fd) {
  if (p->ctx != NULL) {
    p->ctx->pollfds[p->x.idx].fd = fd;
  } else {
  	p->x.fd = fd;
  }
}

/**
 * @brief  Add extra events to a poll object. Duplicates are ignored.
 *         The events will also be propagated to an associated poll context.
 *
 * @param  p            Pointer to an already allocated poll object.
 * @param  events       Poll events.
 */
void ssh_poll_add_events(ssh_poll_handle p, short events) {
  ssh_poll_set_events(p, ssh_poll_get_events(p) | events);
}

/**
 * @brief  Remove events from a poll object. Non-existent are ignored.
 *         The events will also be propagated to an associated poll context.
 *
 * @param  p            Pointer to an already allocated poll object.
 * @param  events       Poll events.
 */
void ssh_poll_remove_events(ssh_poll_handle p, short events) {
  ssh_poll_set_events(p, ssh_poll_get_events(p) & ~events);
}

/**
 * @brief  Get the raw socket of a poll object.
 *
 * @param  p            Pointer to an already allocated poll object.
 *
 * @return              Raw socket.
 */

socket_t ssh_poll_get_fd(ssh_poll_handle p) {
  if (p->ctx != NULL) {
    return p->ctx->pollfds[p->x.idx].fd;
  }

  return p->x.fd;
}
/**
 * @brief  Set the callback of a poll object.
 *
 * @param  p            Pointer to an already allocated poll object.
 * @param  cb           Function to be called if any of the events are set.
 * @param  userdata     Userdata to be passed to the callback function. NULL if
 *                      not needed.
 */
void ssh_poll_set_callback(ssh_poll_handle p, ssh_poll_callback cb, void *userdata) {
  if (cb != NULL) {
    p->cb = cb;
    p->cb_data = userdata;
  }
}

/**
 * @brief  Create a new poll context. It could be associated with many poll object
 *         which are going to be polled at the same time as the poll context. You
 *         would need a single poll context per thread.
 *
 * @param  chunk_size   The size of the memory chunk that will be allocated, when
 *                      more memory is needed. This is for efficiency reasons,
 *                      i.e. don't allocate memory for each new poll object, but
 *                      for the next 5. Set it to 0 if you want to use the
 *                      library's default value.
 */
ssh_poll_ctx ssh_poll_ctx_new(size_t chunk_size) {
    ssh_poll_ctx ctx;

    ctx = malloc(sizeof(struct ssh_poll_ctx_struct));
    if (ctx == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(ctx);

    if (chunk_size == 0) {
        chunk_size = SSH_POLL_CTX_CHUNK;
    }

    ctx->chunk_size = chunk_size;

    return ctx;
}

/**
 * @brief  Free a poll context.
 *
 * @param  ctx          Pointer to an already allocated poll context.
 */
void ssh_poll_ctx_free(ssh_poll_ctx ctx) {
  if (ctx->polls_allocated > 0) {
    while (ctx->polls_used > 0){
      ssh_poll_handle p = ctx->pollptrs[0];
      /*
       * The free function calls ssh_poll_ctx_remove() and decrements
       * ctx->polls_used
       */
      ssh_poll_free(p);
    }

    SAFE_FREE(ctx->pollptrs);
    SAFE_FREE(ctx->pollfds);
  }

  SAFE_FREE(ctx);
}

static int ssh_poll_ctx_resize(ssh_poll_ctx ctx, size_t new_size) {
  ssh_poll_handle *pollptrs;
  ssh_pollfd_t *pollfds;

  pollptrs = realloc(ctx->pollptrs, sizeof(ssh_poll_handle) * new_size);
  if (pollptrs == NULL) {
    return -1;
  }
  ctx->pollptrs = pollptrs;

  pollfds = realloc(ctx->pollfds, sizeof(ssh_pollfd_t) * new_size);
  if (pollfds == NULL) {
    pollptrs = realloc(ctx->pollptrs, sizeof(ssh_poll_handle) * ctx->polls_allocated);
    if (pollptrs == NULL) {
        return -1;
    }
    ctx->pollptrs = pollptrs;
    return -1;
  }

  ctx->pollfds = pollfds;
  ctx->polls_allocated = new_size;

  return 0;
}

/**
 * @brief  Add a poll object to a poll context.
 *
 * @param  ctx          Pointer to an already allocated poll context.
 * @param  p            Pointer to an already allocated poll object.
 *
 * @return              0 on success, < 0 on error
 */
int ssh_poll_ctx_add(ssh_poll_ctx ctx, ssh_poll_handle p) {
  socket_t fd;

  if (p->ctx != NULL) {
    /* already attached to a context */
    return -1;
  }

  if (ctx->polls_used == ctx->polls_allocated &&
      ssh_poll_ctx_resize(ctx, ctx->polls_allocated + ctx->chunk_size) < 0) {
    return -1;
  }

  fd = p->x.fd;
  p->x.idx = ctx->polls_used++;
  ctx->pollptrs[p->x.idx] = p;
  ctx->pollfds[p->x.idx].fd = fd;
  ctx->pollfds[p->x.idx].events = p->events;
  ctx->pollfds[p->x.idx].revents = 0;
  p->ctx = ctx;

  return 0;
}

/**
 * @brief  Add a socket object to a poll context.
 *
 * @param  ctx          Pointer to an already allocated poll context.
 * @param  s            A SSH socket handle
 *
 * @return              0 on success, < 0 on error
 */
int ssh_poll_ctx_add_socket (ssh_poll_ctx ctx, ssh_socket s)
{
    ssh_poll_handle p;
    int ret;

    p = ssh_socket_get_poll_handle(s);
    if (p == NULL) {
        return -1;
    }
    ret = ssh_poll_ctx_add(ctx,p);
    return ret;
}


/**
 * @brief  Remove a poll object from a poll context.
 *
 * @param  ctx          Pointer to an already allocated poll context.
 * @param  p            Pointer to an already allocated poll object.
 */
void ssh_poll_ctx_remove(ssh_poll_ctx ctx, ssh_poll_handle p) {
  size_t i;

  i = p->x.idx;
  p->x.fd = ctx->pollfds[i].fd;
  p->ctx = NULL;

  ctx->polls_used--;

  /* fill the empty poll slot with the last one */
  if (ctx->polls_used > 0 && ctx->polls_used != i) {
    ctx->pollfds[i] = ctx->pollfds[ctx->polls_used];
    ctx->pollptrs[i] = ctx->pollptrs[ctx->polls_used];
    ctx->pollptrs[i]->x.idx = i;
  }

  /* this will always leave at least chunk_size polls allocated */
  if (ctx->polls_allocated - ctx->polls_used > ctx->chunk_size) {
    ssh_poll_ctx_resize(ctx, ctx->polls_allocated - ctx->chunk_size);
  }
}

/**
 * @brief  Poll all the sockets associated through a poll object with a
 *         poll context. If any of the events are set after the poll, the
 *         call back function of the socket will be called.
 *         This function should be called once within the programs main loop.
 *
 * @param  ctx          Pointer to an already allocated poll context.
 * @param  timeout      An upper limit on the time for which ssh_poll_ctx() will
 *                      block, in milliseconds. Specifying a negative value
 *                      means an infinite timeout. This parameter is passed to
 *                      the poll() function.
 * @returns SSH_OK      No error.
 *          SSH_ERROR   Error happened during the poll.
 *          SSH_AGAIN   Timeout occured
 */

int ssh_poll_ctx_dopoll(ssh_poll_ctx ctx, int timeout)
{
    int rc;
    size_t i, used;
    ssh_poll_handle p;
    socket_t fd;
    int revents;
    struct ssh_timestamp ts;

    if (ctx->polls_used == 0) {
        return SSH_ERROR;
    }

    ssh_timestamp_init(&ts);
    do {
        int tm = ssh_timeout_update(&ts, timeout);
        rc = ssh_poll(ctx->pollfds, ctx->polls_used, tm);
    } while (rc == -1 && errno == EINTR);

    if (rc < 0) {
        return SSH_ERROR;
    }
    if (rc == 0) {
        return SSH_AGAIN;
    }

    used = ctx->polls_used;
    for (i = 0; i < used && rc > 0; ) {
        if (!ctx->pollfds[i].revents || ctx->pollptrs[i]->lock) {
            i++;
        } else {
            int ret;

            p = ctx->pollptrs[i];
            fd = ctx->pollfds[i].fd;
            revents = ctx->pollfds[i].revents;
            /* avoid having any event caught during callback */
            ctx->pollfds[i].events = 0;
            p->lock = 1;
            if (p->cb && (ret = p->cb(p, fd, revents, p->cb_data)) < 0) {
                if (ret == -2) {
                    return -1;
                }
                /* the poll was removed, reload the used counter and start again */
                used = ctx->polls_used;
                i = 0;
            } else {
                ctx->pollfds[i].revents = 0;
                ctx->pollfds[i].events = p->events;
                p->lock = 0;
                i++;
            }

            rc--;
        }
    }

    return rc;
}

/**
 * @internal
 * @brief gets the default poll structure for the current session,
 * when used in blocking mode.
 * @param session SSH session
 * @returns the default ssh_poll_ctx
 */
ssh_poll_ctx ssh_poll_get_default_ctx(ssh_session session){
	if(session->default_poll_ctx != NULL)
		return session->default_poll_ctx;
	/* 2 is enough for the default one */
	session->default_poll_ctx = ssh_poll_ctx_new(2);
	return session->default_poll_ctx;
}

/* public event API */

struct ssh_event_fd_wrapper {
    ssh_event_callback cb;
    void * userdata;
};

struct ssh_event_struct {
    ssh_poll_ctx ctx;
#ifdef WITH_SERVER
    struct ssh_list *sessions;
#endif
};

/**
 * @brief  Create a new event context. It could be associated with many
 *         ssh_session objects and socket fd which are going to be polled at the
 *         same time as the event context. You would need a single event context
 *         per thread.
 * 
 * @return  The ssh_event object on success, NULL on failure.
 */
ssh_event ssh_event_new(void) {
    ssh_event event;

    event = malloc(sizeof(struct ssh_event_struct));
    if (event == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(event);

    event->ctx = ssh_poll_ctx_new(2);
    if(event->ctx == NULL) {
        free(event);
        return NULL;
    }

#ifdef WITH_SERVER
    event->sessions = ssh_list_new();
    if(event->sessions == NULL) {
        ssh_poll_ctx_free(event->ctx);
        free(event);
        return NULL;
    }
#endif

    return event;
}

static int ssh_event_fd_wrapper_callback(ssh_poll_handle p, socket_t fd, int revents,
                                                            void *userdata) {
    struct ssh_event_fd_wrapper *pw = (struct ssh_event_fd_wrapper *)userdata;

    (void)p;
    if(pw->cb != NULL) {
        return pw->cb(fd, revents, pw->userdata);
    }
    return 0;
}

/**
 * @brief Add a fd to the event and assign it a callback,
 * when used in blocking mode.
 * @param event         The ssh_event
 * @param  fd           Socket that will be polled.
 * @param  events       Poll events that will be monitored for the socket. i.e.
 *                      POLLIN, POLLPRI, POLLOUT
 * @param  cb           Function to be called if any of the events are set.
 *                      The prototype of cb is:
 *                      int (*ssh_event_callback)(socket_t fd, int revents,
 *                                                          void *userdata);
 * @param  userdata     Userdata to be passed to the callback function. NULL if
 *                      not needed.
 *
 * @returns SSH_OK      on success
 *          SSH_ERROR   on failure
 */
int ssh_event_add_fd(ssh_event event, socket_t fd, short events,
                                    ssh_event_callback cb, void *userdata) {
    ssh_poll_handle p;
    struct ssh_event_fd_wrapper *pw;
    
    if(event == NULL || event->ctx == NULL || cb == NULL
                                           || fd == SSH_INVALID_SOCKET) {
        return SSH_ERROR;
    }
    pw = malloc(sizeof(struct ssh_event_fd_wrapper));
    if(pw == NULL) {
        return SSH_ERROR;
    }

    pw->cb = cb;
    pw->userdata = userdata;

    /* pw is freed by ssh_event_remove_fd */
    p = ssh_poll_new(fd, events, ssh_event_fd_wrapper_callback, pw);
    if(p == NULL) {
        free(pw);
        return SSH_ERROR;
    }

    if(ssh_poll_ctx_add(event->ctx, p) < 0) {
        free(pw);
        ssh_poll_free(p);
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Add a poll handle to the event.
 *
 * @param   event     the ssh_event
 *
 * @param   p         the poll handle
 *
 * @returns SSH_OK    on success
 *          SSH_ERROR on failure
 */
int ssh_event_add_poll(ssh_event event, ssh_poll_handle p)
{
    return ssh_poll_ctx_add(event->ctx, p);
}

/**
 * @brief remove a poll handle to the event.
 *
 * @param   event     the ssh_event
 *
 * @param   p         the poll handle
 */
void ssh_event_remove_poll(ssh_event event, ssh_poll_handle p)
{
    ssh_poll_ctx_remove(event->ctx,p);
}

/**
 * @brief remove the poll handle from session and assign them to a event,
 * when used in blocking mode.
 *
 * @param event     The ssh_event object
 * @param session   The session to add to the event.
 *
 * @returns SSH_OK      on success
 *          SSH_ERROR   on failure
 */
int ssh_event_add_session(ssh_event event, ssh_session session) {
    ssh_poll_handle p;
#ifdef WITH_SERVER
    struct ssh_iterator *iterator;
#endif

    if(event == NULL || event->ctx == NULL || session == NULL) {
        return SSH_ERROR;
    }
    if(session->default_poll_ctx == NULL) {
        return SSH_ERROR;
    }
    while (session->default_poll_ctx->polls_used > 0) {
        p = session->default_poll_ctx->pollptrs[0];
        /*
         * ssh_poll_ctx_remove() decrements
         * session->default_poll_ctx->polls_used
         */
        ssh_poll_ctx_remove(session->default_poll_ctx, p);
        ssh_poll_ctx_add(event->ctx, p);
        /* associate the pollhandler with a session so we can put it back
         * at ssh_event_free()
         */
        p->session = session;
    }
#ifdef WITH_SERVER
    iterator = ssh_list_get_iterator(event->sessions);
    while(iterator != NULL) {
        if((ssh_session)iterator->data == session) {
            /* allow only one instance of this session */
            return SSH_OK;
        }
        iterator = iterator->next;
    }
    if(ssh_list_append(event->sessions, session) == SSH_ERROR) {
        return SSH_ERROR;
    }
#endif
    return SSH_OK;
}

/**
 * @brief Add a connector to the SSH event loop
 *
 * @param[in] event The SSH event loop
 *
 * @param[in] connector The connector object
 *
 * @return SSH_OK
 *
 * @return SSH_ERROR in case of error
 */
int ssh_event_add_connector(ssh_event event, ssh_connector connector){
    return ssh_connector_set_event(connector, event);
}

/**
 * @brief Poll all the sockets and sessions associated through an event object.i
 *
 * If any of the events are set after the poll, the call back functions of the
 * sessions or sockets will be called.
 * This function should be called once within the programs main loop.
 *
 * @param  event        The ssh_event object to poll.
 *
 * @param  timeout      An upper limit on the time for which the poll will
 *                      block, in milliseconds. Specifying a negative value
 *                      means an infinite timeout. This parameter is passed to
 *                      the poll() function.
 * @returns SSH_OK      on success.
 *          SSH_ERROR   Error happened during the poll.
 *          SSH_AGAIN   Timeout occured
 */
int ssh_event_dopoll(ssh_event event, int timeout) {
    int rc;

    if(event == NULL || event->ctx == NULL) {
        return SSH_ERROR;
    }
    rc = ssh_poll_ctx_dopoll(event->ctx, timeout);
    return rc;
}

/**
 * @brief  Remove a socket fd from an event context.
 *
 * @param  event        The ssh_event object.
 * @param  fd           The fd to remove.
 *
 * @returns SSH_OK      on success
 *          SSH_ERROR   on failure
 */
int ssh_event_remove_fd(ssh_event event, socket_t fd) {
    register size_t i, used;
    int rc = SSH_ERROR;

    if(event == NULL || event->ctx == NULL) {
        return SSH_ERROR;
    }

    used = event->ctx->polls_used;
    for (i = 0; i < used; i++) {
        if(fd == event->ctx->pollfds[i].fd) {
            ssh_poll_handle p = event->ctx->pollptrs[i];
            if (p->session != NULL){
            	/* we cannot free that handle, it's owned by its session */
            	continue;
            }
            if (p->cb == ssh_event_fd_wrapper_callback) {
                struct ssh_event_fd_wrapper *pw = p->cb_data;
                SAFE_FREE(pw);
            }

            /*
             * The free function calls ssh_poll_ctx_remove() and decrements
             * event->ctx->polls_used.
             */
            ssh_poll_free(p);
            rc = SSH_OK;

            /* restart the loop */
            used = event->ctx->polls_used;
            i = 0;
        }
    }

    return rc;
}

/**
 * @brief  Remove a session object from an event context.
 *
 * @param  event        The ssh_event object.
 * @param  session      The session to remove.
 *
 * @returns SSH_OK      on success
 *          SSH_ERROR   on failure
 */
int ssh_event_remove_session(ssh_event event, ssh_session session) {
    ssh_poll_handle p;
    register size_t i, used;
    int rc = SSH_ERROR;
#ifdef WITH_SERVER
    struct ssh_iterator *iterator;
#endif

    if(event == NULL || event->ctx == NULL || session == NULL) {
        return SSH_ERROR;
    }

    used = event->ctx->polls_used;
    for(i = 0; i < used; i++) {
    	p = event->ctx->pollptrs[i];
    	if(p->session == session){
            /*
             * ssh_poll_ctx_remove() decrements
             * event->ctx->polls_used
             */
            ssh_poll_ctx_remove(event->ctx, p);
            p->session = NULL;
            ssh_poll_ctx_add(session->default_poll_ctx, p);
            rc = SSH_OK;
            /*
             * Restart the loop!
             * A session can initially have two pollhandlers.
             */
            used = event->ctx->polls_used;
            i = 0;

        }
    }
#ifdef WITH_SERVER
    iterator = ssh_list_get_iterator(event->sessions);
    while(iterator != NULL) {
        if((ssh_session)iterator->data == session) {
            ssh_list_remove(event->sessions, iterator);
            /* there should be only one instance of this session */
            break;
        }
        iterator = iterator->next;
    }
#endif

    return rc;
}

/** @brief Remove a connector from an event context
 * @param[in] event The ssh_event object.
 * @param[in] connector connector object to remove
 * @return SSH_OK on success
 * @return SSH_ERROR on failure
 */
int ssh_event_remove_connector(ssh_event event, ssh_connector connector){
    (void)event;
    return ssh_connector_remove_event(connector);
}

/**
 * @brief  Free an event context.
 *
 * @param  event        The ssh_event object to free.
 *                      Note: you have to manually remove sessions and socket
 *                      fds before freeing the event object.
 *
 */
void ssh_event_free(ssh_event event)
{
    size_t used, i;
    ssh_poll_handle p;

    if(event == NULL) {
        return;
    }

    if (event->ctx != NULL) {
        used = event->ctx->polls_used;
        for(i = 0; i < used; i++) {
            p = event->ctx->pollptrs[i];
            if (p->session != NULL) {
                ssh_poll_ctx_remove(event->ctx, p);
                ssh_poll_ctx_add(p->session->default_poll_ctx, p);
                p->session = NULL;
                used = 0;
            }
        }

        ssh_poll_ctx_free(event->ctx);
    }
#ifdef WITH_SERVER
    if(event->sessions != NULL) {
        ssh_list_free(event->sessions);
    }
#endif
    free(event);
}

/** @} */
