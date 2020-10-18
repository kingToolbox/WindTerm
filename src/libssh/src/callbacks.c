/*
 * callbacks.c - callback functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013  by Andreas Schneider <asn@cryptomilk.org>
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

#include "libssh/callbacks.h"
#include "libssh/session.h"
#include "libssh/misc.h"

#define is_callback_valid(session, cb) \
    (cb->size <= 0 || cb->size > 1024 * sizeof(void *))

/* LEGACY */
static void ssh_legacy_log_callback(int priority,
                                    const char *function,
                                    const char *buffer,
                                    void *userdata)
{
    ssh_session session = (ssh_session)userdata;
    ssh_log_callback log_fn = session->common.callbacks->log_function;
    void *log_data = session->common.callbacks->userdata;

    (void)function; /* unused */

    log_fn(session, priority, buffer, log_data);
}

int ssh_set_callbacks(ssh_session session, ssh_callbacks cb) {
  if (session == NULL || cb == NULL) {
    return SSH_ERROR;
  }

  if (is_callback_valid(session, cb)) {
      ssh_set_error(session,
                    SSH_FATAL,
                    "Invalid callback passed in (badly initialized)");
      return SSH_ERROR;
  };
  session->common.callbacks = cb;

  /* LEGACY */
  if (ssh_get_log_callback() == NULL && cb->log_function) {
      ssh_set_log_callback(ssh_legacy_log_callback);
      ssh_set_log_userdata(session);
  }

  return 0;
}

static int ssh_add_set_channel_callbacks(ssh_channel channel,
                                         ssh_channel_callbacks cb,
                                         int prepend)
{
    ssh_session session = NULL;
    int rc;

    if (channel == NULL || cb == NULL) {
      return SSH_ERROR;
    }
    session = channel->session;

    if (is_callback_valid(session, cb)) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Invalid callback passed in (badly initialized)");
        return SSH_ERROR;
    };
    if (channel->callbacks == NULL) {
        channel->callbacks = ssh_list_new();
        if (channel->callbacks == NULL){
            ssh_set_error_oom(session);
            return SSH_ERROR;
        }
    }
    if (prepend) {
        rc = ssh_list_prepend(channel->callbacks, cb);
    } else {
        rc = ssh_list_append(channel->callbacks, cb);
    }

    return rc;
}

int ssh_set_channel_callbacks(ssh_channel channel, ssh_channel_callbacks cb)
{
    return ssh_add_set_channel_callbacks(channel, cb, 1);
}

int ssh_add_channel_callbacks(ssh_channel channel, ssh_channel_callbacks cb)
{
    return ssh_add_set_channel_callbacks(channel, cb, 0);
}

int ssh_remove_channel_callbacks(ssh_channel channel, ssh_channel_callbacks cb)
{
    struct ssh_iterator *it;

    if (channel == NULL || channel->callbacks == NULL){
        return SSH_ERROR;
    }

    it = ssh_list_find(channel->callbacks, cb);
    if (it == NULL){
        return SSH_ERROR;
    }

    ssh_list_remove(channel->callbacks, it);

    return SSH_OK;
}


int ssh_set_server_callbacks(ssh_session session, ssh_server_callbacks cb){
	if (session == NULL || cb == NULL) {
		return SSH_ERROR;
	}

    if (is_callback_valid(session, cb)) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Invalid callback passed in (badly initialized)");
        return SSH_ERROR;
    };
	session->server_callbacks = cb;

	return 0;
}
