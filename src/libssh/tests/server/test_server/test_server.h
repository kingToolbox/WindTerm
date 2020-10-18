/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

#include <stdbool.h>
#include <fcntl.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

struct server_state_st {
    /* Arguments */
    char *address;
    int  port;

    char *ecdsa_key;
    char *dsa_key;
    char *ed25519_key;
    char *rsa_key;
    char *host_key;

    int  verbosity;
    int  auth_methods;
    bool with_pcap;

    char *pcap_file;

    char *expected_username;
    char *expected_password;

    char *config_file;
    bool parse_global_config;

    /* State */
    int  max_tries;
    int  error;

    struct ssh_server_callbacks_struct *server_cb;
    struct ssh_channel_callbacks_struct *channel_cb;

    /* Callback to handle the session, should block until disconnected */
    void (*handle_session)(ssh_event event,
                           ssh_session session,
                           struct server_state_st *state);
};

/*TODO: Add documentation */
void free_server_state(struct server_state_st *state);

/*TODO: Add documentation */
int run_server(struct server_state_st *state);

/*TODO: Add documentation */
pid_t fork_run_server(struct server_state_st *state);
