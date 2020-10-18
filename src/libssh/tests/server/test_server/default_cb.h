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

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#define SSHD_DEFAULT_USER "libssh"
#define SSHD_DEFAULT_PASSWORD "libssh"
#define SSHD_DEFAULT_PORT 2222
#define SSHD_DEFAULT_ADDRESS "127.0.0.1"
#define SSHD_DEFAULT_PCAP_FILE "debug.server.pcap"

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define BUF_SIZE 1048576
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)
#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

#ifdef HAVE_PTY_H
#include <pty.h>
#endif

/* A userdata struct for channel. */
struct channel_data_st {
    /* pid of the child process the channel will spawn. */
    pid_t pid;
    /* For PTY allocation */
    socket_t pty_master;
    socket_t pty_slave;
    /* For communication with the child process. */
    socket_t child_stdin;
    socket_t child_stdout;
    /* Only used for subsystem and exec requests. */
    socket_t child_stderr;
    /* Event which is used to poll the above descriptors. */
    ssh_event event;
    /* Terminal size struct. */
    struct winsize *winsize;
    /* This pointer will hold the server state for default callbacks */
    void *server_state;
    /* This pointer is useful to set data for custom callbacks */
    void *extra_data;
};

/* A userdata struct for session. */
struct session_data_st {
    /* Pointer to the channel the session will allocate. */
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    const char *username;
    const char *password;
#ifdef WITH_PCAP
    ssh_pcap_file pcap;
#endif
    /* This pointer will hold the server state for default callbacks */
    void *server_state;
    /* This pointer is useful to set data for custom callbacks */
    void *extra_data;
};

int auth_password_cb(ssh_session session, const char *user,
        const char *password, void *userdata);

#if WITH_GSSAPI
int auth_gssapi_mic_cb(ssh_session session, const char *user,
        const char *principal, void *userdata);
#endif

int channel_data_cb(ssh_session session, ssh_channel channel,
        void *data, uint32_t len, int is_stderr, void *userdata);

void channel_eof_cb(ssh_session session, ssh_channel channel,
        void *userdata);

void channel_close_cb(ssh_session session, ssh_channel channel,
        void *userdata);

void channel_signal_cb (ssh_session session,
        ssh_channel channel,
        const char *signal,
        void *userdata);

void channel_exit_status_cb (ssh_session session,
        ssh_channel channel,
        int exit_status,
        void *userdata);

void channel_exit_signal_cb(ssh_session session,
        ssh_channel channel,
        const char *signal,
        int core,
        const char *errmsg,
        const char *lang,
        void *userdata);

int channel_pty_request_cb(ssh_session session, ssh_channel channel,
        const char *term, int cols, int rows, int py, int px, void *userdata);

int channel_pty_resize_cb(ssh_session session, ssh_channel channel,
        int cols, int rows, int py, int px, void *userdata);

int channel_shell_request_cb(ssh_session session, ssh_channel channel,
        void *userdata);

void channel_auth_agent_req_callback(ssh_session session,
        ssh_channel channel, void *userdata);

void channel_x11_req_callback(ssh_session session,
        ssh_channel channel,
        int single_connection,
        const char *auth_protocol,
        const char *auth_cookie,
        uint32_t screen_number,
        void *userdata);

int channel_exec_request_cb(ssh_session session,
        ssh_channel channel,
        const char *command,
        void *userdata);

int channel_env_request_cb(ssh_session session,
        ssh_channel channel, const char *env_name, const char *env_value,
        void *userdata);

int channel_subsystem_request_cb(ssh_session session,
        ssh_channel channel, const char *subsystem,
        void *userdata);

int channel_write_wontblock_cb(ssh_session session,
        ssh_channel channel,
        size_t bytes,
        void *userdata);

ssh_channel channel_new_session_cb(ssh_session session, void *userdata);

/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_server_callbacks_struct *get_default_server_cb(void);

/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_channel_callbacks_struct *get_default_channel_cb(void);

void default_handle_session_cb(ssh_event event, ssh_session session,
        struct server_state_st *state);
