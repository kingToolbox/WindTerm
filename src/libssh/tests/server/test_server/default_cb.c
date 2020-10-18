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
#include "test_server.h"
#include "default_cb.h"

#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <libssh/priv.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

int auth_pubkey_cb(UNUSED_PARAM(ssh_session session),
                   const char *user,
                   UNUSED_PARAM(struct ssh_key_struct *pubkey),
                   char signature_state,
                   void *userdata)
{
    struct session_data_st *sdata;

    sdata = (struct session_data_st *)userdata;
    if (sdata == NULL) {
        fprintf(stderr, "Error: NULL userdata\n");
        goto null_userdata;
    }

    printf("Public key authentication of user %s\n", user);

    switch(signature_state) {
    case SSH_PUBLICKEY_STATE_NONE:
    case SSH_PUBLICKEY_STATE_VALID:
        break;
    default:
        goto denied;
    }

    /* TODO */
    /* Check wheter the user and public key are in authorized keys list */

    /* Authenticated */
    printf("Authenticated\n");
    sdata->authenticated = 1;
    sdata->auth_attempts = 0;
    return SSH_AUTH_SUCCESS;

denied:
    sdata->auth_attempts++;
null_userdata:
    return SSH_AUTH_DENIED;
}

/* TODO implement proper pam authentication cb */
int auth_password_cb(UNUSED_PARAM(ssh_session session),
                     const char *user,
                     const char *password,
                     void *userdata)
{
    bool known_user = false;
    bool valid_password = false;

    struct session_data_st *sdata;

    sdata = (struct session_data_st *)userdata;

    if (sdata == NULL) {
        fprintf(stderr, "Error: NULL userdata\n");
        goto null_userdata;
    }

    if (sdata->username == NULL) {
        fprintf(stderr, "Error: expected username not set\n");
        goto denied;
    }

    if (sdata->password == NULL) {
        fprintf(stderr, "Error: expected password not set\n");
        goto denied;
    }

    printf("Password authentication of user %s\n", user);

    known_user = !(strcmp(user, sdata->username));
    valid_password = !(strcmp(password, sdata->password));

    if (known_user && valid_password) {
        sdata->authenticated = 1;
        sdata->auth_attempts = 0;
        printf("Authenticated\n");
        return SSH_AUTH_SUCCESS;
    }

denied:
    sdata->auth_attempts++;
null_userdata:
    return SSH_AUTH_DENIED;
}

#if WITH_GSSAPI
int auth_gssapi_mic_cb(ssh_session session,
                       UNUSED_PARAM(const char *user),
                       UNUSED_PARAM(const char *principal),
                       void *userdata)
{
    ssh_gssapi_creds creds;
    struct session_data_st *sdata;

    sdata = (struct session_data_st *)userdata;

    if (sdata == NULL) {
        fprintf(stderr, "Error: NULL userdata\n");
        goto null_userdata;
    }

    printf("GSSAPI authentication\n");

    creds = ssh_gssapi_get_creds(session);
    if (creds != NULL) {
        printf("Received some gssapi credentials\n");
    } else {
        printf("Not received any forwardable creds\n");
        goto denied;
    }

    printf("Authenticated\n");

    sdata->authenticated = 1;
    sdata->auth_attempts = 0;

    return SSH_AUTH_SUCCESS;

denied:
    sdata->auth_attempts++;
null_userdata:
    return SSH_AUTH_DENIED;
}
#endif

int channel_data_cb(UNUSED_PARAM(ssh_session session),
                    UNUSED_PARAM(ssh_channel channel),
                    void *data,
                    uint32_t len,
                    UNUSED_PARAM(int is_stderr),
                    void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
        rc = SSH_OK;
        goto end;
    }

    rc = write(cdata->child_stdin, (char *) data, len);

end:
    return rc;
}

void channel_eof_cb(UNUSED_PARAM(ssh_session session),
                    UNUSED_PARAM(ssh_channel channel),
                    void *userdata)
{
    struct channel_data_st *cdata;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto end;
    }

end:
    return;
}

void channel_close_cb(UNUSED_PARAM(ssh_session session),
                      UNUSED_PARAM(ssh_channel channel),
                      void *userdata)
{
    struct channel_data_st *cdata;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto end;
    }

end:
    return;
}

void channel_signal_cb(UNUSED_PARAM(ssh_session session),
                       UNUSED_PARAM(ssh_channel channel),
                       UNUSED_PARAM(const char *signal),
                       void *userdata)
{
    struct channel_data_st *cdata;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto end;
    }

end:
    return;
}

void channel_exit_status_cb(UNUSED_PARAM(ssh_session session),
                            UNUSED_PARAM(ssh_channel channel),
                            UNUSED_PARAM(int exit_status),
                            void *userdata)
{
    struct channel_data_st *cdata;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto end;
    }

end:
    return;
}

void channel_exit_signal_cb(UNUSED_PARAM(ssh_session session),
                            UNUSED_PARAM(ssh_channel channel),
                            UNUSED_PARAM(const char *signal),
                            UNUSED_PARAM(int core),
                            UNUSED_PARAM(const char *errmsg),
                            UNUSED_PARAM(const char *lang),
                            void *userdata)
{
    struct channel_data_st *cdata;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto end;
    }

end:
    return;
}

int channel_pty_request_cb(UNUSED_PARAM(ssh_session session),
                           UNUSED_PARAM(ssh_channel channel),
                           UNUSED_PARAM(const char *term),
                           int cols,
                           int rows,
                           int py,
                           int px,
                           void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    rc = openpty(&cdata->pty_master,
                 &cdata->pty_slave,
                 NULL,
                 NULL,
                 cdata->winsize);
    if (rc != 0) {
        fprintf(stderr, "Failed to open pty\n");
        rc = SSH_ERROR;
        goto end;
    }

    rc = SSH_OK;

end:
    return rc;
}

int channel_pty_resize_cb(ssh_session session,
                          ssh_channel channel,
                          int cols,
                          int rows,
                          int py,
                          int px,
                          void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    (void) session;
    (void) channel;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (cdata->pty_master != -1) {
        rc = ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
        goto end;
    }

    rc = SSH_ERROR;

end:
    return rc;
}

void channel_auth_agent_req_callback(UNUSED_PARAM(ssh_session session),
                                     UNUSED_PARAM(ssh_channel channel),
                                     UNUSED_PARAM(void *userdata))
{
    /* TODO */
}

void channel_x11_req_callback(UNUSED_PARAM(ssh_session session),
                              UNUSED_PARAM(ssh_channel channel),
                              UNUSED_PARAM(int single_connection),
                              UNUSED_PARAM(const char *auth_protocol),
                              UNUSED_PARAM(const char *auth_cookie),
                              UNUSED_PARAM(uint32_t screen_number),
                              UNUSED_PARAM(void *userdata))
{
    /* TODO */
}

static int exec_pty(const char *mode,
                    const char *command,
                    struct channel_data_st *cdata)
{
    int rc;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    cdata->pid = fork();
    switch(cdata->pid) {
    case -1:
        close(cdata->pty_master);
        close(cdata->pty_slave);
        fprintf(stderr, "Failed to fork\n");
        rc = SSH_ERROR;
        goto end;
    case 0:
        close(cdata->pty_master);
        if (login_tty(cdata->pty_slave) != 0) {
            exit(1);
        }
        execl("/bin/sh", "sh", mode, command, NULL);
        exit(0);
    default:
        close(cdata->pty_slave);
        /* pty fd is bi-directional */
        cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }

    rc = SSH_OK;

end:
    return rc;
}

static int exec_nopty(const char *command, struct channel_data_st *cdata)
{
    int in[2], out[2], err[2];

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        goto stdin_failed;
    }

    /* Do the plumbing to be able to talk with the child process. */
    if (pipe(in) != 0) {
        goto stdin_failed;
    }
    if (pipe(out) != 0) {
        goto stdout_failed;
    }
    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    switch(cdata->pid = fork()) {
        case -1:
            goto fork_failed;
        case 0:
            /* Finish the plumbing in the child process. */
            close(in[1]);
            close(out[0]);
            close(err[0]);
            dup2(in[0], STDIN_FILENO);
            dup2(out[1], STDOUT_FILENO);
            dup2(err[1], STDERR_FILENO);
            close(in[0]);
            close(out[1]);
            close(err[1]);
            /* exec the requested command. */
            execl("/bin/sh", "sh", "-c", command, NULL);
            exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

int channel_shell_request_cb(UNUSED_PARAM(ssh_session session),
                             UNUSED_PARAM(ssh_channel channel),
                             void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    if(cdata->pid > 0) {
        rc = SSH_ERROR;
        goto end;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        rc = exec_pty("-l", NULL, cdata);
        goto end;
    }

    /* Client requested a shell without a pty, let's pretend we allow that */
    rc = SSH_OK;

end:
    return rc;
}

int channel_exec_request_cb(UNUSED_PARAM(ssh_session session),
                            UNUSED_PARAM(ssh_channel channel),
                            const char *command,
                            void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    if(cdata->pid > 0) {
        rc = SSH_ERROR;
        goto end;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        rc = exec_pty("-c", command, cdata);
        goto end;
    }

    rc = exec_nopty(command, cdata);

end:
    return rc;
}

int channel_env_request_cb(UNUSED_PARAM(ssh_session session),
                           UNUSED_PARAM(ssh_channel channel),
                           UNUSED_PARAM(const char *env_name),
                           UNUSED_PARAM(const char *env_value),
                           void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    rc = SSH_OK;

end:
    return rc;
}

int channel_subsystem_request_cb(ssh_session session,
                                 ssh_channel channel,
                                 const char *subsystem,
                                 void *userdata)
{
    struct channel_data_st *cdata;
    int rc;

    cdata = (struct channel_data_st *)userdata;

    if (cdata == NULL) {
        fprintf(stderr, "NULL userdata\n");
        rc = SSH_ERROR;
        goto end;
    }

    rc = strcmp(subsystem, "sftp");
    if (rc == 0) {
        rc = channel_exec_request_cb(session,
                                     channel,
                                     SFTP_SERVER_PATH,
                                     userdata);
        goto end;
    }

    /* TODO add other subsystems */

    rc = SSH_ERROR;

end:
    return rc;
}

int channel_write_wontblock_cb(UNUSED_PARAM(ssh_session session),
                               UNUSED_PARAM(ssh_channel channel),
                               UNUSED_PARAM(size_t bytes),
                               UNUSED_PARAM(void *userdata))
{
    /* TODO */

    return 0;
}

ssh_channel channel_new_session_cb(ssh_session session, void *userdata)
{
    struct session_data_st *sdata = NULL;
    ssh_channel chan = NULL;

    sdata = (struct session_data_st *)userdata;

    if (sdata == NULL) {
        fprintf(stderr, "NULL userdata");
        goto end;
    }

    chan = ssh_channel_new(session);
    if (chan == NULL) {
        fprintf(stderr, "Error creating channel: %s\n",
                ssh_get_error(session));
        goto end;
    }

    sdata->channel = chan;

end:
    return chan;
}

#ifdef WITH_PCAP
static void set_pcap(struct session_data_st *sdata,
                     ssh_session session,
                     char *pcap_file)
{
    int rc = 0;

    if (sdata == NULL) {
        return;
    }

    if (pcap_file == NULL) {
        return;
    }

    sdata->pcap = ssh_pcap_file_new();
    if (sdata->pcap == NULL) {
        return;
    }

    rc = ssh_pcap_file_open(sdata->pcap, pcap_file);
    if (rc == SSH_ERROR) {
        fprintf(stderr, "Error opening pcap file\n");
        ssh_pcap_file_free(sdata->pcap);
        sdata->pcap = NULL;
        return;
    }
    ssh_set_pcap_file(session, sdata->pcap);
}

static void cleanup_pcap(struct session_data_st *sdata)
{
    if (sdata == NULL) {
        return;
    }

    if (sdata->pcap == NULL) {
        return;
    }

    ssh_pcap_file_free(sdata->pcap);
    sdata->pcap = NULL;
}
#endif

static int process_stdout(socket_t fd, int revents, void *userdata)
{
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write(channel, buf, n);
        }
    }

    return n;
}

static int process_stderr(socket_t fd, int revents, void *userdata)
{
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0) {
            ssh_channel_write_stderr(channel, buf, n);
        }
    }

    return n;
}

/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_server_callbacks_struct *get_default_server_cb(void)
{

    struct ssh_server_callbacks_struct *cb;

    cb = (struct ssh_server_callbacks_struct *)calloc(1,
            sizeof(struct ssh_server_callbacks_struct));

    if (cb == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto end;
    }

    cb->auth_password_function = auth_password_cb;
    cb->auth_pubkey_function = auth_pubkey_cb;
    cb->channel_open_request_session_function = channel_new_session_cb;
#if WITH_GSSAPI
    cb->auth_gssapi_mic_function = auth_gssapi_mic_cb;
#endif

end:
    return cb;
}

/* The caller is responsible to set the userdata to be provided to the callback
 * The caller is responsible to free the allocated structure
 * */
struct ssh_channel_callbacks_struct *get_default_channel_cb(void)
{
    struct ssh_channel_callbacks_struct *cb;

    cb = (struct ssh_channel_callbacks_struct *)calloc(1,
            sizeof(struct ssh_channel_callbacks_struct));
    if (cb == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto end;
    }

    cb->channel_pty_request_function = channel_pty_request_cb;
    cb->channel_pty_window_change_function = channel_pty_resize_cb;
    cb->channel_shell_request_function = channel_shell_request_cb;
    cb->channel_env_request_function = channel_env_request_cb;
    cb->channel_subsystem_request_function = channel_subsystem_request_cb;
    cb->channel_exec_request_function = channel_exec_request_cb;
    cb->channel_data_function = channel_data_cb;

end:
    return cb;
};

void default_handle_session_cb(ssh_event event,
                               ssh_session session,
                               struct server_state_st *state)
{
    int n;
    int rc = 0;

    /* Structure for storing the pty size. */
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    /* Our struct holding information about the channel. */
    struct channel_data_st cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize
    };

    /* Our struct holding information about the session. */
    struct session_data_st sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
        .username = SSHD_DEFAULT_USER,
        .password = SSHD_DEFAULT_PASSWORD
    };

    struct ssh_channel_callbacks_struct *channel_cb = NULL;
    struct ssh_server_callbacks_struct *server_cb = NULL;

    if (state == NULL) {
        fprintf(stderr, "NULL server state provided\n");
        goto end;
    }

    /* If callbacks were provided use them. Otherwise, use default callbacks */
    if (state->server_cb != NULL) {
        /* This is a macro, it does not return a value */
        ssh_callbacks_init(state->server_cb);

        rc = ssh_set_server_callbacks(session, state->server_cb);
        if (rc) {
            goto end;
        }
    } else {
        server_cb = get_default_server_cb();
        if (server_cb == NULL) {
            goto end;
        }

        server_cb->userdata = &sdata;

        /* This is a macro, it does not return a value */
        ssh_callbacks_init(server_cb);

        rc = ssh_set_server_callbacks(session, server_cb);
        if (rc) {
            goto end;
        }
    }

    sdata.server_state = (void *)state;
    cdata.server_state = (void *)state;

#ifdef WITH_PCAP
    set_pcap(&sdata, session, state->pcap_file);
#endif

    if (state->expected_username != NULL) {
        sdata.username = state->expected_username;
    }

    if (state->expected_password != NULL) {
        sdata.password = state->expected_password;
    }

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        return;
    }

    /* Set the supported authentication methods */
    if (state->auth_methods) {
        ssh_set_auth_methods(session, state->auth_methods);
    } else {
        ssh_set_auth_methods(session,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_PUBLICKEY);
    }

    ssh_event_add_session(event, session);

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= state->max_tries || n >= 100) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "do_poll error: %s\n", ssh_get_error(session));
            return;
        }
        n++;
    }

    /* TODO check return values */
    if (state->channel_cb != NULL) {
        ssh_callbacks_init(state->channel_cb);

        rc = ssh_set_channel_callbacks(sdata.channel, state->channel_cb);
        if (rc) {
            goto end;
        }
    } else {
        channel_cb = get_default_channel_cb();
        if (channel_cb == NULL) {
            goto end;
        }

        channel_cb->userdata = &cdata;

        ssh_callbacks_init(channel_cb);
        rc = ssh_set_channel_callbacks(sdata.channel, channel_cb);
        if (rc) {
            goto end;
        }
    }

    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
          ssh_channel_close(sdata.channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (cdata.event != NULL || cdata.pid == 0) {
            continue;
        }
        /* Executed only once, once the child process starts. */
        cdata.event = event;
        /* If stdout valid, add stdout to be monitored by the poll event. */
        if (cdata.child_stdout != -1) {
            if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN, process_stdout,
                                 sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stdout to poll context\n");
                ssh_channel_close(sdata.channel);
            }
        }

        /* If stderr valid, add stderr to be monitored by the poll event. */
        if (cdata.child_stderr != -1){
            if (ssh_event_add_fd(event, cdata.child_stderr, POLLIN, process_stderr,
                                 sdata.channel) != SSH_OK) {
                fprintf(stderr, "Failed to register stderr to poll context\n");
                ssh_channel_close(sdata.channel);
            }
        }
    } while(ssh_channel_is_open(sdata.channel) &&
            (cdata.pid == 0 || waitpid(cdata.pid, &rc, WNOHANG) == 0));

    close(cdata.pty_master);
    close(cdata.child_stdin);
    close(cdata.child_stdout);
    close(cdata.child_stderr);

    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */
    ssh_event_remove_fd(event, cdata.child_stdout);
    ssh_event_remove_fd(event, cdata.child_stderr);

    /* If the child process exited. */
    if (kill(cdata.pid, 0) < 0 && WIFEXITED(rc)) {
        rc = WEXITSTATUS(rc);
        ssh_channel_request_send_exit_status(sdata.channel, rc);
    /* If client terminated the channel or the process did not exit nicely,
     * but only if something has been forked. */
    } else if (cdata.pid > 0) {
        kill(cdata.pid, SIGKILL);
    }

    ssh_channel_send_eof(sdata.channel);
    ssh_channel_close(sdata.channel);

    /* Wait up to 5 seconds for the client to terminate the session. */
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) {
        ssh_event_dopoll(event, 100);
    }

end:
#ifdef WITH_PCAP
    cleanup_pcap(&sdata);
#endif
    if (channel_cb != NULL) {
        free(channel_cb);
    }
    if (server_cb != NULL) {
        free(server_cb);
    }
    return;
}
