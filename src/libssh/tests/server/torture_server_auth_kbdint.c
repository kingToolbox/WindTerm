/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
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

#define LIBSSH_STATIC

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>

#include "torture.h"
#include "torture_key.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"

#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "test_server.h"
#include "default_cb.h"

#define TORTURE_KNOWN_HOSTS_FILE "libssh_torture_knownhosts"

enum {
    SUCCESS,
    MORE,
    FAILED
};

struct test_server_st {
    struct torture_state *state;
    struct server_state_st *ss;
};

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

    /* Do not free the pcap data context here since its ownership was
     * transfered to the session object, which will take care of its cleanup.
     * Morover it is still in use so we can very simply crash by freeing
     * it here.
     */
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

static int authenticate_kbdint(ssh_session session,
                               ssh_message message,
                               void *userdata)
{
    int rc = 0;
    int count;
    int *step = NULL;
    size_t expected_len;

    const char instruction[] = "Type the requested data";
    const char name[] = "Keyboard-Interactive Authentication\n";
    char initial_echo[] = {1, 0};
    char retype_echo[] = {0};
    const char *initial_prompt[2];
    const char *retype_prompt[1];
    int cmp;

    const char *answer;

    struct session_data_st *sdata = (struct session_data_st *)userdata;

    initial_prompt[0] = "username: ";
    initial_prompt[1] = "password: ";

    /* Prompt for aditional prompts */
    retype_prompt[0] = "retype password: ";

    if ((session == NULL) || (message == NULL) || (sdata == NULL)) {
        fprintf(stderr, "Null argument provided\n");
        goto failed;
    }

    if (sdata->extra_data == NULL) {
        goto failed;
    }

    step = (int *)sdata->extra_data;

    switch (*step) {
    case 0:
        ssh_message_auth_interactive_request(message, name, instruction, 2,
                initial_prompt, initial_echo);
        rc = MORE;
        goto end;
    case 1:
        count = ssh_userauth_kbdint_getnanswers(session);
        if (count != 2) {
            goto failed;
        }

        if ((sdata->username == NULL) || (sdata->password == NULL)) {
            goto failed;
        }

        /* Get and compare username */
        expected_len = strlen(sdata->username);
        if (expected_len <= 0) {
            goto failed;
        }

        answer = ssh_userauth_kbdint_getanswer(session, 0);
        if (answer == NULL) {
            goto failed;
        }

        cmp = strncmp(answer, sdata->username, expected_len);
        if (cmp != 0) {
            goto failed;
        }

        /* Get and compare password */
        expected_len = strlen(sdata->password);
        if (expected_len <= 0) {
            goto failed;
        }

        answer = ssh_userauth_kbdint_getanswer(session, 1);
        if (answer == NULL) {
            goto failed;
        }

        cmp = strncmp(answer, sdata->password, expected_len);
        if (cmp != 0) {
            goto failed;
        }

        /* Username and password matched. Ask for a retype. */
        ssh_message_auth_interactive_request(message,
                                             name,
                                             instruction,
                                             1,
                                             retype_prompt,
                                             retype_echo);

        rc = MORE;
        goto end;
    case 2:
        /* Get and compare password */
        expected_len = strlen(sdata->password);
        if (expected_len <= 0) {
            goto failed;
        }

        answer = ssh_userauth_kbdint_getanswer(session, 0);
        if (answer == NULL) {
            goto failed;
        }

        cmp = strncmp(answer, sdata->password, expected_len);
        if (cmp != 0) {
            goto failed;
        }

        /* Password was correct, authenticated */
        rc = SUCCESS;
        goto end;
    default:
        goto failed;
    }

failed:
    if (step != NULL) {
        *step = 0;
    }
    return FAILED;

end:
    if (step != NULL) {
        (*step)++;
    }
    return rc;
}

static int authenticate_callback(ssh_session session,
                                 ssh_message message,
                                 void *userdata)
{
    struct session_data_st *sdata = (struct session_data_st *)userdata;
    int rc;

    if (sdata == NULL) {
        fprintf(stderr, "Null userdata\n");
        goto denied;
    }

    if (sdata->extra_data == NULL) {
        sdata->extra_data = (void *)calloc(1, sizeof(int));
    }

    switch (ssh_message_type(message)) {
    case SSH_REQUEST_AUTH:
        switch (ssh_message_subtype(message)) {
        case SSH_AUTH_METHOD_INTERACTIVE:
            rc = authenticate_kbdint(session, message, (void *)sdata);
            if (rc == SUCCESS) {
                goto accept;
            }
            else if (rc == MORE) {
                goto more;
            }
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_INTERACTIVE);
            goto denied;
        default:
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_INTERACTIVE);
            goto denied;
        }
    default:
        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_INTERACTIVE);
        goto denied;
    }

    ssh_message_free(message);

accept:
    if (sdata) {
        if (sdata->extra_data) {
            free(sdata->extra_data);
            sdata->extra_data = NULL;
        }
    }
    ssh_message_auth_reply_success (message, 0);
more:
    return 0;
denied:
    if (sdata) {
        if (sdata->extra_data) {
            free(sdata->extra_data);
            sdata->extra_data = NULL;
        }
    }
    return 1;
}

static void handle_kbdint_session_cb(ssh_event event,
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
        .username = TORTURE_SSH_USER_BOB,
        .password = TORTURE_SSH_USER_BOB_PASSWORD
    };

    struct ssh_channel_callbacks_struct *channel_cb = NULL;
    struct ssh_server_callbacks_struct *server_cb = NULL;

    if (state == NULL) {
        fprintf(stderr, "NULL server state provided\n");
        goto end;
    }

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

#ifdef WITH_PCAP
    set_pcap(&sdata, session, state->pcap_file);
#endif

    rc = ssh_handle_key_exchange(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        goto end;
    }

    /* Set the supported authentication methods */
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_INTERACTIVE);

    ssh_set_message_callback(session, authenticate_callback, &sdata);

    rc = ssh_event_add_session(event, session);
    if (rc != 0) {
        fprintf(stderr, "Error adding session to event\n");
        goto end;
    }

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= state->max_tries || n >= 100) {
            goto end;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "do_poll error: %s\n", ssh_get_error(session));
            goto end;
        }
        n++;
    }

    channel_cb = get_default_channel_cb();
    if (channel_cb == NULL) {
        goto end;
    }

    channel_cb->userdata = &cdata;

    ssh_callbacks_init(channel_cb);
    rc = ssh_set_channel_callbacks(sdata.channel, channel_cb);
    if (rc != 0) {
        goto end;
    }

    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        rc = ssh_event_dopoll(event, -1);
        if (rc == SSH_ERROR) {
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

static int setup_kbdint_server(void **state)
{
    struct torture_state *s;
    struct server_state_st *ss;
    struct test_server_st *tss;

    char rsa_hostkey[1024] = {0};

    char sshd_path[1024];

    int rc;

    char pid_str[1024];

    pid_t pid;

    assert_non_null(state);

    tss = (struct test_server_st*)calloc(1, sizeof(struct test_server_st));
    assert_non_null(tss);

    torture_setup_socket_dir((void **)&s);
    assert_non_null(s->socket_dir);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);
    setenv("PAM_WRAPPER", "1", 1);

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey,
                       torture_get_openssh_testkey(SSH_KEYTYPE_RSA, 0));

    /* Create the server state */
    ss = (struct server_state_st *)calloc(1, sizeof(struct server_state_st));
    assert_non_null(ss);

    ss->address = strdup("127.0.0.10");
    assert_non_null(ss->address);

    ss->port = 22;

    ss->host_key = strdup(rsa_hostkey);
    assert_non_null(rsa_hostkey);

    ss->verbosity = torture_libssh_verbosity();

#ifdef WITH_PCAP
    ss->with_pcap = 1;
    ss->pcap_file = strdup(s->pcap_file);
    assert_non_null(ss->pcap_file);
#endif

    ss->max_tries = 3;
    ss->error = 0;

    /* Set the session handling function */
    ss->handle_session = handle_kbdint_session_cb;
    assert_non_null(ss->handle_session);

    /* Start the server */
    pid = fork_run_server(ss);
    if (pid < 0) {
        fail();
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    torture_write_file(s->srv_pidfile, (const char *)pid_str);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);
    unsetenv("PAM_WRAPPER");

    /* Wait 200ms */
    usleep(200 * 1000);

    tss->state = s;
    tss->ss = ss;

    *state = tss;

    return 0;
}

static int teardown_kbdint_server(void **state)
{
    struct torture_state *s;
    struct server_state_st *ss;
    struct test_server_st *tss;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ss = tss->ss;
    assert_non_null(ss);

    /* This function can be reused */
    torture_teardown_sshd_server((void **)&s);

    free_server_state(tss->ss);
    SAFE_FREE(tss->ss);
    SAFE_FREE(tss);

    return 0;
}

static int session_setup(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool b = false;
    int rc;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);
    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_server_auth_kbdint(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    ssh_session session;
    int rc;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    rc = ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_BOB);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    rc = ssh_userauth_none(session,NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_INTERACTIVE);

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_INFO);
    assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 2);

    /* Reply the first 2 prompts using the username and password */
    rc = ssh_userauth_kbdint_setanswer(session, 0,
            TORTURE_SSH_USER_BOB);
    assert_false(rc < 0);

    rc = ssh_userauth_kbdint_setanswer(session, 1,
            TORTURE_SSH_USER_BOB_PASSWORD);
    assert_false(rc < 0);

    /* Resend the password */
    rc = ssh_userauth_kbdint(session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_INFO);
    assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 1);

    rc = ssh_userauth_kbdint_setanswer(session, 0,
            TORTURE_SSH_USER_BOB_PASSWORD);
    assert_false(rc < 0);

    rc = ssh_userauth_kbdint(session, NULL, NULL);

    /* Sometimes, SSH server send an empty query at the end of exchange */
    if(rc == SSH_AUTH_INFO) {
        assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 0);
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }

    assert_int_equal(rc, SSH_AUTH_SUCCESS);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_server_auth_kbdint,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
            setup_kbdint_server,
            teardown_kbdint_server);

    ssh_finalize();

    return rc;
}
