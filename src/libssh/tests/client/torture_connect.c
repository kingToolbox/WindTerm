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

#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/libssh.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <pwd.h>

/* Should work until Apnic decides to assign it :) */
#define BLACKHOLE "1.1.1.1"

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state) {
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, BLACKHOLE);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_connect_nonblocking(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);
    ssh_set_blocking(session,0);

    do {
        rc = ssh_connect(session);
        assert_ssh_return_code_not_equal(session, rc, SSH_ERROR);
    } while(rc == SSH_AGAIN);

    assert_ssh_return_code(session, rc);
}

#if 0 /* This does not work with socket_wrapper */
static void torture_connect_timeout(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    struct timeval before, after;
    int rc;
    long timeout = 2;
    time_t sec;
    suseconds_t usec;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, BLACKHOLE);
    assert_true(rc == SSH_OK);
    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    assert_true(rc == SSH_OK);

    rc = gettimeofday(&before, NULL);
    assert_true(rc == 0);
    rc = ssh_connect(session);
    assert_true(rc == SSH_ERROR);
    rc = gettimeofday(&after, NULL);
    assert_true(rc == 0);
    sec = after.tv_sec - before.tv_sec;
    usec = after.tv_usec - before.tv_usec;
    /* Borrow a second for the missing usecs, but don't bother calculating */
    if (usec < 0)
      sec--;
    assert_in_range(sec, 1, 3);
}
#endif

static void torture_connect_double(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;

    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

static void torture_connect_failure(void **state) {
    /*
     * The intent of this test is to check that a fresh
     * ssh_new/ssh_disconnect/ssh_free sequence doesn't crash/leak
     * and the behavior of a double ssh_disconnect
     */
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;

    ssh_disconnect(session);
}

static void torture_connect_socket(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;

    int rc;
    int sock_fd = 0;
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(22),
        .sin_addr.s_addr = inet_addr(TORTURE_SSH_SERVER),
    };

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(sock_fd > 2);

    rc = connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    assert_return_code(rc, errno);

    ssh_options_set(session, SSH_OPTIONS_FD, &sock_fd);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

static void torture_connect_uninitialized(UNUSED_PARAM(void **state))
{
    int rc;
    ssh_session session;
    struct passwd *pwd;

    /* Make sure the library is unitialized */
    while (is_ssh_initialized()) {
        rc = ssh_finalize();
        assert_return_code(rc, errno);
    }

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(session, rc);

    /* Expect error from ssh_connect */
    rc = ssh_connect(session);
    assert_false(rc == SSH_OK);
    assert_string_equal(ssh_get_error(session), "Library not initialized.");

    ssh_free(session);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_connect_nonblocking, session_setup, session_teardown),
        cmocka_unit_test_setup_teardown(torture_connect_double, session_setup, session_teardown),
        cmocka_unit_test_setup_teardown(torture_connect_failure, session_setup, session_teardown),
#if 0
        cmocka_unit_test_setup_teardown(torture_connect_timeout, session_setup, session_teardown),
#endif
        cmocka_unit_test_setup_teardown(torture_connect_socket, session_setup, session_teardown),
        cmocka_unit_test(torture_connect_uninitialized),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}
