/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2012 by Aris Adamantiadis
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
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#define BUFLEN 4096
static char buffer[BUFLEN];

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
    struct passwd *pwd;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_channel_read_error(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_channel channel;
    int rc;
    int fd;
    int i;

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_ssh_return_code(session, rc);

    rc = ssh_channel_request_exec(channel, "hexdump -C /dev/urandom");
    assert_ssh_return_code(session, rc);

    /* send crap and for server to send us a disconnect */
    fd = ssh_get_fd(session);
    assert_true(fd > 2);
    rc = write(fd, "AAAA", 4);
    assert_int_equal(rc, 4);

    for (i=0;i<20;++i){
        rc = ssh_channel_read(channel,buffer,sizeof(buffer),0);
        if (rc == SSH_ERROR)
            break;
    }
#if OPENSSH_VERSION_MAJOR == 6 && OPENSSH_VERSION_MINOR >= 7
    /* With openssh 6.7 this doesn't produce and error anymore */
    assert_ssh_return_code(session, rc);
#else
    assert_ssh_return_code_equal(session, rc, SSH_ERROR);
#endif

    ssh_channel_free(channel);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_channel_read_error,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);
    ssh_finalize();

    return rc;
}
