/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Andreas Schneider <asn@cryptomilk.org>
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

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

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

static void torture_request_env(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    ssh_channel c;
    char buffer[4096] = {0};
    int nbytes;
    int rc;
    int lang_found = 0;

    c = ssh_channel_new(session);
    assert_non_null(c);

    rc = ssh_channel_open_session(c);
    assert_ssh_return_code(session, rc);

    rc = ssh_channel_request_env(c, "LC_LIBSSH", "LIBSSH_EXPORTED_VARIABLE");
    assert_ssh_return_code(session, rc);

    rc = ssh_channel_request_exec(c, "echo $LC_LIBSSH");
    assert_ssh_return_code(session, rc);

    nbytes = ssh_channel_read(c, buffer, sizeof(buffer) - 1, 0);
    printf("nbytes=%d\n", nbytes);
    while (nbytes > 0) {
#if 1
        rc = fwrite(buffer, 1, nbytes, stdout);
        assert_int_equal(rc, nbytes);
#endif
        buffer[nbytes]='\0';
        if (strstr(buffer, "LIBSSH_EXPORTED_VARIABLE")) {
            lang_found = 1;
            break;
        }

        nbytes = ssh_channel_read(c, buffer, sizeof(buffer), 0);
    }
    assert_int_equal(lang_found, 1);

    ssh_channel_close(c);
}

int torture_run_tests(void) {
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_request_env,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}

