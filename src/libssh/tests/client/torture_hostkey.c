/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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
#include <errno.h>
#include <pwd.h>

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

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_hostkey_rsa(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char rsa[] = "ssh-rsa";

    int rc;

    if (ssh_fips_mode()) {
        skip();
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &rsa);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

static void torture_hostkey_ed25519(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char ed[] = "ssh-ed25519";

    int rc;

    if (ssh_fips_mode()) {
        skip();
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &ed);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

#ifdef HAVE_DSA
static void torture_hostkey_dss(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char rsa[] = "ssh-dss";

    int rc;

    if (ssh_fips_mode()) {
        skip();
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &rsa);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}
#endif /* HAVE_DSA */

#ifdef HAVE_ECC
static void torture_hostkey_ecdsa(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char ecdsa[] = "ecdsa-sha2-nistp521";

    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &ecdsa);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}
#endif

static void torture_hostkey_rsa_sha256(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char rsa[] = "rsa-sha2-256";

    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &rsa);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

static void torture_hostkey_rsa_sha512(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    char rsa[] = "rsa-sha2-512";

    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, &rsa);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    ssh_disconnect(session);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_hostkey_rsa, session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_hostkey_ed25519, session_setup,
                                        session_teardown),
#ifdef HAVE_ECC
        cmocka_unit_test_setup_teardown(torture_hostkey_ecdsa, session_setup,
                                        session_teardown),
#endif
#ifdef HAVE_DSA
        cmocka_unit_test_setup_teardown(torture_hostkey_dss, session_setup,
                                        session_teardown),
#endif
        /* the client is able to handle SHA2 extension (if negotiated) */
        cmocka_unit_test_setup_teardown(torture_hostkey_rsa_sha256,
                                        session_setup, session_teardown),
        cmocka_unit_test_setup_teardown(torture_hostkey_rsa_sha512,
                                        session_setup, session_teardown),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();
    return rc;
}
