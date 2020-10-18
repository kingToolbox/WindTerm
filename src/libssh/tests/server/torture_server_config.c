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
#include "libssh/token.h"

#include "test_server.h"
#include "default_cb.h"

const char template[] = "temp_dir_XXXXXX";

struct test_server_st {
    struct torture_state *state;
    struct server_state_st *ss;
    char *cwd;
    char *temp_dir;
    char ed25519_hostkey[1024];
    char rsa_hostkey[1024];
    char ecdsa_521_hostkey[1024];
    char ecdsa_384_hostkey[1024];
    char ecdsa_256_hostkey[1024];
#ifdef HAVE_DSA
    char dsa_hostkey[1024];
#endif /* HAVE_DSA */
};

static int setup_files(void **state)
{
    struct test_server_st *tss;
    struct torture_state *s;
    char sshd_path[1024];

    int rc;

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

    snprintf(tss->rsa_hostkey,
             sizeof(tss->rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(tss->rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0));

    snprintf(tss->ecdsa_521_hostkey,
             sizeof(tss->ecdsa_521_hostkey),
             "%s/sshd/ssh_host_ecdsa_521_key",
             s->socket_dir);
    torture_write_file(tss->ecdsa_521_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0));

    snprintf(tss->ecdsa_384_hostkey,
             sizeof(tss->ecdsa_384_hostkey),
             "%s/sshd/ssh_host_ecdsa_384_key",
             s->socket_dir);
    torture_write_file(tss->ecdsa_384_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA_P384, 0));

    snprintf(tss->ecdsa_256_hostkey,
             sizeof(tss->ecdsa_256_hostkey),
             "%s/sshd/ssh_host_ecdsa_256_key",
             s->socket_dir);
    torture_write_file(tss->ecdsa_256_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA_P256, 0));

    if (!ssh_fips_mode()) {
        snprintf(tss->ed25519_hostkey,
                 sizeof(tss->ed25519_hostkey),
                 "%s/sshd/ssh_host_ed25519_key",
                 s->socket_dir);
        torture_write_file(tss->ed25519_hostkey,
                           torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0));

#ifdef HAVE_DSA
        snprintf(tss->dsa_hostkey,
                 sizeof(tss->dsa_hostkey),
                 "%s/sshd/ssh_host_dsa_key",
                 s->socket_dir);
        torture_write_file(tss->dsa_hostkey,
                           torture_get_testkey(SSH_KEYTYPE_DSS, 0));
#endif /* HAVE_DSA */
    }

    tss->state = s;
    *state = tss;

    return 0;
}

static int teardown_files(void **state)
{
    struct torture_state *s;
    struct test_server_st *tss;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    torture_teardown_socket_dir((void **)&s);
    SAFE_FREE(tss);

    return 0;
}

static int setup_temp_dir(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;

    char *cwd = NULL;
    char *tmp_dir = NULL;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tmp_dir = torture_make_temp_dir(template);
    assert_non_null(tmp_dir);

    tss->cwd = cwd;
    tss->temp_dir = tmp_dir;

    return 0;
}

static int teardown_temp_dir(void **state)
{
    struct test_server_st *tss = *state;
    int rc;

    assert_non_null(tss);

    rc = torture_change_dir(tss->cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(tss->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(tss->temp_dir);
    SAFE_FREE(tss->cwd);

    return 0;
}

static struct server_state_st *setup_server_state(char *config_file,
                                                  bool parse_global)
{
    struct server_state_st *ss = NULL;

    assert_non_null(config_file);

    /* Create default server state */
    ss = (struct server_state_st *)calloc(1, sizeof(struct server_state_st));
    assert_non_null(ss);

    ss->address = strdup("127.0.0.10");
    assert_non_null(ss->address);

    ss->port = 22;
    ss->host_key = NULL;

    /* Use default username and password (set in default_handle_session_cb) */
    ss->expected_username = NULL;
    ss->expected_password = NULL;

    ss->verbosity = torture_libssh_verbosity();
    ss->auth_methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY;

    /* TODO make configurable */
    ss->max_tries = 3;
    ss->error = 0;

    /* Use the default session handling function */
    ss->handle_session = default_handle_session_cb;
    assert_non_null(ss->handle_session);

    /* Set if should parse global configuration before */
    ss->parse_global_config = parse_global;

    /* Set the config file to be used */
    ss->config_file = strdup(config_file);
    assert_non_null(ss->config_file);

    return ss;
}

static int start_server(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s;
    struct server_state_st *ss;

    char pid_str[1024];
    pid_t pid;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ss = tss->ss;
    assert_non_null(ss);

    /* Start the server using the default values */
    pid = fork_run_server(ss);
    if (pid < 0) {
        fail();
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    torture_write_file(s->srv_pidfile, (const char *)pid_str);

    /* TODO properly wait for the server (use ping approach) */
    /* Wait 200ms */
    usleep(200 * 1000);

    return 0;
}

static int stop_server(void **state)
{
    struct torture_state *s;
    struct test_server_st *tss;

    int rc;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    rc = torture_terminate_process(s->srv_pidfile);
    if (rc != 0) {
        fprintf(stderr, "XXXXXX Failed to terminate sshd\n");
    }

    unlink(s->srv_pidfile);

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

    /* Make sure we do not test the agent */
    unsetenv("SSH_AUTH_SOCK");

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

static int try_config_content(void **state, const char *config_content,
                              bool parse_global)
{
    struct test_server_st *tss = *state;
    struct server_state_st *ss;
    struct torture_state *s;
    char config_file[1024];
    int rc;

    ssh_session session;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    /* Prepare the config file to test */
    snprintf(config_file,
             sizeof(config_file),
             "%s/config_file",
             tss->temp_dir);

    if (parse_global) {
        fprintf(stderr, "Using system-wide configuration\n");
    }
    fprintf(stderr, "Trying content: \n\n%s\n", config_content);

    torture_write_file(config_file, config_content);

    ss = setup_server_state(config_file, parse_global);
    assert_non_null(ss);

    tss->ss = ss;

    rc = start_server(state);
    assert_int_equal(rc, 0);

    rc = session_setup(state);
    assert_int_equal(rc, 0);

    session = s->ssh.session;
    assert_non_null(session);

    /* Authenticate as alice with bob */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);
    assert_ssh_return_code(session, rc);

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    rc = ssh_userauth_none(session,NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    rc = session_teardown(state);
    assert_int_equal(rc, 0);

    rc = stop_server(state);
    assert_int_equal(rc, 0);

    free_server_state(tss->ss);
    SAFE_FREE(tss->ss);

    unlink(config_file);

    return 0;
}

static char *hostkey_files[6] = {0};

static size_t setup_hostkey_files(struct test_server_st *tss)
{
    size_t num_hostkey_files = 1;

    hostkey_files[0] = tss->rsa_hostkey;

#ifdef TEST_ALL_CRYPTO_COMBINATIONS
    hostkey_files[1] = tss->ecdsa_256_hostkey;
    hostkey_files[2] = tss->ecdsa_384_hostkey;
    hostkey_files[3] = tss->ecdsa_521_hostkey;

    num_hostkey_files = 4;

    if (!ssh_fips_mode()) {
        hostkey_files[4] = tss->ed25519_hostkey;
        num_hostkey_files++;
#ifdef HAVE_DSA
        hostkey_files[5] = tss->dsa_hostkey;
        num_hostkey_files++;
#endif
    }
#endif /* TEST_ALL_CRYPTO_COMBINATIONS */

    return num_hostkey_files;
}

static void torture_server_config_hostkey(void **state)
{
    struct test_server_st *tss = *state;
    size_t i, num_hostkey_files;
    char config_content[4096];

    int rc;

    assert_non_null(tss);

    num_hostkey_files = setup_hostkey_files(tss);

    for (i = 0; i < num_hostkey_files; i++) {
        snprintf(config_content,
                sizeof(config_content),
                "HostKey %s\n",
                hostkey_files[i]);

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);
    }
}

static void torture_server_config_ciphers(void **state)
{
    struct test_server_st *tss = *state;
    size_t i, j, num_hostkey_files = 1;
    char config_content[4096];

    const char *ciphers;

    struct ssh_tokens_st *tokens;

    int rc;

    assert_non_null(tss);

    num_hostkey_files = setup_hostkey_files(tss);

    if (ssh_fips_mode()) {
        ciphers = ssh_kex_get_fips_methods(SSH_CRYPT_S_C);
        assert_non_null(ciphers);
    } else {
        ciphers = ssh_kex_get_default_methods(SSH_CRYPT_S_C);
        assert_non_null(ciphers);
    }

    tokens = ssh_tokenize(ciphers, ',');
    assert_non_null(tokens);

    for (i = 0; i < num_hostkey_files; i++) {
        /* Try setting all default algorithms */
        snprintf(config_content,
                 sizeof(config_content),
                 "HostKey %s\nCiphers %s\n",
                 hostkey_files[i], ciphers);

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);

        /* Try each algorithm individually */
        j = 0;
        while(tokens->tokens[j] != NULL) {
            snprintf(config_content,
                    sizeof(config_content),
                    "HostKey %s\nCiphers %s\n",
                    hostkey_files[i], tokens->tokens[j]);

            rc = try_config_content(state, config_content, false);
            assert_int_equal(rc, 0);

            j++;
        }
    }

    ssh_tokens_free(tokens);
}

static void torture_server_config_macs(void **state)
{
    struct test_server_st *tss = *state;
    size_t i, j, num_hostkey_files = 1;
    char config_content[4096];

    const char *macs;

    struct ssh_tokens_st *tokens;

    int rc;

    assert_non_null(tss);

    num_hostkey_files = setup_hostkey_files(tss);

    if (ssh_fips_mode()) {
        macs = ssh_kex_get_fips_methods(SSH_MAC_S_C);
        assert_non_null(macs);
    } else {
        macs = ssh_kex_get_default_methods(SSH_MAC_S_C);
        assert_non_null(macs);
    }

    tokens = ssh_tokenize(macs, ',');
    assert_non_null(tokens);

    for (i = 0; i < num_hostkey_files; i++) {
        /* Try setting all default algorithms */
        snprintf(config_content,
                 sizeof(config_content),
                 "HostKey %s\nMACs %s\n",
                 hostkey_files[i], macs);

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);

        /* Try each algorithm individually */
        j = 0;
        while(tokens->tokens[j] != NULL) {
            snprintf(config_content,
                    sizeof(config_content),
                    "HostKey %s\nMACs %s\n",
                    hostkey_files[i], tokens->tokens[j]);

            rc = try_config_content(state, config_content, false);
            assert_int_equal(rc, 0);

            j++;
        }
    }

    ssh_tokens_free(tokens);
}

static void torture_server_config_kex(void **state)
{
    struct test_server_st *tss = *state;
    size_t i, j, num_hostkey_files = 1;
    char config_content[4096];

    const char *kex;

    struct ssh_tokens_st *tokens;

    int rc;

    assert_non_null(tss);

    num_hostkey_files = setup_hostkey_files(tss);

    if (ssh_fips_mode()) {
        kex = ssh_kex_get_fips_methods(SSH_KEX);
        assert_non_null(kex);
    } else {
        kex = ssh_kex_get_default_methods(SSH_KEX);
        assert_non_null(kex);
    }

    tokens = ssh_tokenize(kex, ',');
    assert_non_null(tokens);

    for (i = 0; i < num_hostkey_files; i++) {
        /* Try setting all default algorithms */
        snprintf(config_content,
                 sizeof(config_content),
                 "HostKey %s\nKexAlgorithms %s\n",
                 hostkey_files[i], kex);

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);

        /* Try each algorithm individually */
        j = 0;
        while(tokens->tokens[j] != NULL) {
            snprintf(config_content,
                    sizeof(config_content),
                    "HostKey %s\nKexAlgorithms %s\n",
                    hostkey_files[i], tokens->tokens[j]);

            rc = try_config_content(state, config_content, false);
            assert_int_equal(rc, 0);

            j++;
        }
    }

    ssh_tokens_free(tokens);
}

static void torture_server_config_hostkey_algorithms(void **state)
{
    struct test_server_st *tss = *state;
    size_t i, num_hostkey_files = 5;
    char config_content[4096];

    const char *allowed;

    int rc;

    assert_non_null(tss);

    num_hostkey_files = setup_hostkey_files(tss);

    if (ssh_fips_mode()) {
        allowed = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
        assert_non_null(allowed);
    } else {
        allowed = ssh_kex_get_default_methods(SSH_HOSTKEYS);
        assert_non_null(allowed);
    }

    for (i = 0; i < num_hostkey_files; i++) {
        /* Should work with all allowed */
        snprintf(config_content,
                 sizeof(config_content),
                 "HostKey %s\nHostKeyAlgorithms %s\n",
                 hostkey_files[i], allowed);

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);
    }

    /* Should work with matching hostkey and allowed algorithm */

    if (!ssh_fips_mode()) {
        /* ed25519 */
        snprintf(config_content,
                sizeof(config_content),
                "HostKey %s\nHostkeyAlgorithms %s\n",
                tss->ed25519_hostkey, "ssh-ed25519");

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);

        /* ssh-rsa */
        snprintf(config_content,
                sizeof(config_content),
                "HostKey %s\nHostkeyAlgorithms %s\n",
                tss->rsa_hostkey, "ssh-rsa");

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);
    }

    /* rsa-sha2-256 */
    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nHostkeyAlgorithms %s\n",
            tss->rsa_hostkey, "rsa-sha2-256");

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);

    /* ssh-sha2-512 */
    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nHostkeyAlgorithms %s\n",
            tss->rsa_hostkey, "rsa-sha2-512");

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);

    /* ecdsa-sha2-nistp256 */
    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nHostkeyAlgorithms %s\n",
            tss->ecdsa_256_hostkey, "ecdsa-sha2-nistp256");

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);

    /* ecdsa-sha2-nistp384 */
    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nHostkeyAlgorithms %s\n",
            tss->ecdsa_384_hostkey, "ecdsa-sha2-nistp384");

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);

    /* ecdsa-sha2-nistp521 */
    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nHostkeyAlgorithms %s\n",
            tss->ecdsa_521_hostkey, "ecdsa-sha2-nistp521");

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);

#ifdef HAVE_DSA
    if (!ssh_fips_mode()) {
        /* ssh-dss */
        snprintf(config_content,
                sizeof(config_content),
                "HostKey %s\nHostkeyAlgorithms %s\n",
                tss->dsa_hostkey, "ssh-dss");

        rc = try_config_content(state, config_content, false);
        assert_int_equal(rc, 0);
    }
#endif
}

static void torture_server_config_unknown(void **state)
{
    struct test_server_st *tss = *state;
    char config_content[4096];

    int rc;

    assert_non_null(tss);
    assert_non_null(tss->rsa_hostkey);

    snprintf(config_content,
            sizeof(config_content),
            "HostKey %s\nUnknownOption unknown-value1,unknown-value2\n",
            tss->rsa_hostkey);

    rc = try_config_content(state, config_content, false);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_server_config_hostkey,
                                        setup_temp_dir, teardown_temp_dir),
        cmocka_unit_test_setup_teardown(torture_server_config_ciphers,
                                        setup_temp_dir, teardown_temp_dir),
        cmocka_unit_test_setup_teardown(torture_server_config_macs,
                                        setup_temp_dir, teardown_temp_dir),
        cmocka_unit_test_setup_teardown(torture_server_config_kex,
                                        setup_temp_dir, teardown_temp_dir),
        cmocka_unit_test_setup_teardown(torture_server_config_hostkey_algorithms,
                                        setup_temp_dir, teardown_temp_dir),
        cmocka_unit_test_setup_teardown(torture_server_config_unknown,
                                        setup_temp_dir, teardown_temp_dir),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
            setup_files,
            teardown_files);

    ssh_finalize();

    return rc;
}
