/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Red Hat, Inc.
 *
 * Authors: Jakub Jelen <jjelen@redhat.com>
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
#include "libssh/sftp.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state)
{
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool b = false;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);

    /* Authenticate as alice with bob's pubkey */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_USER, TORTURE_SSH_USER_ALICE);
    assert_int_equal(rc, SSH_OK);

    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    /* Make sure we do not interfere with another ssh-agent */
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_free(s->ssh.session);

    return 0;
}

/* Check that the default limits for rekeying are enforced.
 * the limits are too high for testsuite to verify so
 * we should be fine with checking the values in internal
 * structures
 */
static void torture_rekey_default(void **state)
{
    struct torture_state *s = *state;
    int rc;
    struct ssh_crypto_struct *c = NULL;

    /* Define preferred ciphers: */
    if (ssh_fips_mode()) {
        /* We do not have any FIPS allowed cipher with different block size */
        rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_CIPHERS_C_S,
                             "aes128-gcm@openssh.com");
    } else {
        /* (out) C->S has 8B block */
        rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_CIPHERS_C_S,
                             "chacha20-poly1305@openssh.com");
    }
    assert_ssh_return_code(s->ssh.session, rc);
    /* (in) S->C has 16B block */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_CIPHERS_S_C,
                         "aes128-cbc");
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, rc);

    c = s->ssh.session->current_crypto;
    /* The blocks limit is set correctly */
    /* For S->C (in) we have 16B block => 2**(L/4) blocks */
    assert_int_equal(c->in_cipher->max_blocks,
                     (uint64_t)1 << (2 * c->in_cipher->blocksize));
    if (ssh_fips_mode()) {
        /* We do not have any FIPS allowed cipher with different block size */
        assert_int_equal(c->in_cipher->max_blocks,
                         (uint64_t)1 << (2 * c->in_cipher->blocksize));
    } else {
        /* The C->S (out) we have 8B block => 1 GB limit */
        assert_int_equal(c->out_cipher->max_blocks,
                         ((uint64_t)1 << 30) / c->out_cipher->blocksize);
    }

    ssh_disconnect(s->ssh.session);
}

/* We lower the rekey limits manually and check that the rekey
 * really happens when sending data
 */
static void torture_rekey_send(void **state)
{
    struct torture_state *s = *state;
    int rc;
    char data[256];
    unsigned int i;
    uint64_t bytes = 2048; /* 2KB (more than the authentication phase) */
    struct ssh_crypto_struct *c = NULL;
    unsigned char *secret_hash = NULL;

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_REKEY_DATA, &bytes);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, rc);

    /* The blocks limit is set correctly */
    c = s->ssh.session->current_crypto;
    assert_int_equal(c->in_cipher->max_blocks,
                     bytes / c->in_cipher->blocksize);
    assert_int_equal(c->out_cipher->max_blocks,
                     bytes / c->out_cipher->blocksize);
    /* We should have less encrypted packets than transfered (first are not encrypted) */
    assert_true(c->out_cipher->packets < s->ssh.session->send_seq);
    assert_true(c->in_cipher->packets < s->ssh.session->recv_seq);
    /* Copy the initial secret hash = session_id so we know we changed keys later */
    secret_hash = malloc(c->digest_len);
    assert_non_null(secret_hash);
    memcpy(secret_hash, c->secret_hash, c->digest_len);

    /* OpenSSH can not rekey before authentication so authenticate here */
    rc = ssh_userauth_none(s->ssh.session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(s->ssh.session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(s->ssh.session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(s->ssh.session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    /* send ignore packets of up to 1KB to trigger rekey */
    memset(data, 0, sizeof(data));
    memset(data, 'A', 128);
    for (i = 0; i < 16; i++) {
        ssh_send_ignore(s->ssh.session, data);
        ssh_handle_packets(s->ssh.session, 50);
    }

    /* The rekey limit was restored in the new crypto to the same value */
    c = s->ssh.session->current_crypto;
    assert_int_equal(c->in_cipher->max_blocks, bytes / c->in_cipher->blocksize);
    assert_int_equal(c->out_cipher->max_blocks, bytes / c->out_cipher->blocksize);
    /* Check that the secret hash is different than initially */
    assert_memory_not_equal(secret_hash, c->secret_hash, c->digest_len);
    free(secret_hash);

    ssh_disconnect(s->ssh.session);
}

#ifdef WITH_SFTP
static void session_setup_sftp(void **state)
{
    struct torture_state *s = *state;
    int rc;

    rc = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, rc);

    /* OpenSSH can not rekey before authentication so authenticate here */
    rc = ssh_userauth_none(s->ssh.session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(s->ssh.session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(s->ssh.session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(s->ssh.session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    /* Initialize SFTP session */
    s->ssh.tsftp = torture_sftp_session(s->ssh.session);
    assert_non_null(s->ssh.tsftp);
}

uint64_t bytes = 2048; /* 2KB */

static int session_setup_sftp_client(void **state)
{
    struct torture_state *s = *state;
    int rc;

    session_setup(state);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_REKEY_DATA, &bytes);
    assert_ssh_return_code(s->ssh.session, rc);

    session_setup_sftp(state);

    return 0;
}

#define MAX_XFER_BUF_SIZE 16384

/* To trigger rekey by receiving data, the easiest thing is probably to
 * use sftp
 */
static void torture_rekey_recv(void **state)
{
    struct torture_state *s = *state;
    struct ssh_crypto_struct *c = NULL;
    unsigned char *secret_hash = NULL;

    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE];
    ssize_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;
    mode_t mask;

    /* The blocks limit is set correctly */
    c = s->ssh.session->current_crypto;
    assert_int_equal(c->in_cipher->max_blocks, bytes / c->in_cipher->blocksize);
    assert_int_equal(c->out_cipher->max_blocks, bytes / c->out_cipher->blocksize);
    /* We should have less encrypted packets than transfered (first are not encrypted) */
    assert_true(c->out_cipher->packets < s->ssh.session->send_seq);
    assert_true(c->in_cipher->packets < s->ssh.session->recv_seq);
    /* Copy the initial secret hash = session_id so we know we changed keys later */
    secret_hash = malloc(c->digest_len);
    assert_non_null(secret_hash);
    memcpy(secret_hash, c->secret_hash, c->digest_len);

    /* Download a file */
    file = sftp_open(s->ssh.tsftp->sftp, SSH_EXECUTABLE, O_RDONLY, 0);
    assert_non_null(file);

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(libssh_tmp_file);
    umask(mask);
    unlink(libssh_tmp_file);

    for (;;) {
        bytesread = sftp_read(file, buf, MAX_XFER_BUF_SIZE);
        if (bytesread == 0) {
                break; /* EOF */
        }
        assert_false(bytesread < 0);

        byteswritten = write(fd, buf, bytesread);
        assert_int_equal(byteswritten, bytesread);
    }

    close(fd);

    /* The rekey limit was restored in the new crypto to the same value */
    c = s->ssh.session->current_crypto;
    assert_int_equal(c->in_cipher->max_blocks, bytes / c->in_cipher->blocksize);
    assert_int_equal(c->out_cipher->max_blocks, bytes / c->out_cipher->blocksize);
    /* Check that the secret hash is different than initially */
    assert_memory_not_equal(secret_hash, c->secret_hash, c->digest_len);
    free(secret_hash);

    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
}
#endif /* WITH_SFTP */

/* Rekey time requires rekey after specified time and is off by default.
 * Setting the time to small enough value and waiting, we should trigger
 * rekey on the first sent packet afterward.
 */
static void torture_rekey_time(void **state)
{
    struct torture_state *s = *state;
    int rc;
    char data[256];
    unsigned int i;
    uint32_t time = 3; /* 3 seconds */
    struct ssh_crypto_struct *c = NULL;
    unsigned char *secret_hash = NULL;

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_REKEY_TIME, &time);
    assert_ssh_return_code(s->ssh.session, rc);
    /* The time is internally stored in microseconds */
    assert_int_equal(time * 1000, s->ssh.session->opts.rekey_time);

    rc = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, rc);

    /* Copy the initial secret hash = session_id so we know we changed keys later */
    c = s->ssh.session->current_crypto;
    secret_hash = malloc(c->digest_len);
    assert_non_null(secret_hash);
    memcpy(secret_hash, c->secret_hash, c->digest_len);

    /* OpenSSH can not rekey before authentication so authenticate here */
    rc = ssh_userauth_none(s->ssh.session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(s->ssh.session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(s->ssh.session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(s->ssh.session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    /* Send some data. This should not trigger rekey yet */
    memset(data, 0, sizeof(data));
    memset(data, 'A', 8);
    for (i = 0; i < 3; i++) {
        ssh_send_ignore(s->ssh.session, data);
        ssh_handle_packets(s->ssh.session, 50);
    }

    /* Check that the secret hash is the same */
    c = s->ssh.session->current_crypto;
    assert_memory_equal(secret_hash, c->secret_hash, c->digest_len);

    /* Wait some more time */
    sleep(3);

    /* send some more data to trigger rekey and handle the
     * key exchange "in background" */
    for (i = 0; i < 8; i++) {
        ssh_send_ignore(s->ssh.session, data);
        ssh_handle_packets(s->ssh.session, 50);
    }

    /* Check that the secret hash is different than initially */
    c = s->ssh.session->current_crypto;
    assert_memory_not_equal(secret_hash, c->secret_hash, c->digest_len);
    free(secret_hash);

    ssh_disconnect(s->ssh.session);
}

/* We lower the rekey limits manually and check that the rekey
 * really happens when sending data
 */
static void torture_rekey_server_send(void **state)
{
    struct torture_state *s = *state;
    int rc;
    char data[256];
    unsigned int i;
    struct ssh_crypto_struct *c = NULL;
    unsigned char *secret_hash = NULL;
    const char *sshd_config = "RekeyLimit 2K none";

    torture_update_sshd_config(state, sshd_config);

    rc = ssh_connect(s->ssh.session);
    assert_ssh_return_code(s->ssh.session, rc);

    /* Copy the initial secret hash = session_id so we know we changed keys later */
    c = s->ssh.session->current_crypto;
    secret_hash = malloc(c->digest_len);
    assert_non_null(secret_hash);
    memcpy(secret_hash, c->secret_hash, c->digest_len);

    /* OpenSSH can not rekey before authentication so authenticate here */
    rc = ssh_userauth_none(s->ssh.session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_int_equal(ssh_get_error_code(s->ssh.session), SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(s->ssh.session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(s->ssh.session, NULL, NULL);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    /* send ignore packets of up to 1KB to trigger rekey */
    memset(data, 0, sizeof(data));
    memset(data, 'A', 128);
    for (i = 0; i < 20; i++) {
        ssh_send_ignore(s->ssh.session, data);
        ssh_handle_packets(s->ssh.session, 50);
    }

    /* Check that the secret hash is different than initially */
    c = s->ssh.session->current_crypto;
    assert_memory_not_equal(secret_hash, c->secret_hash, c->digest_len);
    free(secret_hash);

    ssh_disconnect(s->ssh.session);
}

#ifdef WITH_SFTP
static int session_setup_sftp_server(void **state)
{
    const char *sshd_config = "RekeyLimit 2K none";

    session_setup(state);

    torture_update_sshd_config(state, sshd_config);

    session_setup_sftp(state);

    return 0;
}

static void torture_rekey_server_recv(void **state)
{
    struct torture_state *s = *state;
    struct ssh_crypto_struct *c = NULL;
    unsigned char *secret_hash = NULL;
    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE];
    ssize_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;
    mode_t mask;

    /* Copy the initial secret hash = session_id so we know we changed keys later */
    c = s->ssh.session->current_crypto;
    secret_hash = malloc(c->digest_len);
    assert_non_null(secret_hash);
    memcpy(secret_hash, c->secret_hash, c->digest_len);

    /* Download a file */
    file = sftp_open(s->ssh.tsftp->sftp, SSH_EXECUTABLE, O_RDONLY, 0);
    assert_non_null(file);

    mask = umask(S_IRWXO | S_IRWXG);
    fd = mkstemp(libssh_tmp_file);
    umask(mask);
    unlink(libssh_tmp_file);

    for (;;) {
        bytesread = sftp_read(file, buf, MAX_XFER_BUF_SIZE);
        if (bytesread == 0) {
                break; /* EOF */
        }
        assert_false(bytesread < 0);

        byteswritten = write(fd, buf, bytesread);
        assert_int_equal(byteswritten, bytesread);
    }

    close(fd);

    /* Check that the secret hash is different than initially */
    c = s->ssh.session->current_crypto;
    assert_memory_not_equal(secret_hash, c->secret_hash, c->digest_len);
    free(secret_hash);

    torture_sftp_close(s->ssh.tsftp);
    ssh_disconnect(s->ssh.session);
}
#endif /* WITH_SFTP */


int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_rekey_default,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_rekey_time,
                                        session_setup,
                                        session_teardown),
#ifdef WITH_SFTP
        cmocka_unit_test_setup_teardown(torture_rekey_recv,
                                        session_setup_sftp_client,
                                        session_teardown),
#endif /* WITH_SFTP */
        cmocka_unit_test_setup_teardown(torture_rekey_send,
                                        session_setup,
                                        session_teardown),
        /* Note, that this modifies the sshd_config */
        cmocka_unit_test_setup_teardown(torture_rekey_server_send,
                                        session_setup,
                                        session_teardown),
#ifdef WITH_SFTP
        cmocka_unit_test_setup_teardown(torture_rekey_server_recv,
                                        session_setup_sftp_server,
                                        session_teardown),
#endif /* WITH_SFTP */
        /* TODO verify the two rekey are possible and the states are not broken after rekey */
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
