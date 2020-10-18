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
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"

#include <errno.h>
#include <sys/types.h>
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

static int session_setup(void **state) {
    struct torture_state *s = *state;
    int verbosity = torture_libssh_verbosity();
    struct passwd *pwd;
    bool false_v = false;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    /* Prevent parsing configuration files that can introduce different
     * algorithms then we want to test */
    ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &false_v);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void test_algorithm(ssh_session session,
                           const char *kex,
                           const char *cipher,
                           const char *hmac) {
    int rc;
    char data[256];
    size_t len_to_test[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 10,
        12, 15, 16, 20,
        31, 32, 33,
        63, 64, 65,
        100, 127, 128
    };
    unsigned int i;

    if (kex != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, kex);
        assert_ssh_return_code(session, rc);
    }

    if (cipher != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher);
        assert_ssh_return_code(session, rc);
        rc = ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher);
        assert_ssh_return_code(session, rc);
    }

    if (hmac != NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, hmac);
        assert_ssh_return_code(session, rc);
        rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, hmac);
        assert_ssh_return_code(session, rc);
    }

    rc = ssh_connect(session);
    assert_ssh_return_code(session, rc);

    /* send ignore packets of all sizes */
    memset(data, 0, sizeof(data));
    for (i = 0; i < (sizeof(len_to_test) / sizeof(size_t)); i++) {
        memset(data, 'A', len_to_test[i]);
        ssh_send_ignore(session, data);
        ssh_handle_packets(session, 50);
    }

    rc = ssh_userauth_none(session, NULL);
    if (rc != SSH_OK) {
        rc = ssh_get_error_code(session);
        assert_int_equal(rc, SSH_REQUEST_DENIED);
    }

    ssh_disconnect(session);
}

static void torture_algorithms_aes128_cbc_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha1");
}

static void torture_algorithms_aes128_cbc_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha2-256");
}

static void torture_algorithms_aes128_cbc_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha2-512");
}

static void torture_algorithms_aes128_cbc_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes128_cbc_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes128_cbc_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-cbc", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes192_cbc_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha1");
}

static void torture_algorithms_aes192_cbc_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha2-256");
}

static void torture_algorithms_aes192_cbc_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha2-512");
}

static void torture_algorithms_aes192_cbc_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes192_cbc_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes192_cbc_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-cbc", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes256_cbc_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha1");
}

static void torture_algorithms_aes256_cbc_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha2-256");
}

static void torture_algorithms_aes256_cbc_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha2-512");
}

static void torture_algorithms_aes256_cbc_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes256_cbc_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes256_cbc_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-cbc", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes128_ctr_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha1");
}

static void torture_algorithms_aes128_ctr_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha2-256");
}

static void torture_algorithms_aes128_ctr_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha2-512");
}

static void torture_algorithms_aes128_ctr_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes128_ctr_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes128_ctr_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-ctr", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes192_ctr_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha1");
}

static void torture_algorithms_aes192_ctr_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha2-256");
}

static void torture_algorithms_aes192_ctr_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha2-512");
}

static void torture_algorithms_aes192_ctr_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes192_ctr_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes192_ctr_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes192-ctr", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes256_ctr_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha1");
}

static void torture_algorithms_aes256_ctr_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha2-256");
}

static void torture_algorithms_aes256_ctr_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha2-512");
}

static void torture_algorithms_aes256_ctr_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_aes256_ctr_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_aes256_ctr_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-ctr", "hmac-sha2-512-etm@openssh.com");
}

static void torture_algorithms_aes128_gcm(void **state)
{
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes128-gcm@openssh.com", NULL);
}

static void torture_algorithms_aes256_gcm(void **state)
{
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, NULL/*kex*/, "aes256-gcm@openssh.com", NULL);
}

static void torture_algorithms_3des_cbc_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha1");
}

static void torture_algorithms_3des_cbc_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha2-256");
}

static void torture_algorithms_3des_cbc_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha2-512");
}

static void torture_algorithms_3des_cbc_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_3des_cbc_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_3des_cbc_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "3des-cbc", "hmac-sha2-512-etm@openssh.com");
}

#if defined(WITH_BLOWFISH_CIPHER) && defined(OPENSSH_BLOWFISH_CBC)
static void torture_algorithms_blowfish_cbc_hmac_sha1(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha1");
}

static void torture_algorithms_blowfish_cbc_hmac_sha2_256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha2-256");
}

static void torture_algorithms_blowfish_cbc_hmac_sha2_512(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha2-512");
}

static void torture_algorithms_blowfish_cbc_hmac_sha1_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha1-etm@openssh.com");
}

static void torture_algorithms_blowfish_cbc_hmac_sha2_256_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha2-256-etm@openssh.com");
}

static void torture_algorithms_blowfish_cbc_hmac_sha2_512_etm(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, NULL/*kex*/, "blowfish-cbc", "hmac-sha2-512-etm@openssh.com");
}
#endif /* WITH_BLOWFISH_CIPHER */

#ifdef OPENSSH_CHACHA20_POLY1305_OPENSSH_COM
static void torture_algorithms_chacha20_poly1305(void **state)
{
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session,
                   NULL, /*kex*/
                   "chacha20-poly1305@openssh.com",
                   NULL);
}
#endif /* OPENSSH_CHACHA20_POLY1305_OPENSSH_COM */

static void torture_algorithms_zlib(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "zlib");
#ifdef WITH_ZLIB
    assert_int_equal(rc, SSH_OK);
#else
    assert_int_equal(rc, SSH_ERROR);
#endif

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "zlib");
#ifdef WITH_ZLIB
    assert_int_equal(rc, SSH_OK);
#else
    assert_int_equal(rc, SSH_ERROR);
#endif

    rc = ssh_connect(session);
#ifdef WITH_ZLIB
    if (ssh_get_openssh_version(session)) {
        assert_false(rc == SSH_OK);
        ssh_disconnect(session);
        return;
    }
#endif
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    if (rc != SSH_OK) {
        rc = ssh_get_error_code(session);
        assert_int_equal(rc, SSH_REQUEST_DENIED);
    }

    ssh_disconnect(session);
}

static void torture_algorithms_zlib_openssh(void **state) {
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "zlib@openssh.com");
#ifdef WITH_ZLIB
    assert_int_equal(rc, SSH_OK);
#else
    assert_int_equal(rc, SSH_ERROR);
#endif

    rc = ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "zlib@openssh.com");
#ifdef WITH_ZLIB
    assert_int_equal(rc, SSH_OK);
#else
    assert_int_equal(rc, SSH_ERROR);
#endif

    rc = ssh_connect(session);
#ifdef WITH_ZLIB
    if (ssh_get_openssh_version(session)) {
        assert_true(rc==SSH_OK);
        rc = ssh_userauth_none(session, NULL);
        if (rc != SSH_OK) {
            rc = ssh_get_error_code(session);
            assert_int_equal(rc, SSH_REQUEST_DENIED);
        }
        ssh_disconnect(session);
        return;
    }
    assert_false(rc == SSH_OK);
#else
    assert_int_equal(rc, SSH_OK);
#endif

    ssh_disconnect(session);
}

#if defined(HAVE_ECC)
static void torture_algorithms_ecdh_sha2_nistp256(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, "ecdh-sha2-nistp256", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_ecdh_sha2_nistp384(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, "ecdh-sha2-nistp384", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_ecdh_sha2_nistp521(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, "ecdh-sha2-nistp521", NULL/*cipher*/, NULL/*hmac*/);
}
#endif

#ifdef OPENSSH_CURVE25519_SHA256
static void torture_algorithms_ecdh_curve25519_sha256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, "curve25519-sha256", NULL/*cipher*/, NULL/*hmac*/);
}
#endif /* OPENSSH_CURVE25519_SHA256 */

#ifdef OPENSSH_CURVE25519_SHA256_LIBSSH_ORG
static void torture_algorithms_ecdh_curve25519_sha256_libssh_org(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, "curve25519-sha256@libssh.org", NULL/*cipher*/, NULL/*hmac*/);
}
#endif /* OPENSSH_CURVE25519_SHA256_LIBSSH_ORG */

static void torture_algorithms_dh_group1(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, "diffie-hellman-group1-sha1", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_dh_group14(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, "diffie-hellman-group14-sha1", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_dh_group14_sha256(void **state) {
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, "diffie-hellman-group14-sha256", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_dh_group16(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, "diffie-hellman-group16-sha512", NULL/*cipher*/, NULL/*hmac*/);
}

static void torture_algorithms_dh_group18(void **state) {
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session, "diffie-hellman-group18-sha512", NULL/*cipher*/, NULL/*hmac*/);
}

#ifdef WITH_GEX
static void torture_algorithms_dh_gex_sha1(void **state)
{
    struct torture_state *s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session,
                   "diffie-hellman-group-exchange-sha1",
                   NULL,  /* cipher */
                   NULL); /* hmac */
}

static void torture_algorithms_dh_gex_sha256(void **state)
{
    struct torture_state *s = *state;

    test_algorithm(s->ssh.session,
                   "diffie-hellman-group-exchange-sha256",
                   NULL, /* cipher */
                   NULL); /* hmac */
}
#endif /* WITH_GEX */

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_cbc_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_cbc_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_cbc_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_ctr_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes192_ctr_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_ctr_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes128_gcm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_aes256_gcm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_3des_cbc_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
#if defined(WITH_BLOWFISH_CIPHER) && defined(OPENSSH_BLOWFISH_CBC)
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha2_256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha2_512,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha1_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha2_256_etm,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_blowfish_cbc_hmac_sha2_512_etm,
                                        session_setup,
                                        session_teardown),
#endif /* WITH_BLOWFISH_CIPHER */
#ifdef OPENSSH_CHACHA20_POLY1305_OPENSSH_COM
        cmocka_unit_test_setup_teardown(torture_algorithms_chacha20_poly1305,
                                        session_setup,
                                        session_teardown),
#endif /* OPENSSH_CHACHA20_POLY1305_OPENSSH_COM */
        cmocka_unit_test_setup_teardown(torture_algorithms_zlib,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_zlib_openssh,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_group1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_group14,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_group14_sha256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_group16,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_group18,
                                        session_setup,
                                        session_teardown),
#ifdef WITH_GEX
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_gex_sha1,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_dh_gex_sha256,
                                        session_setup,
                                        session_teardown),
#endif /* WITH_GEX */
#ifdef OPENSSH_CURVE25519_SHA256
        cmocka_unit_test_setup_teardown(torture_algorithms_ecdh_curve25519_sha256,
                                        session_setup,
                                        session_teardown),
#endif /* OPENSSH_CURVE25519_SHA256 */
#ifdef OPENSSH_CURVE25519_SHA256_LIBSSH_ORG
        cmocka_unit_test_setup_teardown(torture_algorithms_ecdh_curve25519_sha256_libssh_org,
                                        session_setup,
                                        session_teardown),
#endif /* OPENSSH_CURVE25519_SHA256_LIBSSH_ORG */
#if defined(HAVE_ECC)
        cmocka_unit_test_setup_teardown(torture_algorithms_ecdh_sha2_nistp256,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_ecdh_sha2_nistp384,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_algorithms_ecdh_sha2_nistp521,
                                        session_setup,
                                        session_teardown),
#endif
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
