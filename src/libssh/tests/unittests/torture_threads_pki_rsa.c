/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018 by Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "torture_key.h"
#include "pki.c"

#include <pthread.h>

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_RSA_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_rsa"

#define NUM_THREADS 10

const char template[] = "temp_dir_XXXXXX";
const unsigned char RSA_HASH[] = "12345678901234567890";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

static int run_on_threads(void *(*func)(void *))
{
    pthread_t threads[NUM_THREADS];
    int rc;
    int i;

    for (i = 0; i < NUM_THREADS; ++i) {
        rc = pthread_create(&threads[i], NULL, func, NULL);
        assert_int_equal(rc, 0);
    }

    for (i = 0; i < NUM_THREADS; ++i) {
        void *p = NULL;
        uint64_t *result;

        rc = pthread_join(threads[i], &p);
        assert_int_equal(rc, 0);

        result = (uint64_t *)p;
        assert_null(result);
    }

    return rc;
}

static int setup_rsa_key(void **state)
{
    struct pki_st *test_state = NULL;
    char *cwd = NULL;
    char *tmp_dir = NULL;
    int rc = 0;

    test_state = (struct pki_st *)malloc(sizeof(struct pki_st));
    assert_non_null(test_state);

    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tmp_dir = torture_make_temp_dir(template);
    assert_non_null(tmp_dir);

    test_state->cwd = cwd;
    test_state->temp_dir = tmp_dir;

    *state = test_state;

    rc = torture_change_dir(tmp_dir);
    assert_int_equal(rc, 0);

    printf("Changed directory to: %s\n", tmp_dir);

    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_RSA, 0));
    torture_write_file(LIBSSH_RSA_TESTKEY_PASSPHRASE,
                       torture_get_testkey(SSH_KEYTYPE_RSA, 1));
    torture_write_file(LIBSSH_RSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    torture_write_file(LIBSSH_RSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA_CERT01));

    return 0;
}

static int teardown(void **state) {

    struct pki_st *test_state = NULL;
    int rc = 0;

    test_state = *((struct pki_st **)state);

    assert_non_null(test_state);
    assert_non_null(test_state->cwd);
    assert_non_null(test_state->temp_dir);

    rc = torture_change_dir(test_state->cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(test_state->temp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(test_state->temp_dir);
    SAFE_FREE(test_state->cwd);
    SAFE_FREE(test_state);

    return 0;
}

static int disable_secmem(void **state)
{
    (void) state; /*unused*/

#if defined(HAVE_LIBGCRYPT)
    /* gcrypt currently is configured to use only 4kB of locked secmem
     * (see ssh_crypto_init() in src/libcrypt.c)
     *
     * This is insufficient to run the RSA key generation in many threads.
     * To avoid the expected warning, disable the secure memory.
     * */

    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_DISABLE_SECMEM);
#endif

    return 0;
}

static int enable_secmem(void **state)
{
    (void) state; /*unused*/

#if defined(HAVE_LIBGCRYPT)
    /* Re-enable secmem */
    gcry_control(GCRYCTL_INIT_SECMEM, 4096);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
#endif
    return 0;
}

static void *thread_pki_rsa_import_pubkey_file(void *threadid)
{
    ssh_key pubkey = NULL;
    int rc;

    (void) threadid;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);

    pthread_exit(NULL);
}

static void torture_pki_rsa_import_pubkey_file(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_pubkey_file);
    assert_int_equal(rc, 0);
}


static void *thread_pki_rsa_import_privkey_base64_NULL_key(void *threadid)
{
    int rc;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *testkey;

    (void) threadid; /* unused */

    testkey = torture_get_testkey(SSH_KEYTYPE_RSA, 0);
    assert_non_null(testkey);

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       NULL);
    assert_true(rc == -1);

    pthread_exit(NULL);
}

static void torture_pki_rsa_import_privkey_base64_NULL_key(void **state){
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_privkey_base64_NULL_key);
    assert_int_equal(rc, 0);
}


static void *thread_pki_rsa_import_privkey_base64_NULL_str(void *threadid)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) threadid; /* unused */

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, passphrase, NULL, NULL, &key);
    assert_true(rc == -1);

    SSH_KEY_FREE(key);
    pthread_exit(NULL);
}

static void torture_pki_rsa_import_privkey_base64_NULL_str(void **state){
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_privkey_base64_NULL_str);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_import_privkey_base64(void *threadid)
{
    const char *passphrase = torture_get_testkey_passphrase();
    char *key_str = NULL;
    ssh_key key = NULL;
    enum ssh_keytypes_e type;
    int ok;
    int rc;

    (void) threadid; /* unused */

    key_str = torture_pki_read_file(LIBSSH_RSA_TESTKEY);
    assert_non_null(key_str);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    ok = ssh_key_is_private(key);
    assert_true(ok);

    ok = ssh_key_is_public(key);
    assert_true(ok);

    free(key_str);
    SSH_KEY_FREE(key);

    pthread_exit(NULL);
}

static void torture_pki_rsa_import_privkey_base64(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_privkey_base64);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_publickey_from_privatekey(void *threadid)
{
    const char *passphrase = NULL;
    const char *testkey;
    ssh_key pubkey = NULL;
    ssh_key key = NULL;
    int rc;
    int ok;

    (void) threadid; /* unused */

    testkey = torture_get_testkey(SSH_KEYTYPE_RSA, 0);
    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);
    assert_non_null(key);

    ok = ssh_key_is_private(key);
    assert_true(ok);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);
    pthread_exit(NULL);
}

static void torture_pki_rsa_publickey_from_privatekey(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_publickey_from_privatekey);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_copy_cert_to_privkey(void *threadid)
{
    /*
     * Tests copying a cert loaded into a public key to a private key.
     * The function is encryption type agnostic, no need to run this against
     * all supported key types.
     */
    const char *passphrase = torture_get_testkey_passphrase();
    const char *testkey = NULL;
    ssh_key pubkey = NULL;
    ssh_key privkey = NULL;
    ssh_key cert = NULL;
    int rc;

    (void) threadid; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == SSH_OK);
    assert_non_null(cert);

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    testkey = torture_get_testkey(SSH_KEYTYPE_RSA, 0);
    assert_non_null(testkey);

    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey);

    /* Basic sanity. */
    rc = ssh_pki_copy_cert_to_privkey(NULL, privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_copy_cert_to_privkey(pubkey, NULL);
    assert_true(rc == SSH_ERROR);

    /* A public key doesn't have a cert, copy should fail. */
    rc = ssh_pki_copy_cert_to_privkey(pubkey, privkey);
    assert_true(rc == SSH_ERROR);

    /* Copying the cert to non-cert keys should work fine. */
    rc = ssh_pki_copy_cert_to_privkey(cert, pubkey);
    assert_true(rc == SSH_OK);
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_OK);

    /* The private key's cert is already set, another copy should fail. */
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_ERROR);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(pubkey);
    pthread_exit(NULL);
}

static void torture_pki_rsa_copy_cert_to_privkey(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_copy_cert_to_privkey);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_import_cert_file(void *threadid)
{
    int rc;
    ssh_key cert = NULL;
    enum ssh_keytypes_e type;

    (void) threadid; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_RSA_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    SSH_KEY_FREE(cert);
    pthread_exit(NULL);
}

static void torture_pki_rsa_import_cert_file(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_cert_file);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_publickey_base64(void *threadid)
{
    enum ssh_keytypes_e type;
    char *b64_key = NULL, *key_buf = NULL, *p = NULL;
    const char *q = NULL;
    ssh_key key;
    int rc;

    (void) threadid; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    assert_non_null(key_buf);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_RSA);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);
    assert_non_null(b64_key);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    SSH_KEY_FREE(key);
    pthread_exit(NULL);
}

static void torture_pki_rsa_publickey_base64(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_publickey_base64);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_duplicate_key(void *threadid)
{
    char *b64_key = NULL;
    char *b64_key_gen = NULL;
    ssh_key pubkey = NULL;
    ssh_key privkey = NULL;
    ssh_key privkey_dup = NULL;
    int cmp;
    int rc;

    (void) threadid;

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    SSH_KEY_FREE(pubkey);
    assert_non_null(b64_key);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    privkey_dup = ssh_key_dup(privkey);
    assert_non_null(privkey_dup);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);
    assert_non_null(b64_key_gen);

    assert_string_equal(b64_key, b64_key_gen);

    cmp = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(cmp == 0);

    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(privkey_dup);
    SSH_STRING_FREE_CHAR(b64_key);
    SSH_STRING_FREE_CHAR(b64_key_gen);
    pthread_exit(NULL);
}

static void torture_pki_rsa_duplicate_key(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_duplicate_key);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_generate_key(void *threadid)
{
    int rc;
    ssh_key key = NULL, pubkey = NULL;
    ssh_signature sign = NULL;
    ssh_session session = NULL;

    (void) threadid;

    session = ssh_new();
    assert_non_null(session);

    if (!ssh_fips_mode()) {
        rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
        assert_ssh_return_code(session, rc);
        assert_non_null(key);

        rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
        assert_int_equal(rc, SSH_OK);
        assert_non_null(pubkey);

        sign = pki_do_sign(key, RSA_HASH, 20, SSH_DIGEST_SHA256);
        assert_non_null(sign);

        rc = ssh_pki_signature_verify(session, sign, pubkey, RSA_HASH, 20);
        assert_ssh_return_code(session, rc);

        ssh_signature_free(sign);
        SSH_KEY_FREE(key);
        SSH_KEY_FREE(pubkey);
    }

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_ssh_return_code(session, rc);
    assert_non_null(key);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    sign = pki_do_sign(key, RSA_HASH, 20, SSH_DIGEST_SHA256);
    assert_non_null(sign);

    rc = ssh_pki_signature_verify(session, sign, pubkey, RSA_HASH, 20);
    assert_ssh_return_code(session, rc);

    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    sign = pki_do_sign(key, RSA_HASH, 20, SSH_DIGEST_SHA256);
    assert_non_null(sign);

    rc = ssh_pki_signature_verify(session, sign, pubkey, RSA_HASH, 20);
    assert_true(rc == SSH_OK);

    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    ssh_free(session);
    pthread_exit(NULL);
}

static void torture_pki_rsa_generate_key(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_generate_key);
    assert_int_equal(rc, 0);
}

static void *thread_pki_rsa_import_privkey_base64_passphrase(void *threadid)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *testkey;

    (void) threadid; /* unused */

    testkey = torture_get_testkey(SSH_KEYTYPE_RSA, 1);
    assert_non_null(testkey);

    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    SSH_KEY_FREE(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(testkey,
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(testkey,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);
#endif
    pthread_exit(NULL);
}

static void torture_pki_rsa_import_privkey_base64_passphrase(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_pki_rsa_import_privkey_base64_passphrase);
    assert_int_equal(rc, 0);
}

#define NUM_TESTS 11

static void torture_mixed(void **state)
{
    pthread_t threads[NUM_TESTS][NUM_THREADS];

    int i;
    int f;
    int rc;

    /* Array of functions to run on threads */
    static void *(*funcs[NUM_TESTS])(void *) = {
        thread_pki_rsa_import_pubkey_file,
        thread_pki_rsa_import_privkey_base64_NULL_key,
        thread_pki_rsa_import_privkey_base64_NULL_str,
        thread_pki_rsa_import_privkey_base64,
        thread_pki_rsa_publickey_from_privatekey,
        thread_pki_rsa_import_privkey_base64_passphrase,
        thread_pki_rsa_copy_cert_to_privkey,
        thread_pki_rsa_import_cert_file,
        thread_pki_rsa_publickey_base64,
        thread_pki_rsa_duplicate_key,
        thread_pki_rsa_generate_key,
    };

    (void) state;

    /* Call tests in a round-robin fashion */
    for (i = 0; i < NUM_THREADS; ++i) {
        for (f = 0; f < NUM_TESTS; f++) {
            rc = pthread_create(&threads[f][i], NULL, funcs[f], NULL);
            assert_int_equal(rc, 0);
        }
    }

    for (f = 0; f < NUM_TESTS; f++) {
        for (i = 0; i < NUM_THREADS; ++i) {
            void *p = NULL;
            uint64_t *result = NULL;

            rc = pthread_join(threads[f][i], &p);
            assert_int_equal(rc, 0);

            result = (uint64_t *)p;
            assert_null(result);
        }
    }
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_pubkey_file,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64_NULL_key,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64_NULL_str,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_publickey_from_privatekey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test(torture_pki_rsa_import_privkey_base64_passphrase),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_copy_cert_to_privkey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_cert_file,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_publickey_base64,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_duplicate_key,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_generate_key,
                                        disable_secmem,
                                        enable_secmem),
        cmocka_unit_test_setup_teardown(torture_mixed,
                                        setup_rsa_key,
                                        teardown),
    };

    /*
     * Not testing:
     *  - pki_rsa_generate_pubkey_from_privkey
     *  - pki_rsa_write_privkey
     *
     * The original tests in torture_pki_rsa.c require files to be erased
     */

    /*
     * If the library is statically linked, ssh_init() is not called
     * automatically
     */
    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
