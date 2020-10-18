#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "torture_key.h"
#include "legacy.c"

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#ifdef HAVE_DSA
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#endif

static int setup_rsa_key(void **state)
{
    ssh_session session;

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_RSA, 0));
    torture_write_file(LIBSSH_RSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA));

    session = ssh_new();
    *state = session;

    return 0;
}

#ifdef HAVE_DSA
static int setup_dsa_key(void **state)
{
    ssh_session session;

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS));

    session = ssh_new();
    *state = session;

    return 0;
}
#endif

static int setup_both_keys(void **state) {
    int rc;

    rc = setup_rsa_key(state);
    if (rc != 0) {
        return rc;
    }
#ifdef HAVE_DSA
    ssh_free(*state);

    rc = setup_dsa_key(state);
#endif

    return rc;
}

static int setup_both_keys_passphrase(void **state)
{
    ssh_session session;

    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_RSA, 1));
    torture_write_file(LIBSSH_RSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_RSA));

#ifdef HAVE_DSA
    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 1));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS));
#endif

    session = ssh_new();
    *state = session;

    return 0;
}

static int teardown(void **state)
{
#ifdef HAVE_DSA
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");
#endif

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    ssh_free(*state);

    return 0;
}

static void torture_pubkey_from_file(void **state) {
    ssh_session session = *state;
    ssh_string pubkey = NULL;
    int type, rc;

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);

    assert_true(rc == 0);

    SSH_STRING_FREE(pubkey);

    /* test if it returns 1 if pubkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    assert_true(rc == 1);

    /* This free is unnecessary, but the static analyser does not know */
    SSH_STRING_FREE(pubkey);

    /* test if it returns -1 if privkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    assert_true(rc == -1);

    /* This free is unnecessary, but the static analyser does not know */
    SSH_STRING_FREE(pubkey);
}

static int torture_read_one_line(const char *filename, char *buffer, size_t len)
{
    FILE *fp;
    size_t nmemb;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    nmemb = fread(buffer, len - 2, 1, fp);
    if (nmemb != 0 || ferror(fp)) {
        fclose(fp);
        return -1;
    }
    buffer[len - 1] = '\0';

    fclose(fp);

    return 0;
}

static void torture_pubkey_generate_from_privkey(void **state) {
    ssh_session session = *state;
    ssh_private_key privkey = NULL;
    ssh_public_key pubkey = NULL;
    ssh_string pubkey_orig = NULL;
    ssh_string pubkey_new = NULL;
    char pubkey_line_orig[512] = {0};
    char pubkey_line_new[512] = {0};
    char *p;
    int type_orig = 0;
    int type_new = 0;
    int rc;

    /* read the publickey */
    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey_orig,
        &type_orig);
    assert_true(rc == 0);
    assert_non_null(pubkey_orig);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_orig,
        sizeof(pubkey_line_orig));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    privkey = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    assert_non_null(privkey);

    pubkey = publickey_from_privatekey(privkey);
    assert_non_null(pubkey);
    type_new = privkey->type;
    privatekey_free(privkey);

    pubkey_new = publickey_to_string(pubkey);
    publickey_free(pubkey);

    assert_non_null(pubkey_new);

    assert_true(ssh_string_len(pubkey_orig) == ssh_string_len(pubkey_new));
    assert_memory_equal(ssh_string_data(pubkey_orig),
                        ssh_string_data(pubkey_new),
                        ssh_string_len(pubkey_orig));

    rc = ssh_publickey_to_file(session, LIBSSH_RSA_TESTKEY ".pub", pubkey_new, type_new);
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_new,
        sizeof(pubkey_line_new));
    assert_true(rc == 0);

    /* do not compare hostname */
    p = strrchr(pubkey_line_orig, ' ');
    if (p != NULL) {
        *p = '\0';
    }
    p = strrchr(pubkey_line_new, ' ');
    if (p != NULL) {
        *p = '\0';
    }

    assert_string_equal(pubkey_line_orig, pubkey_line_new);

    SSH_STRING_FREE(pubkey_orig);
    SSH_STRING_FREE(pubkey_new);
}

/**
 * @brief tests the privatekey_from_file function without passphrase
 */
static void torture_privatekey_from_file(void **state) {
    ssh_session session = *state;
    ssh_private_key key = NULL;

    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, NULL);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

#ifdef HAVE_DSA
    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, NULL);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
#endif

    /* Test the automatic type discovery */
    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

#ifdef HAVE_DSA
    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, NULL);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
#endif
}

/**
 * @brief tests the privatekey_from_file function with passphrase
 */
static void torture_privatekey_from_file_passphrase(void **state) {
    ssh_session session = *state;
    ssh_private_key key = NULL;

    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, TORTURE_TESTKEY_PASSWORD);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

#ifdef HAVE_DSA
    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, TORTURE_TESTKEY_PASSWORD);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
#endif

    /* Test the automatic type discovery */
    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, TORTURE_TESTKEY_PASSWORD);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

#ifdef HAVE_DSA
    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, TORTURE_TESTKEY_PASSWORD);
    assert_non_null(key);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
#endif
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pubkey_from_file,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pubkey_generate_from_privkey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_privatekey_from_file,
                                        setup_both_keys,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_privatekey_from_file_passphrase,
                                        setup_both_keys_passphrase,
                                        teardown),
    };


    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
