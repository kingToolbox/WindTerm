
#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "torture_key.h"
#include "pki.c"

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_RSA_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_rsa"

const char template[] = "temp_dir_XXXXXX";
const unsigned char INPUT[] = "1234567890123456789012345678901234567890"
                              "123456789012345678901234";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

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

static int setup_openssh_rsa_key(void **state)
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

    torture_write_file(LIBSSH_RSA_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_RSA, 0));
    torture_write_file(LIBSSH_RSA_TESTKEY_PASSPHRASE,
                       torture_get_openssh_testkey(SSH_KEYTYPE_RSA, 1));
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

static void torture_pki_rsa_import_pubkey_file(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_rsa_import_pubkey_from_openssh_privkey(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY_PASSPHRASE, &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_rsa_import_privkey_base64_NULL_key(void **state)
{
    int rc;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       NULL);
    assert_true(rc == -1);

}

static void torture_pki_rsa_import_privkey_base64_NULL_str(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, passphrase, NULL, NULL, &key);
    assert_true(rc == -1);

    SSH_KEY_FREE(key);
}

static void torture_pki_rsa_import_privkey_base64(void **state)
{
    int rc;
    char *key_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_RSA_TESTKEY);
    assert_non_null(key_str);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    SSH_KEY_FREE(key);
}

static void torture_pki_rsa_import_privkey_base64_comment(void **state)
{
    int rc, file_str_len;
    const char *comment_str = "#this is line-comment\n#this is another\n";
    char *key_str = NULL, *file_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_RSA_TESTKEY);
    assert_non_null(key_str);

    file_str_len = strlen(comment_str) + strlen(key_str) + 1;
    file_str = malloc(file_str_len);
    assert_non_null(file_str);
    rc = snprintf(file_str, file_str_len, "%s%s", comment_str, key_str);
    assert_int_equal(rc, file_str_len - 1);

    rc = ssh_pki_import_privkey_base64(file_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    free(file_str);
    SSH_KEY_FREE(key);
}

static void torture_pki_rsa_import_privkey_base64_whitespace(void **state)
{
    int rc, file_str_len;
    const char *whitespace_str = "      \n\t\t\t\t\t\n\n\n\n\n";
    char *key_str = NULL, *file_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_RSA_TESTKEY);
    assert_non_null(key_str);

    file_str_len = strlen(whitespace_str) + strlen(key_str) + 1;
    file_str = malloc(file_str_len);
    assert_non_null(file_str);
    rc = snprintf(file_str, file_str_len, "%s%s", whitespace_str, key_str);
    assert_int_equal(rc, file_str_len - 1);

    rc = ssh_pki_import_privkey_base64(file_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    free(file_str);
    SSH_KEY_FREE(key);
}

static void torture_pki_rsa_publickey_from_privatekey(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_key pubkey = NULL;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);
    assert_non_null(key);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);
}

static void torture_pki_rsa_copy_cert_to_privkey(void **state)
{
    /*
     * Tests copying a cert loaded into a public key to a private key.
     * The function is encryption type agnostic, no need to run this against
     * all supported key types.
     */
    int rc;
    const char *passphrase = torture_get_testkey_passphrase();
    ssh_key pubkey = NULL;
    ssh_key privkey = NULL;
    ssh_key cert = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == SSH_OK);
    assert_non_null(cert);

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 0),
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
    assert_null(pubkey->cert);
    rc = ssh_pki_copy_cert_to_privkey(pubkey, privkey);
    assert_true(rc == SSH_ERROR);

    /* Copying the cert to non-cert keys should work fine. */
    rc = ssh_pki_copy_cert_to_privkey(cert, pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey->cert);
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey->cert);

    /* The private key's cert is already set, another copy should fail. */
    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_true(rc == SSH_ERROR);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(pubkey);
}

static void torture_pki_rsa_import_cert_file(void **state) {
    int rc;
    ssh_key cert = NULL;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_RSA_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    SSH_KEY_FREE(cert);
}

static void torture_pki_rsa_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key = NULL, *key_buf = NULL, *p = NULL;
    const char *q = NULL;
    ssh_key key = NULL;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    assert_non_null(key_buf);

    q = p = key_buf;
    while (p != NULL && *p != '\0' && *p != ' ') p++;
    if (p != NULL) {
        *p = '\0';
    }

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_RSA);

    q = ++p;
    while (p != NULL && *p != '\0' && *p != ' ') p++;
    if (p != NULL) {
        *p = '\0';
    }

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
}

static void torture_pki_rsa_generate_pubkey_from_privkey(void **state) {
    char pubkey_generated[4096] = {0};
    ssh_key privkey = NULL;
    ssh_key pubkey = NULL;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_RSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_RSA),
                        pubkey_generated,
                        len);

    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(pubkey);
}

static void torture_pki_rsa_duplicate_key(void **state)
{
    int rc;
    char *b64_key = NULL;
    char *b64_key_gen = NULL;
    ssh_key pubkey = NULL;
    ssh_key pubkey_dup = NULL;
    ssh_key privkey = NULL;
    ssh_key privkey_dup = NULL;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
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

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey_dup);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey_dup);

    rc = ssh_pki_export_pubkey_base64(pubkey_dup, &b64_key_gen);
    assert_true(rc == 0);
    assert_non_null(b64_key_gen);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    rc = ssh_key_cmp(pubkey, pubkey_dup, SSH_KEY_CMP_PUBLIC);
    assert_true(rc == 0);

    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(pubkey_dup);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(privkey_dup);
    SSH_STRING_FREE_CHAR(b64_key);
    SSH_STRING_FREE_CHAR(b64_key_gen);
}

static void torture_pki_rsa_generate_key(void **state)
{
    int rc;
    ssh_key key = NULL, pubkey = NULL;
    ssh_signature sign = NULL;
    ssh_session session=ssh_new();
    (void) state;

    if (!ssh_fips_mode()) {
        rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
        assert_true(rc == SSH_OK);
        assert_non_null(key);
        rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
        assert_int_equal(rc, SSH_OK);
        assert_non_null(pubkey);
        sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA256);
        assert_non_null(sign);
        rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
        assert_true(rc == SSH_OK);
        ssh_signature_free(sign);
        SSH_KEY_FREE(key);
        SSH_KEY_FREE(pubkey);
        key = NULL;
        pubkey = NULL;
    }

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA256);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);
    key = NULL;
    pubkey = NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA256);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);
    key = NULL;
    pubkey = NULL;

    ssh_free(session);
}

static void torture_pki_rsa_sha2(void **state)
{
    int rc;
    ssh_key key = NULL, cert = NULL, pubkey = NULL;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    assert_non_null(session);

    /* Setup */
    rc  = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY, NULL, NULL, NULL, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);

    rc  = ssh_pki_import_cert_file(LIBSSH_RSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == SSH_OK);
    assert_non_null(cert);

    /* Get the public key to verify signature */
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    if (!ssh_fips_mode()) {
        /* Sign using old SHA1 digest */
        sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA1);
        assert_non_null(sign);
        rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
        assert_ssh_return_code(session, rc);
        rc = ssh_pki_signature_verify(session, sign, cert, INPUT, sizeof(INPUT));
        assert_ssh_return_code(session, rc);
        ssh_signature_free(sign);
    }

    /* Sign using new SHA256 digest */
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA256);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_ssh_return_code(session, rc);
    rc = ssh_pki_signature_verify(session, sign, cert, INPUT, sizeof(INPUT));
    assert_ssh_return_code(session, rc);
    ssh_signature_free(sign);

    /* Sign using rsa-sha2-512 algorithm */
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA512);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_ssh_return_code(session, rc);
    rc = ssh_pki_signature_verify(session, sign, cert, INPUT, sizeof(INPUT));
    assert_ssh_return_code(session, rc);
    ssh_signature_free(sign);

    /* Test that it fails when using DIGEST_AUTO */
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_AUTO);
    assert_null(sign);

    /* Test that it fails when using SHA384 */
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA384);
    assert_null(sign);

    /* Cleanup */
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(cert);
    ssh_free(session);
}

static int test_sign_verify_data(ssh_key key,
                                 enum ssh_digest_e hash_type,
                                 const unsigned char *input,
                                 size_t input_len)
{
    ssh_signature sig;
    ssh_key pubkey = NULL;
    int rc;

    /* Get the public key to verify signature */
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    /* Sign the buffer */
    sig = pki_sign_data(key, hash_type, input, input_len);
    assert_non_null(sig);

    /* Verify signature */
    rc = pki_verify_data_signature(sig, pubkey, input, input_len);
    assert_int_equal(rc, SSH_OK);

    ssh_signature_free(sig);
    SSH_KEY_FREE(pubkey);

    return rc;
}

static void torture_pki_sign_data_rsa(void **state)
{
    int rc;
    ssh_key key = NULL;

    (void) state;

    /* Setup */
    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    if (!ssh_fips_mode()) {
        /* Test using SHA1 */
        rc = test_sign_verify_data(key, SSH_DIGEST_SHA1, INPUT, sizeof(INPUT));
        assert_int_equal(rc, SSH_OK);
    }

    /* Test using SHA256 */
    rc = test_sign_verify_data(key, SSH_DIGEST_SHA256, INPUT, sizeof(INPUT));
    assert_int_equal(rc, SSH_OK);

    /* Test using SHA512 */
    rc = test_sign_verify_data(key, SSH_DIGEST_SHA512, INPUT, sizeof(INPUT));
    assert_int_equal(rc, SSH_OK);

    /* Cleanup */
    SSH_KEY_FREE(key);
}

static void torture_pki_fail_sign_with_incompatible_hash(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_key pubkey = NULL;
    ssh_signature sig, bad_sig;

    (void) state;

    /* Setup */
    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    /* Get the public key to verify signature */
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    /* Sign the buffer */
    sig = pki_sign_data(key, SSH_DIGEST_SHA256, INPUT, sizeof(INPUT));
    assert_non_null(sig);

    /* Verify signature */
    rc = pki_verify_data_signature(sig, pubkey, INPUT, sizeof(INPUT));
    assert_int_equal(rc, SSH_OK);

    /* Test if signature fails with SSH_DIGEST_AUTO */
    bad_sig = pki_sign_data(key, SSH_DIGEST_AUTO, INPUT, sizeof(INPUT));
    assert_null(bad_sig);

    /* Test if verification fails with SSH_DIGEST_AUTO */
    sig->hash_type = SSH_DIGEST_AUTO;
    rc = pki_verify_data_signature(sig, pubkey, INPUT, sizeof(INPUT));
    assert_int_not_equal(rc, SSH_OK);

    /* Cleanup */
    ssh_signature_free(sig);
    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(key);
}

#ifdef HAVE_LIBCRYPTO
static void torture_pki_rsa_write_privkey(void **state)
{
    ssh_key origkey = NULL;
    ssh_key privkey = NULL;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     NULL,
                                     NULL,
                                     NULL,
                                     LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    SSH_KEY_FREE(origkey);
    SSH_KEY_FREE(privkey);

    /* Test with passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_RSA_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_RSA_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);
    assert_null(privkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    SSH_KEY_FREE(origkey);
    SSH_KEY_FREE(privkey);
}
#endif /* HAVE_LIBCRYPTO */

static void torture_pki_rsa_import_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */


    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 1),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);
    assert_non_null(key);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    SSH_KEY_FREE(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_RSA, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);
#endif
}

static void
torture_pki_rsa_import_openssh_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *keystring = NULL;

    (void) state; /* unused */

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_RSA, 1);
    assert_non_null(keystring);

    rc = ssh_pki_import_privkey_base64(keystring,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);
    assert_non_null(key);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    SSH_KEY_FREE(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);

    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    SSH_KEY_FREE(key);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_pubkey_file,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_pubkey_from_openssh_privkey,
                                        setup_openssh_rsa_key,
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
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64_comment,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64_whitespace,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_privkey_base64,
                                        setup_openssh_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_publickey_from_privatekey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test(torture_pki_rsa_import_privkey_base64_passphrase),
        cmocka_unit_test(torture_pki_rsa_import_openssh_privkey_base64_passphrase),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_copy_cert_to_privkey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_import_cert_file,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_publickey_base64,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_generate_pubkey_from_privkey,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_duplicate_key,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test(torture_pki_rsa_generate_key),
#if defined(HAVE_LIBCRYPTO)
        cmocka_unit_test_setup_teardown(torture_pki_rsa_write_privkey,
                                        setup_rsa_key,
                                        teardown),
#endif /* HAVE_LIBCRYPTO */
        cmocka_unit_test(torture_pki_sign_data_rsa),
        cmocka_unit_test(torture_pki_fail_sign_with_incompatible_hash),
        cmocka_unit_test_setup_teardown(torture_pki_rsa_sha2,
                                        setup_rsa_key,
                                        teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
