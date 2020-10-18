#include "config.h"

#define LIBSSH_STATIC

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_key.h"
#include "torture_pki.h"
#include "pki.c"

#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_DSA_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_dsa"

const char template[] = "temp_dir_XXXXXX";
const unsigned char INPUT[] = "12345678901234567890";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

static int setup_dsa_key(void **state)
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

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                       torture_get_testkey(SSH_KEYTYPE_DSS, 1));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS));
    torture_write_file(LIBSSH_DSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS_CERT01));

    return 0;
}

static int setup_openssh_dsa_key(void **state)
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

    torture_write_file(LIBSSH_DSA_TESTKEY,
                       torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 0));
    torture_write_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                       torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 1));
    torture_write_file(LIBSSH_DSA_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS));
    torture_write_file(LIBSSH_DSA_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_DSS_CERT01));

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

static void torture_pki_dsa_import_pubkey_file(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_dsa_import_pubkey_from_openssh_privkey(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE, &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_dsa_import_privkey_base64(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    SSH_KEY_FREE(key);
}

static void torture_pki_dsa_import_privkey_base64_comment(void **state)
{
    int rc, file_str_len;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *comment_str = "#this is line-comment\n#this is another\n";
    const char *key_str = NULL;
    char *file_str = NULL;

    (void) state; /* unused */

    key_str = torture_get_testkey(SSH_KEYTYPE_DSS, 0);
    assert_non_null(key_str);

    file_str_len = strlen(comment_str) + strlen(key_str) + 1;
    file_str = malloc(file_str_len);
    assert_non_null(file_str);
    rc = snprintf(file_str, file_str_len, "%s%s", comment_str, key_str);
    assert_int_equal(rc, file_str_len - 1);

    rc = ssh_pki_import_privkey_base64(file_str,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    free(file_str);
    SSH_KEY_FREE(key);
}

static void torture_pki_dsa_import_privkey_base64_whitespace(void **state)
{
    int rc, file_str_len;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *whitespace_str = "      \n\t\t\t\t\t\n\n\n\n\n";
    const char *key_str = NULL;
    char *file_str = NULL;

    (void) state; /* unused */

    key_str = torture_get_testkey(SSH_KEYTYPE_DSS, 0);
    assert_non_null(key_str);

    file_str_len = strlen(whitespace_str) + strlen(key_str) + 1;
    file_str = malloc(file_str_len);
    assert_non_null(file_str);
    rc = snprintf(file_str, file_str_len, "%s%s", whitespace_str, key_str);
    assert_int_equal(rc, file_str_len - 1);

    rc = ssh_pki_import_privkey_base64(file_str,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);

    free(file_str);
    SSH_KEY_FREE(key);
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

static void torture_pki_sign_data_dsa(void **state)
{
    int rc;
    ssh_key key = NULL;

    (void) state;

    /* Setup */
    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    /* Test using SHA1 */
    rc = test_sign_verify_data(key, SSH_DIGEST_SHA1, INPUT, sizeof(INPUT));
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
    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(key);

    /* Get the public key to verify signature */
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);

    /* Sign the buffer */
    sig = pki_sign_data(key, SSH_DIGEST_SHA1, INPUT, sizeof(INPUT));
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

    /* Test if signature fails with SSH_DIGEST_SHA256 */
    bad_sig = pki_sign_data(key, SSH_DIGEST_SHA256, INPUT, sizeof(INPUT));
    assert_null(bad_sig);

    /* Test if verification fails with SSH_DIGEST_SHA256 */
    sig->hash_type = SSH_DIGEST_SHA256;
    rc = pki_verify_data_signature(sig, pubkey, INPUT, sizeof(INPUT));
    assert_int_not_equal(rc, SSH_OK);

    /* Test if signature fails with SSH_DIGEST_SHA384 */
    bad_sig = pki_sign_data(key, SSH_DIGEST_SHA384, INPUT, sizeof(INPUT));
    assert_null(bad_sig);

    /* Test if verification fails with SSH_DIGEST_SHA384 */
    sig->hash_type = SSH_DIGEST_SHA384;
    rc = pki_verify_data_signature(sig, pubkey, INPUT, sizeof(INPUT));
    assert_int_not_equal(rc, SSH_OK);

    /* Test if signature fails with SSH_DIGEST_SHA512 */
    bad_sig = pki_sign_data(key, SSH_DIGEST_SHA512, INPUT, sizeof(INPUT));
    assert_null(bad_sig);

    /* Test if verification fails with SSH_DIGEST_SHA512 */
    sig->hash_type = SSH_DIGEST_SHA512;
    rc = pki_verify_data_signature(sig, pubkey, INPUT, sizeof(INPUT));
    assert_int_not_equal(rc, SSH_OK);

    /* Cleanup */
    ssh_signature_free(sig);
    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(key);
}

#ifdef HAVE_LIBCRYPTO
static void torture_pki_dsa_write_privkey(void **state)
{
    ssh_key origkey = NULL;
    ssh_key privkey = NULL;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_DSA_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
                                     NULL,
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
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
    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_DSA_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_DSA_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);
    assert_null(privkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY_PASSPHRASE,
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
#endif

static void torture_pki_dsa_import_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
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
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    assert_null(key);

    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
#ifndef HAVE_LIBCRYPTO
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    assert_null(key);
#endif

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
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
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
                                       "wrong passphrase !!",
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    assert_null(key);

    /* This free in unnecessary, but the static analyser does not know */
    SSH_KEY_FREE(key);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 1),
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    assert_null(key);

    /* This free in unnecessary, but the static analyser does not know */
    SSH_KEY_FREE(key);
#endif /* HAVE_LIBCRYPTO */
}

static void
torture_pki_dsa_import_openssh_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *keystring = NULL;

    (void) state; /* unused */

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_DSS, 1);
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
    assert_null(key);

    /* test if it returns -1 if passphrase is NULL */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);

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
    assert_null(key);

    /* This free is unnecessary, but the static analyser does not know */
    SSH_KEY_FREE(key);

    /* test if it returns -1 if passphrase is NULL */
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == -1);
    assert_null(key);

    /* This free is unnecessary, but the static analyser does not know */
    SSH_KEY_FREE(key);
}


static void torture_pki_dsa_publickey_from_privatekey(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_key pubkey = NULL;
    const char *passphrase = NULL;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_testkey(SSH_KEYTYPE_DSS, 0),
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

static void torture_pki_dsa_import_cert_file(void **state)
{
    int rc;
    ssh_key cert = NULL;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_DSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_DSS_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    SSH_KEY_FREE(cert);
}

static void torture_pki_dsa_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key = NULL, *key_buf = NULL, *p = NULL;
    const char *str = NULL;
    ssh_key key = NULL;
    size_t keylen;
    size_t i;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_DSS));
    assert_non_null(key_buf);

    keylen = strlen(key_buf);

    str = p = key_buf;
    for (i = 0; i < keylen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }

    }

    type = ssh_key_type_from_name(str);
    assert_true(type == SSH_KEYTYPE_DSS);

    str = &p[i + 1];

    for (; i < keylen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }
    }

    rc = ssh_pki_import_pubkey_base64(str, type, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);
    assert_non_null(b64_key);

    assert_string_equal(str, b64_key);

    free(b64_key);
    free(key_buf);
    SSH_KEY_FREE(key);
}

static void torture_pki_dsa_generate_pubkey_from_privkey(void **state)
{
    char pubkey_generated[4096] = {0};
    ssh_key privkey = NULL;
    ssh_key pubkey = NULL;
    int len;
    int rc;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_DSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_DSS));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_DSS),
                        pubkey_generated,
                        len);

    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(pubkey);
}

static void torture_pki_dsa_duplicate_key(void **state)
{
    int rc;
    char *b64_key = NULL;
    char *b64_key_gen = NULL;
    ssh_key pubkey = NULL;
    ssh_key pubkey_dup = NULL;
    ssh_key privkey = NULL;
    ssh_key privkey_dup = NULL;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    assert_non_null(b64_key);
    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
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

static void torture_pki_dsa_generate_key(void **state)
{
    int rc;
    ssh_key key = NULL, pubkey = NULL;
    ssh_signature sign = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA1);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA1);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 3072, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, INPUT, sizeof(INPUT), SSH_DIGEST_SHA1);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    ssh_free(session);
}

static void torture_pki_dsa_cert_verify(void **state)
{
    int rc;
    ssh_key privkey = NULL, cert = NULL;
    ssh_signature sign = NULL;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_pki_import_cert_file(LIBSSH_DSA_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    sign = pki_do_sign(privkey, INPUT, sizeof(INPUT), SSH_DIGEST_SHA1);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, cert, INPUT, sizeof(INPUT));
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(cert);

    ssh_free(session);
}

static void torture_pki_dsa_skip(UNUSED_PARAM(void **state))
{
    skip();
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_pubkey_file,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_pubkey_from_openssh_privkey,
                                 setup_openssh_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64_comment,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64_whitespace,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_privkey_base64,
                                 setup_openssh_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_publickey_from_privatekey,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_import_cert_file,
                                        setup_dsa_key,
                                        teardown),
#ifdef HAVE_LIBCRYPTO
        cmocka_unit_test_setup_teardown(torture_pki_dsa_write_privkey,
                                 setup_dsa_key,
                                 teardown),
#endif
        cmocka_unit_test(torture_pki_sign_data_dsa),
        cmocka_unit_test(torture_pki_fail_sign_with_incompatible_hash),
        cmocka_unit_test(torture_pki_dsa_import_privkey_base64_passphrase),
        cmocka_unit_test(torture_pki_dsa_import_openssh_privkey_base64_passphrase),

        /* public key */
        cmocka_unit_test_setup_teardown(torture_pki_dsa_publickey_base64,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_generate_pubkey_from_privkey,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_duplicate_key,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_duplicate_key,
                                 setup_dsa_key,
                                 teardown),
        cmocka_unit_test(torture_pki_dsa_generate_key),
        cmocka_unit_test_setup_teardown(torture_pki_dsa_cert_verify,
                                 setup_dsa_key,
                                 teardown),
    };
    struct CMUnitTest skip_tests[] = {
        cmocka_unit_test(torture_pki_dsa_skip)
    };

    ssh_init();
    if (ssh_fips_mode()) {
        rc = cmocka_run_group_tests(skip_tests, NULL, NULL);
    } else {
        torture_filter_tests(tests);
        rc = cmocka_run_group_tests(tests, NULL, NULL);
    }
    ssh_finalize();
    return rc;
}
