#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "torture_key.h"
#include "torture_pki.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_ED25519_TESTKEY "libssh_testkey.id_ed25519"
#define LIBSSH_ED25519_TESTKEY_PASSPHRASE "libssh_testkey_passphrase.id_ed25519"

const char template[] = "temp_dir_XXXXXX";
const unsigned char HASH[] = "12345678901234567890";
const uint8_t ref_signature[ED25519_SIG_LEN]=
    "\xbb\x8d\x55\x9f\x06\x14\x39\x24\xb4\xe1\x5a\x57\x3d\x9d\xbe\x22"
    "\x1b\xc1\x32\xd5\x55\x16\x00\x64\xce\xb4\xc3\xd2\xe3\x6f\x5e\x8d"
    "\x10\xa3\x18\x93\xdf\xa4\x96\x81\x11\x8e\x1e\x26\x14\x8a\x08\x1b"
    "\x01\x6a\x60\x59\x9c\x4a\x55\xa3\x16\x56\xf6\xc4\x50\x42\x7f\x03";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

static int setup_ed25519_key(void **state)
{
    const char *keystring = NULL;
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

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0);
    torture_write_file(LIBSSH_ED25519_TESTKEY, keystring);
    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 1);
    torture_write_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE, keystring);

    torture_write_file(LIBSSH_ED25519_TESTKEY ".pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ED25519));
    torture_write_file(LIBSSH_ED25519_TESTKEY "-cert.pub",
                       torture_get_testkey_pub(SSH_KEYTYPE_ED25519_CERT01));

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

static void torture_pki_ed25519_import_pubkey_file(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_ED25519_TESTKEY ".pub", &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_ed25519_import_pubkey_from_openssh_privkey(void **state)
{
    ssh_key pubkey = NULL;
    int rc;

    (void)state;

    /* The key doesn't have the hostname as comment after the key */
    rc = ssh_pki_import_pubkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE, &pubkey);
    assert_return_code(rc, errno);
    assert_non_null(pubkey);

    SSH_KEY_FREE(pubkey);
}

static void torture_pki_ed25519_import_privkey_base64(void **state)
{
    int rc;
    char *key_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ED25519_TESTKEY);
    assert_non_null(key_str);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    SSH_KEY_FREE(key);

}

static void torture_pki_ed25519_import_privkey_base64_comment(void **state)
{
    int rc, file_str_len;
    const char *comment_str = "#this is line-comment\n#this is another\n";
    char *key_str = NULL, *file_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ED25519_TESTKEY);
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
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    free(file_str);
    SSH_KEY_FREE(key);

}

static void torture_pki_ed25519_import_privkey_base64_whitespace(void **state)
{
    int rc, file_str_len;
    const char *whitespace_str = "      \n\t\t\t\t\t\n\n\n\n\n";
    char *key_str = NULL, *file_str = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = torture_pki_read_file(LIBSSH_ED25519_TESTKEY);
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
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    free(file_str);
    SSH_KEY_FREE(key);

}

static void torture_pki_ed25519_import_export_privkey_base64(void **state)
{
    char *b64_key = NULL;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    enum ssh_keytypes_e type;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_base64(torture_get_openssh_testkey(SSH_KEYTYPE_ED25519,
                                                                   false),
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    rc = ssh_pki_export_privkey_base64(key,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &b64_key);
    assert_return_code(rc, errno);
    assert_non_null(b64_key);
    SSH_KEY_FREE(key);

    rc = ssh_pki_import_privkey_base64(b64_key,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_return_code(rc, errno);
    assert_non_null(key);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    SSH_STRING_FREE_CHAR(b64_key);
    SSH_KEY_FREE(key);
}

static void torture_pki_ed25519_publickey_from_privatekey(void **state)
{
    int rc;
    ssh_key key = NULL;
    ssh_key pubkey = NULL;
    const char *passphrase = NULL;
    const char *keystring = NULL;

    (void) state; /* unused */

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0);
    rc = ssh_pki_import_privkey_base64(keystring,
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

static void torture_pki_ed25519_import_cert_file(void **state)
{
    int rc;
    ssh_key cert = NULL;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    rc = ssh_pki_import_cert_file(LIBSSH_ED25519_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    type = ssh_key_type(cert);
    assert_true(type == SSH_KEYTYPE_ED25519_CERT01);

    rc = ssh_key_is_public(cert);
    assert_true(rc == 1);

    SSH_KEY_FREE(cert);
}

static void torture_pki_ed25519_publickey_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key = NULL, *key_buf = NULL, *p = NULL;
    const char *q = NULL;
    ssh_key key = NULL;
    int rc;

    (void) state; /* unused */

    key_buf = strdup(torture_get_testkey_pub(SSH_KEYTYPE_ED25519));
    assert_non_null(key_buf);

    q = p = key_buf;
    while (p != NULL && *p != '\0' && *p != ' ') p++;
    if (p != NULL) {
        *p = '\0';
    }

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ED25519);

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

static void torture_pki_ed25519_generate_pubkey_from_privkey(void **state)
{
    char pubkey_generated[4096] = {0};
    ssh_key privkey = NULL;
    ssh_key pubkey = NULL;
    int rc;
    int len;

    (void) state; /* unused */

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ED25519_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ED25519_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ED25519_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    len = torture_pubkey_len(torture_get_testkey_pub(SSH_KEYTYPE_ED25519));
    assert_memory_equal(torture_get_testkey_pub(SSH_KEYTYPE_ED25519),
                        pubkey_generated,
                        len);

    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(pubkey);
}

static void torture_pki_ed25519_generate_key(void **state)
{
    int rc;
    ssh_key key = NULL, pubkey = NULL;
    ssh_signature sign = NULL;
    enum ssh_keytypes_e type = SSH_KEYTYPE_UNKNOWN;
    const char *type_char = NULL;
    ssh_session session=ssh_new();
    uint8_t *raw_sig_data = NULL;
    (void) state;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(session);

    rc = ssh_pki_generate(SSH_KEYTYPE_ED25519, 256, &key);
    assert_true(rc == SSH_OK);
    assert_non_null(key);
    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(pubkey);
    sign = pki_do_sign(key, HASH, 20, SSH_DIGEST_AUTO);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, pubkey, HASH, 20);
    assert_true(rc == SSH_OK);
    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_ED25519);
    type_char = ssh_key_type_to_char(type);
    assert_true(strcmp(type_char, "ssh-ed25519") == 0);

    /* try an invalid signature */
#ifdef HAVE_OPENSSL_ED25519
    raw_sig_data = ssh_string_data(sign->raw_sig);
#else
    raw_sig_data = (uint8_t *)sign->ed25519_sig;
#endif
    assert_non_null(raw_sig_data);
    (raw_sig_data)[3]^= 0xff;
    rc = ssh_pki_signature_verify(session, sign, pubkey, HASH, 20);
    assert_true(rc == SSH_ERROR);

    ssh_signature_free(sign);
    SSH_KEY_FREE(key);
    SSH_KEY_FREE(pubkey);

    ssh_free(session);
}

static void torture_pki_ed25519_cert_verify(void **state)
{
    int rc;
    ssh_key privkey = NULL, cert = NULL;
    ssh_signature sign = NULL;
    ssh_session session=ssh_new();
    (void) state;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    assert_non_null(session);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_pki_import_cert_file(LIBSSH_ED25519_TESTKEY "-cert.pub", &cert);
    assert_true(rc == 0);
    assert_non_null(cert);

    sign = pki_do_sign(privkey, HASH, 20, SSH_DIGEST_AUTO);
    assert_non_null(sign);
    rc = ssh_pki_signature_verify(session, sign, cert, HASH, 20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(cert);

    ssh_free(session);
}

static void torture_pki_ed25519_write_privkey(void **state)
{
    ssh_key origkey = NULL;
    ssh_key privkey = NULL;
    int rc;

    (void) state; /* unused */

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_ED25519_TESTKEY);

    rc = ssh_pki_export_privkey_file(origkey,
            NULL,
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    unlink(LIBSSH_ED25519_TESTKEY);
    SSH_KEY_FREE(privkey);
    /* do the same with passphrase */
    rc = ssh_pki_export_privkey_file(origkey,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            LIBSSH_ED25519_TESTKEY);
    assert_true(rc == 0);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            NULL,
            NULL,
            NULL,
            &privkey);
    /* opening without passphrase should fail */
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY,
            torture_get_testkey_passphrase(),
            NULL,
            NULL,
            &privkey);
    assert_true(rc == 0);
    assert_non_null(privkey);

    rc = ssh_key_cmp(origkey, privkey, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);
    unlink(LIBSSH_ED25519_TESTKEY);

    SSH_KEY_FREE(origkey);
    SSH_KEY_FREE(privkey);

    /* Test with passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     &origkey);
    assert_true(rc == 0);
    assert_non_null(origkey);

    unlink(LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    rc = ssh_pki_export_privkey_file(origkey,
                                     torture_get_testkey_passphrase(),
                                     NULL,
                                     NULL,
                                     LIBSSH_ED25519_TESTKEY_PASSPHRASE);
    assert_true(rc == 0);

    /* Test with invalid passphrase */
    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
                                     "invalid secret",
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == SSH_ERROR);

    rc = ssh_pki_import_privkey_file(LIBSSH_ED25519_TESTKEY_PASSPHRASE,
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

static void torture_pki_ed25519_sign(void **state)
{
    ssh_key privkey = NULL;
    ssh_signature sig = NULL;
    ssh_string blob = NULL;
    const char *keystring = NULL;
    int rc;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    (void)state;

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0);
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey);

    sig = pki_do_sign(privkey, HASH, sizeof(HASH), SSH_DIGEST_AUTO);
    assert_non_null(sig);

    blob = pki_signature_to_blob(sig);
    assert_non_null(blob);

    assert_int_equal(ssh_string_len(blob), sizeof(ref_signature));
    assert_memory_equal(ssh_string_data(blob), ref_signature,
                        sizeof(ref_signature));

    ssh_signature_free(sig);
    SSH_KEY_FREE(privkey);
    SSH_STRING_FREE(blob);

}

static void torture_pki_ed25519_sign_openssh_privkey_passphrase(void **state)
{
    ssh_key privkey = NULL;
    ssh_signature sig = NULL;
    ssh_string blob = NULL;
    const char *keystring = NULL;
    int rc;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    (void)state;

    keystring = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 1);
    rc = ssh_pki_import_privkey_base64(keystring,
                                       torture_get_testkey_passphrase(),
                                       NULL,
                                       NULL,
                                       &privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey);

    sig = pki_do_sign(privkey, HASH, sizeof(HASH), SSH_DIGEST_AUTO);
    assert_non_null(sig);

    blob = pki_signature_to_blob(sig);
    assert_non_null(blob);
    assert_int_equal(ssh_string_len(blob), sizeof(ref_signature));
    assert_memory_equal(ssh_string_data(blob), ref_signature,
                        sizeof(ref_signature));

    ssh_signature_free(sig);
    SSH_KEY_FREE(privkey);
    SSH_STRING_FREE(blob);
}

#ifdef HAVE_OPENSSL_ED25519
static void torture_pki_ed25519_sign_pkcs8_privkey(void **state)
{
    ssh_key privkey = NULL;
    ssh_signature sig = NULL;
    ssh_string blob = NULL;
    const char *keystring = NULL;
    int rc;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    (void)state;

    keystring = torture_get_testkey(SSH_KEYTYPE_ED25519, 0);
    rc = ssh_pki_import_privkey_base64(keystring,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey);

    sig = pki_do_sign(privkey, HASH, sizeof(HASH), SSH_DIGEST_AUTO);
    assert_non_null(sig);

    blob = pki_signature_to_blob(sig);
    assert_non_null(blob);
    assert_int_equal(ssh_string_len(blob), sizeof(ref_signature));
    assert_memory_equal(ssh_string_data(blob), ref_signature,
                        sizeof(ref_signature));

    ssh_signature_free(sig);
    SSH_KEY_FREE(privkey);
    SSH_STRING_FREE(blob);
}

static void torture_pki_ed25519_sign_pkcs8_privkey_passphrase(void **state)
{
    ssh_key privkey = NULL;
    ssh_signature sig = NULL;
    ssh_string blob = NULL;
    const char *keystring = NULL;
    int rc;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    (void)state;

    keystring = torture_get_testkey(SSH_KEYTYPE_ED25519, 1);
    rc = ssh_pki_import_privkey_base64(keystring,
                                       torture_get_testkey_passphrase(),
                                       NULL,
                                       NULL,
                                       &privkey);
    assert_true(rc == SSH_OK);
    assert_non_null(privkey);

    sig = pki_do_sign(privkey, HASH, sizeof(HASH), SSH_DIGEST_AUTO);
    assert_non_null(sig);

    blob = pki_signature_to_blob(sig);
    assert_non_null(blob);
    assert_int_equal(ssh_string_len(blob), sizeof(ref_signature));
    assert_memory_equal(ssh_string_data(blob), ref_signature,
                        sizeof(ref_signature));

    ssh_signature_free(sig);
    SSH_KEY_FREE(privkey);
    SSH_STRING_FREE(blob);
}
#endif /* HAVE_OPENSSL_ED25519 */

static void torture_pki_ed25519_verify(void **state){
    ssh_key pubkey = NULL;
    ssh_signature sig = NULL;
    ssh_session session = NULL;
    ssh_string blob = ssh_string_new(ED25519_SIG_LEN);
    char *pkey_ptr = strdup(strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519), ' ') + 1);
    char *ptr = NULL;
    uint8_t *raw_sig_data = NULL;
    int rc;
    (void) state;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    session = ssh_new();
    assert_non_null(session);

    /* remove trailing comment */
    ptr = strchr(pkey_ptr, ' ');
    if(ptr != NULL){
        *ptr = '\0';
    }
    rc = ssh_pki_import_pubkey_base64(pkey_ptr, SSH_KEYTYPE_ED25519, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    ssh_string_fill(blob, ref_signature, ED25519_SIG_LEN);
    sig = pki_signature_from_blob(pubkey, blob, SSH_KEYTYPE_ED25519, SSH_DIGEST_AUTO);
    assert_non_null(sig);

    rc = ssh_pki_signature_verify(session, sig, pubkey, HASH, sizeof(HASH));
    assert_true(rc == SSH_OK);

    /* Alter signature and expect verification error */
#if defined(HAVE_OPENSSL_ED25519)
    raw_sig_data = ssh_string_data(sig->raw_sig);
#else
    raw_sig_data = (uint8_t *)sig->ed25519_sig;
#endif
    assert_non_null(raw_sig_data);
    (raw_sig_data)[3]^= 0xff;
    rc = ssh_pki_signature_verify(session, sig, pubkey, HASH, sizeof(HASH));
    assert_true(rc == SSH_ERROR);

    ssh_signature_free(sig);

    SSH_KEY_FREE(pubkey);
    SSH_STRING_FREE(blob);
    free(pkey_ptr);
    ssh_free(session);
}

static void torture_pki_ed25519_verify_bad(void **state){
    ssh_key pubkey = NULL;
    ssh_signature sig = NULL;
    ssh_session session = NULL;
    ssh_string blob = ssh_string_new(ED25519_SIG_LEN);
    char *pkey_ptr = strdup(strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519), ' ') + 1);
    char *ptr = NULL;
    int rc;
    int i;
    (void) state;

    /* Skip test if in FIPS mode */
    if (ssh_fips_mode()) {
        skip();
    }

    session = ssh_new();
    assert_non_null(session);

    /* remove trailing comment */
    ptr = strchr(pkey_ptr, ' ');
    if(ptr != NULL){
        *ptr = '\0';
    }
    rc = ssh_pki_import_pubkey_base64(pkey_ptr, SSH_KEYTYPE_ED25519, &pubkey);
    assert_true(rc == SSH_OK);
    assert_non_null(pubkey);

    /* alter signature and expect false result */

    for (i=0; i < ED25519_SIG_LEN; ++i){
        ssh_string_fill(blob, ref_signature, ED25519_SIG_LEN);
        ((uint8_t *)ssh_string_data(blob))[i] ^= 0xff;
        sig = pki_signature_from_blob(pubkey, blob, SSH_KEYTYPE_ED25519, SSH_DIGEST_AUTO);
        assert_non_null(sig);

        rc = ssh_pki_signature_verify(session, sig, pubkey, HASH, sizeof(HASH));
        assert_true(rc == SSH_ERROR);
        ssh_signature_free(sig);

    }
    SSH_KEY_FREE(pubkey);
    SSH_STRING_FREE(blob);
    free(pkey_ptr);
    ssh_free(session);
}

static void torture_pki_ed25519_import_privkey_base64_passphrase(void **state)
{
    int rc;
    ssh_key key = NULL;
    const char *passphrase = torture_get_testkey_passphrase();
    const char *testkey = NULL;

    (void) state; /* unused */

    /* same for ED25519 */
    testkey = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 1);
    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);
    assert_non_null(key);

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
}

static void torture_pki_ed25519_privkey_dup(void **state)
{
    const char *passphrase = torture_get_testkey_passphrase();
    ssh_key key = NULL;
    ssh_key dup = NULL;
    const char *testkey = NULL;
    int rc;

    (void) state; /* unused */

    testkey = torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 1);
    rc = ssh_pki_import_privkey_base64(testkey,
                                       passphrase,
                                       NULL,
                                       NULL,
                                       &key);
    assert_true(rc == 0);
    assert_non_null(key);

    rc = ssh_key_is_private(key);
    assert_true(rc == 1);

    dup = ssh_key_dup(key);
    assert_non_null(dup);

    SSH_KEY_FREE(key);
    SSH_KEY_FREE(dup);
}

static void torture_pki_ed25519_pubkey_dup(void **state)
{
    ssh_key pubkey = NULL;
    ssh_key dup = NULL;
    const char *p = strchr(torture_get_testkey_pub(SSH_KEYTYPE_ED25519), ' ');
    char *pub_str = NULL;
    char *q = NULL;
    int rc;

    (void) state; /* unused */

    pub_str = strdup(p + 1);
    assert_non_null(pub_str);

    q = strchr(pub_str, ' ');
    assert_non_null(q);
    *q = '\0';

    rc = ssh_pki_import_pubkey_base64(pub_str,
                                      SSH_KEYTYPE_ED25519,
                                      &pubkey);
    assert_true(rc == 0);
    assert_non_null(pubkey);

    rc = ssh_key_is_public(pubkey);
    assert_true(rc == 1);

    dup = ssh_key_dup(pubkey);
    assert_non_null(dup);

    rc = ssh_key_is_public(dup);
    assert_true(rc == 1);

    SAFE_FREE(pub_str);
    SSH_KEY_FREE(pubkey);
    SSH_KEY_FREE(dup);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_pubkey_file,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_pubkey_from_openssh_privkey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_privkey_base64,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_privkey_base64_comment,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_privkey_base64_whitespace,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_export_privkey_base64,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_publickey_from_privatekey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_import_cert_file,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_publickey_base64,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_generate_pubkey_from_privkey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test(torture_pki_ed25519_generate_key),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_cert_verify,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_pki_ed25519_write_privkey,
                                        setup_ed25519_key,
                                        teardown),
        cmocka_unit_test(torture_pki_ed25519_import_privkey_base64_passphrase),
        cmocka_unit_test(torture_pki_ed25519_sign),
        cmocka_unit_test(torture_pki_ed25519_sign_openssh_privkey_passphrase),
#ifdef HAVE_OPENSSL_ED25519
        cmocka_unit_test(torture_pki_ed25519_sign_pkcs8_privkey),
        cmocka_unit_test(torture_pki_ed25519_sign_pkcs8_privkey_passphrase),
#endif
        cmocka_unit_test(torture_pki_ed25519_verify),
        cmocka_unit_test(torture_pki_ed25519_verify_bad),
        cmocka_unit_test(torture_pki_ed25519_privkey_dup),
        cmocka_unit_test(torture_pki_ed25519_pubkey_dup),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
