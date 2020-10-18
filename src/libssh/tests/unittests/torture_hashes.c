#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "torture_key.h"
#include "legacy.c"
#include "dh.c"

static int setup_rsa_key(void **state)
{
    int rc=0;
    enum ssh_keytypes_e type;
    char *b64_key, *p;
    ssh_key key;

    const char *q;

    b64_key = strdup(torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    assert_non_null(b64_key);

    q = p = b64_key;
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

    free(b64_key);
    *state = key;

    return 0;
}

static int teardown(void **state)
{
    SSH_KEY_FREE(*state);
    return 0;
}

static void torture_md5_hash(void **state)
{
    ssh_key pubkey = *state;
    char *hash = NULL;
    char *hexa = NULL;
    size_t hlen;
    int rc = 0;

    if (ssh_fips_mode()) {
        skip();
    }

    rc = ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_MD5,
                                (unsigned char **)&hash, &hlen);
    if (ssh_fips_mode()) {
        /* When in FIPS mode, expect the call to fail */
        assert_int_equal(rc, SSH_ERROR);
    } else {
        assert_int_equal(rc, SSH_OK);

        hexa = ssh_get_hexa((unsigned char *)hash, hlen);
        SSH_STRING_FREE_CHAR(hash);
        assert_string_equal(hexa,
                            "50:15:a0:9b:92:bf:33:1c:01:c5:8c:fe:18:fa:ce:78");

        SSH_STRING_FREE_CHAR(hexa);
    }
}

static void torture_sha1_hash(void **state)
{
    ssh_key pubkey = *state;
    char *hash = NULL;
    char *sha1 = NULL;
    int rc = 0;
    size_t hlen;

    rc = ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA1,
                                (unsigned char **)&hash, &hlen);
    assert_true(rc == 0);

    sha1 = ssh_get_b64_unpadded((unsigned char *)hash, hlen);
    SSH_STRING_FREE_CHAR(hash);
    assert_string_equal(sha1, "6wP+houujQmxLBiFugTcoeoODCM");

    SSH_STRING_FREE_CHAR(sha1);
}

static void torture_sha256_hash(void **state)
{
    ssh_key pubkey = *state;
    char *hash = NULL;
    char *sha256 = NULL;
    int rc = 0;
    size_t hlen;

    rc = ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA256,
                                (unsigned char **)&hash, &hlen);
    assert_true(rc == 0);

    sha256 = ssh_get_b64_unpadded((unsigned char *)hash, hlen);
    SSH_STRING_FREE_CHAR(hash);
    assert_string_equal(sha256, "jXstVLLe84fSDo1kEYGn6iumnPCSorhaiWxnJz8VTII");

    SSH_STRING_FREE_CHAR(sha256);

}

static void torture_sha256_fingerprint(void **state)
{
    ssh_key pubkey = *state;
    char *hash = NULL;
    char *sha256 = NULL;
    int rc = 0;
    size_t hlen;

    rc = ssh_get_publickey_hash(pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                (unsigned char **)&hash,
                                &hlen);
    assert_true(rc == 0);

    sha256 = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256,
                                      (unsigned char *)hash,
                                      hlen);
    SSH_STRING_FREE_CHAR(hash);
    assert_string_equal(sha256,
                        "SHA256:jXstVLLe84fSDo1kEYGn6iumnPCSorhaiWxnJz8VTII");

    SSH_STRING_FREE_CHAR(sha256);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_md5_hash,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_sha1_hash,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_sha256_hash,
                                        setup_rsa_key,
                                        teardown),
        cmocka_unit_test_setup_teardown(torture_sha256_fingerprint,
                                        setup_rsa_key,
                                        teardown),
    };

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc;
}
