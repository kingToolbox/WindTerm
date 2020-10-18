#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <fcntl.h>

#include "torture.h"
#include "torture_pki.h"
#include "torture_key.h"
#include "pki.c"

const unsigned char INPUT[] = "1234567890123456789012345678901234567890"
                              "123456789012345678901234";

const char template[] = "temp_dir_XXXXXX";

struct pki_st {
    char *cwd;
    char *temp_dir;
};

static int setup_cert_dir(void **state)
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

    return 0;
}

static int teardown_cert_dir(void **state) {

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

static void torture_pki_keytype(void **state) {
    enum ssh_keytypes_e type;
    const char *type_c;

    (void) state; /* unused */

    type = ssh_key_type(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name("42");
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type_c = ssh_key_type_to_char(SSH_KEYTYPE_UNKNOWN);
    assert_null(type_c);

    type_c = ssh_key_type_to_char(42);
    assert_null(type_c);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_non_null(sig);

    ssh_signature_free(sig);
}

struct key_attrs {
    int sign;
    int verify;
    const char *type_c;
    int size_arg;
    int sig_length;
    const char *sig_type_c;
    int expect_success;
};

struct key_attrs key_attrs_list[][5] = {
    {
        {0, 0, "", 0, 0, "", 0}, /* UNKNOWN, AUTO */
        {0, 0, "", 0, 0, "", 0}, /* UNKNOWN, SHA1 */
        {0, 0, "", 0, 0, "", 0}, /* UNKNOWN, SHA256 */
        {0, 0, "", 0, 0, "", 0}, /* UNKNOWN, SHA384 */
        {0, 0, "", 0, 0, "", 0}, /* UNKNOWN, SHA512 */
    },
#ifdef HAVE_DSA
    {
        {1, 1, "ssh-dss", 1024, 0, "", 0},         /* DSS, AUTO */
        {1, 1, "ssh-dss", 1024, 20, "ssh-dss", 1}, /* DSS, SHA1 */
        {1, 1, "ssh-dss", 1024, 0, "", 0},         /* DSS, SHA256 */
        {1, 1, "ssh-dss", 1024, 0, "", 0},         /* DSS, SHA384 */
        {1, 1, "ssh-dss", 1024, 0, "", 0},         /* DSS, SHA512 */
    },
#else
    {
        {0, 0, "", 0, 0, "", 0}, /* DSS, AUTO */
        {0, 0, "", 0, 0, "", 0}, /* DSS, SHA1 */
        {0, 0, "", 0, 0, "", 0}, /* DSS, SHA256 */
        {0, 0, "", 0, 0, "", 0}, /* DSS, SHA384 */
        {0, 0, "", 0, 0, "", 0}, /* DSS, SHA512 */
    },
#endif /* HAVE_DSA */
    {
        {1, 1, "ssh-rsa", 2048, 0, "", 0},              /* RSA, AUTO */
        {1, 1, "ssh-rsa", 2048, 20, "ssh-rsa", 1},      /* RSA, SHA1 */
        {1, 1, "ssh-rsa", 2048, 32, "rsa-sha2-256", 1}, /* RSA, SHA256 */
        {1, 1, "ssh-rsa", 2048, 0, "", 0},              /* RSA, SHA384 */
        {1, 1, "ssh-rsa", 2048, 64, "rsa-sha2-512", 1}, /* RSA, SHA512 */
    },
    {
        {0, 0, "", 0, 0, "", 0}, /* RSA1, AUTO */
        {0, 0, "", 0, 0, "", 0}, /* RSA1, SHA1 */
        {0, 0, "", 0, 0, "", 0}, /* RSA1, SHA256 */
        {0, 0, "", 0, 0, "", 0}, /* RSA1, SHA384 */
        {0, 0, "", 0, 0, "", 0}, /* RSA1, SHA512 */
    },
    {
        {0, 1, "", 256, 0, "", 0}, /* ECDSA, AUTO */
        {0, 1, "", 256, 0, "", 0}, /* ECDSA, SHA1 */
        {0, 1, "", 256, 0, "", 0}, /* ECDSA, SHA256 */
        {0, 1, "", 384, 0, "", 0}, /* ECDSA, SHA384 */
        {0, 1, "", 521, 0, "", 0}, /* ECDSA, SHA512 */
    },
    {
        {1, 1, "ssh-ed25519", 0, 33, "ssh-ed25519", 1}, /* ED25519, AUTO */
        {1, 1, "ssh-ed25519", 0, 0, "", 0},             /* ED25519, SHA1 */
        {1, 1, "ssh-ed25519", 0, 0, "", 0},             /* ED25519, SHA256 */
        {1, 1, "ssh-ed25519", 0, 0, "", 0},             /* ED25519, SHA384 */
        {1, 1, "ssh-ed25519", 0, 0, "", 0},             /* ED25519, SHA512 */
    },
#ifdef HAVE_DSA
    {
        {0, 1, "", 0, 0, "", 0}, /* DSS CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* DSS CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* DSS CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* DSS CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* DSS CERT, SHA512 */
    },
#else
    {
        {0, 0, "", 0, 0, "", 0}, /* DSS CERT, AUTO */
        {0, 0, "", 0, 0, "", 0}, /* DSS CERT, SHA1 */
        {0, 0, "", 0, 0, "", 0}, /* DSS CERT, SHA256 */
        {0, 0, "", 0, 0, "", 0}, /* DSS CERT, SHA384 */
        {0, 0, "", 0, 0, "", 0}, /* DSS CERT, SHA512 */
    },
#endif /* HAVE_DSA */
    {
        {0, 1, "", 0, 0, "", 0}, /* RSA CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* RSA CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* RSA CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* RSA CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* RSA CERT, SHA512 */
    },
#ifdef HAVE_ECC
    {
        {1, 1, "ecdsa-sha2-nistp256", 256, 0, "", 0},                     /* ECDSA P256, AUTO */
        {1, 1, "ecdsa-sha2-nistp256", 256, 0, "", 0},                     /* ECDSA P256, SHA1 */
        {1, 1, "ecdsa-sha2-nistp256", 256, 32, "ecdsa-sha2-nistp256", 1}, /* ECDSA P256, SHA256 */
        {1, 1, "ecdsa-sha2-nistp256", 256, 0, "", 0},                     /* ECDSA P256, SHA384 */
        {1, 1, "ecdsa-sha2-nistp256", 256, 0, "", 0},                     /* ECDSA P256, SHA512 */
    },
    {
        {1, 1, "ecdsa-sha2-nistp384", 384, 0, "", 0},                     /* ECDSA P384, AUTO */
        {1, 1, "ecdsa-sha2-nistp384", 384, 0, "", 0},                     /* ECDSA P384, SHA1 */
        {1, 1, "ecdsa-sha2-nistp384", 384, 0, "", 0},                     /* ECDSA P384, SHA256 */
        {1, 1, "ecdsa-sha2-nistp384", 384, 48, "ecdsa-sha2-nistp384", 1}, /* ECDSA P384, SHA384 */
        {1, 1, "ecdsa-sha2-nistp384", 384, 0, "", 0},                     /* ECDSA P384, SHA512 */
    },
    {
        {1, 1, "ecdsa-sha2-nistp521", 521, 0, "", 0},                     /* ECDSA P521, AUTO */
        {1, 1, "ecdsa-sha2-nistp521", 521, 0, "", 0},                     /* ECDSA P521, SHA1 */
        {1, 1, "ecdsa-sha2-nistp521", 521, 0, "", 0},                     /* ECDSA P521, SHA256 */
        {1, 1, "ecdsa-sha2-nistp521", 521, 0, "", 0},                     /* ECDSA P521, SHA384 */
        {1, 1, "ecdsa-sha2-nistp521", 521, 64, "ecdsa-sha2-nistp521", 1}, /* ECDSA P521, SHA512 */
    },
    {
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P256 CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P256 CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P256 CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P256 CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P256 CERT, SHA512 */
    },
    {
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P384 CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P384 CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P384 CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P384 CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P384 CERT, SHA512 */
    },
    {
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P521 CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P521 CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P521 CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P521 CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* ECDSA P521 CERT, SHA512 */
    },
#endif /* HAVE_ECC */
    {
        {0, 1, "", 0, 0, "", 0}, /* ED25519 CERT, AUTO */
        {0, 1, "", 0, 0, "", 0}, /* ED25519 CERT, SHA1 */
        {0, 1, "", 0, 0, "", 0}, /* ED25519 CERT, SHA256 */
        {0, 1, "", 0, 0, "", 0}, /* ED25519 CERT, SHA384 */
        {0, 1, "", 0, 0, "", 0}, /* ED25519 CERT, SHA512 */
    },
};

/* This tests all the base types and their signatures against each other */
static void torture_pki_verify_mismatch(void **state)
{
    int rc;
    int verbosity = torture_libssh_verbosity();
    ssh_key key = NULL, verify_key = NULL, pubkey = NULL, verify_pubkey = NULL;
    ssh_signature sign = NULL, import_sig = NULL, new_sig = NULL;
    ssh_string blob;
    ssh_session session = ssh_new();
    enum ssh_keytypes_e key_type, sig_type;
    enum ssh_digest_e hash;
    size_t input_length = sizeof(INPUT);
    struct key_attrs skey_attrs, vkey_attrs;

    (void) state;

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    for (sig_type = SSH_KEYTYPE_DSS;
         sig_type <= SSH_KEYTYPE_ED25519_CERT01;
         sig_type++)
    {
        for (hash = SSH_DIGEST_AUTO;
             hash <= SSH_DIGEST_SHA512;
             hash++)
        {
            if (ssh_fips_mode()) {
                if (sig_type == SSH_KEYTYPE_DSS ||
                    sig_type == SSH_KEYTYPE_ED25519 ||
                    hash == SSH_DIGEST_SHA1)
                {
                    /* In FIPS mode, skip unsupported algorithms */
                    continue;
                }
            }

            skey_attrs = key_attrs_list[sig_type][hash];

            if (!skey_attrs.sign) {
                continue;
            }

            rc = ssh_pki_generate(sig_type, skey_attrs.size_arg, &key);
            assert_true(rc == SSH_OK);
            assert_non_null(key);
            assert_int_equal(key->type, sig_type);
            assert_string_equal(key->type_c, skey_attrs.type_c);

            SSH_LOG(SSH_LOG_TRACE, "Creating signature %d with hash %d",
                    sig_type, hash);

            if (skey_attrs.expect_success == 0) {
                /* Expect error */
                sign = pki_do_sign(key, INPUT, input_length, hash);
                assert_null(sign);

                SSH_KEY_FREE(key);
                continue;
            }

            rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
            assert_int_equal(rc, SSH_OK);
            assert_non_null(pubkey);

            /* Create a valid signature using this key */
            sign = pki_do_sign(key, INPUT, input_length, hash);
            assert_non_null(sign);
            assert_int_equal(sign->type, key->type);
            assert_string_equal(sign->type_c, skey_attrs.sig_type_c);

            /* Create a signature blob that can be imported and verified */
            blob = pki_signature_to_blob(sign);
            assert_non_null(blob);

            /* Import and verify with current key
             * (this is not tested anywhere else yet) */
            import_sig = pki_signature_from_blob(key,
                                                 blob,
                                                 sig_type,
                                                 hash);
            assert_non_null(import_sig);
            assert_int_equal(import_sig->type, key->type);
            assert_string_equal(import_sig->type_c, skey_attrs.sig_type_c);

            rc = ssh_pki_signature_verify(session,
                                      import_sig,
                                      pubkey,
                                      INPUT,
                                      input_length);
            assert_true(rc == SSH_OK);

            for (key_type = SSH_KEYTYPE_DSS;
                 key_type <= SSH_KEYTYPE_ED25519_CERT01;
                 key_type++)
            {
                if (ssh_fips_mode()) {
                    if (key_type == SSH_KEYTYPE_DSS ||
                        key_type == SSH_KEYTYPE_ED25519)
                    {
                        /* In FIPS mode, skip unsupported algorithms */
                        continue;
                    }
                }

                vkey_attrs = key_attrs_list[key_type][hash];
                if (!vkey_attrs.verify) {
                    continue;
                }

                SSH_LOG(SSH_LOG_TRACE, "Trying key %d with signature %d",
                        key_type, sig_type);

                if (is_cert_type(key_type)) {
                    torture_write_file("libssh_testkey-cert.pub",
                       torture_get_testkey_pub(key_type));
                    rc = ssh_pki_import_cert_file("libssh_testkey-cert.pub", &verify_pubkey);
                    verify_key = NULL;
                } else {
                    rc = ssh_pki_generate(key_type, vkey_attrs.size_arg, &verify_key);
                    assert_int_equal(rc, SSH_OK);
                    assert_non_null(verify_key);
                    rc = ssh_pki_export_privkey_to_pubkey(verify_key, &verify_pubkey);
                }
                assert_int_equal(rc, SSH_OK);
                assert_non_null(verify_pubkey);

                /* Should gracefully fail, but not crash */
                rc = ssh_pki_signature_verify(session,
                                          sign,
                                          verify_pubkey,
                                          INPUT,
                                          input_length);
                assert_true(rc != SSH_OK);

                /* Try the same with the imported signature */
                rc = ssh_pki_signature_verify(session,
                                          import_sig,
                                          verify_pubkey,
                                          INPUT,
                                          input_length);
                assert_true(rc != SSH_OK);

                /* Try to import the signature blob with different key */
                new_sig = pki_signature_from_blob(verify_pubkey,
                                                  blob,
                                                  sig_type,
                                                  import_sig->hash_type);
                if (ssh_key_type_plain(verify_pubkey->type) == sig_type) {
                    /* Importing with the same key type should work */
                    assert_non_null(new_sig);
                    assert_int_equal(new_sig->type, key->type);
                    assert_string_equal(new_sig->type_c, skey_attrs.sig_type_c);

                    /* The verification should not work */
                    rc = ssh_pki_signature_verify(session,
                                              new_sig,
                                              verify_pubkey,
                                              INPUT,
                                              input_length);
                    assert_true(rc != SSH_OK);

                    ssh_signature_free(new_sig);
                } else {
                    assert_null(new_sig);
                }
                SSH_KEY_FREE(verify_key);
                SSH_KEY_FREE(verify_pubkey);
            }

            ssh_string_free(blob);
            ssh_signature_free(sign);
            ssh_signature_free(import_sig);

            SSH_KEY_FREE(key);
            SSH_KEY_FREE(pubkey);
            key = NULL;
        }
    }

    ssh_free(session);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_pki_keytype),
        cmocka_unit_test(torture_pki_signature),
        cmocka_unit_test_setup_teardown(torture_pki_verify_mismatch,
                                        setup_cert_dir,
                                        teardown_cert_dir),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
