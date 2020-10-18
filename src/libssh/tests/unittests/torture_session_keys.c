#include "config.h"

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/bignum.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"

uint8_t key[32] =
    "\xf7\xa0\xe6\xdf\x1f\x87\x7d\x22\x68\xd2\xc4\xb0\xc5\x93\xa4"
    "\x8e\x30\x17\xc6\xab\xca\xf3\x9a\xa4\x9f\x7b\xed\x51\xb1\xe8"
    "\x8a\x42";
uint8_t secret[32] =
    "\x33\x64\x8e\x7f\xea\xd9\xd7\xee\x89\x4f\xd8\xd0\xe5\x83\x00"
    "\x3d\x53\x17\xbc\xa8\x8b\x6b\x2a\x31\x50\xcc\x08\xe9\xea\x87"
    "\xb4\x23";

uint8_t eIV[32] =
    "\x9a\x2b\x40\x9d\x29\x8e\x22\x70\x86\xdf\x0e\x72\x9b\x91\x31"
    "\x90\x5d\x69\xc5\x87\x79\x83\x72\x63\x4e\x67\xf5\x9e\x00\x77"
    "\x8c\x7f";
uint8_t dIV[32] =
    "\x10\xdd\x7f\x31\x6d\xe3\x49\x28\xbf\x99\x80\x08\x16\xb3\x99"
    "\xff\x8c\x61\x9b\xb9\xc2\xdd\x40\xfb\x36\xf9\x97\xd8\x8c\x55"
    "\xbf\xa0";
uint8_t eK[24] =
    "\xe1\x99\x36\xb8\xe6\x1f\x3d\x54\xc3\xa2\xdd\x79\xf0\xfe\x78"
    "\x9e\x87\xd5\x05\x54\x26\x34\x21\xd0";
uint8_t dK[24] =
    "\xf8\xdd\xc3\xea\x5a\x59\x98\xb9\x86\xaa\x77\x29\x67\x51\x46"
    "\x21\x73\xc2\x6a\x6b\xed\xf2\x49\x98";
uint8_t eMAC[32] =
    "\x0f\xbd\x1f\xe9\x2a\xaa\x84\xdc\xb5\xfc\xfb\x68\x2c\xa5\xe0"
    "\xba\xf2\x6f\xe5\x80\xee\x8f\x5c\x5b\x30\x55\x25\xb3\x7b\x21"
    "\xdc\xe5";
uint8_t dMAC[32] =
    "\xa3\x52\x6e\x72\xa8\x8b\xde\xc5\x68\x66\x89\xae\x0a\xd2\x83"
    "\x23\x21\x4b\x3f\x04\x2e\x7f\x86\x04\x0f\xa8\x04\x3c\x62\xad"
    "\x74\x91";

struct ssh_cipher_struct fake_in_cipher = {
    .keysize = 192
};

struct ssh_cipher_struct fake_out_cipher = {
    .keysize = 192
};

struct ssh_crypto_struct test_crypto = {
    .digest_len = 32,
    .session_id = secret,
    .secret_hash = secret,
    .in_cipher = &fake_in_cipher,
    .out_cipher = &fake_out_cipher,
    .in_hmac = SSH_HMAC_SHA256,
    .out_hmac = SSH_HMAC_SHA256,
    .digest_type = SSH_KDF_SHA256,
};

struct ssh_session_struct session = {
    .next_crypto = &test_crypto
};

static void torture_session_keys(UNUSED_PARAM(void **state))
{
    ssh_string k_string;
    int rc;

    k_string = ssh_string_new(32);
    ssh_string_fill(k_string, key, 32);
    test_crypto.shared_secret = ssh_make_string_bn(k_string);

    rc = ssh_generate_session_keys(&session);
    assert_int_equal(rc, 0);

    assert_memory_equal(test_crypto.encryptIV, eIV, 32);
    assert_memory_equal(test_crypto.decryptIV, dIV, 32);
    assert_memory_equal(test_crypto.encryptkey, eK, 24);
    assert_memory_equal(test_crypto.decryptkey, dK, 24);
    assert_memory_equal(test_crypto.encryptMAC, eMAC, 32);
    assert_memory_equal(test_crypto.decryptMAC, dMAC, 32);

    SSH_STRING_FREE(k_string);
}

int torture_run_tests(void) {
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_session_keys),
    };

    ssh_init();
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
