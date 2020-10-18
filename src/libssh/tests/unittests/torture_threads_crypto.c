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

#include "torture.h"
#include "libssh/crypto.h"

#include <pthread.h>

#define NUM_THREADS 100

static int8_t key[32] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
    "\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d"
    "\x1e\x1f";

static uint8_t IV[16] =
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
    "\x1f";

static uint8_t cleartext[144] =
    "\xb4\xfc\x5d\xc2\x49\x8d\x2c\x29\x4a\xc9\x9a\xb0\x1b\xf8\x29"
    "\xee\x85\x6d\x8c\x04\x34\x7c\x65\xf4\x89\x97\xc5\x71\x70\x41"
    "\x91\x40\x19\x60\xe1\xf1\x8f\x4d\x8c\x17\x51\xd6\xbc\x69\x6e"
    "\xf2\x21\x87\x18\x6c\xef\xc4\xf4\xd9\xe6\x1b\x94\xf7\xd8\xb2"
    "\xe9\x24\xb9\xe7\xe6\x19\xf5\xec\x55\x80\x9a\xc8\x7d\x70\xa3"
    "\x50\xf8\x03\x10\x35\x49\x9b\x53\x58\xd7\x4c\xfc\x5f\x02\xd6"
    "\x28\xea\xcc\x43\xee\x5e\x2b\x8a\x7a\x66\xf7\x00\xee\x09\x18"
    "\x30\x1b\x47\xa2\x16\x69\xc4\x6e\x44\x3f\xbd\xec\x52\xce\xe5"
    "\x41\xf2\xe0\x04\x4f\x5a\x55\x58\x37\xba\x45\x8d\x15\x53\xf6"
    "\x31\x91\x13\x8c\x51\xed\x08\x07\xdb";

static uint8_t aes256_cbc_encrypted[144] =
    "\x7f\x1b\x92\xac\xc5\x16\x05\x55\x74\xac\xb4\xe0\x91\x8c\xf8"
    "\x0d\xa9\x72\xa5\x09\xb8\x44\xee\x55\x02\x13\xb7\x52\x0a\xf0"
    "\xac\xd0\x21\x0e\x58\x7b\x34\xfe\xdb\x36\x01\x60\x7d\x18\x3a"
    "\xa9\x15\x18\x5b\x13\xca\xdd\x77\x7d\xdf\x64\xc6\xd5\x75\x4b"
    "\x02\x02\x37\xb1\xf4\x33\xff\x93\xe6\x32\x08\xda\xcb\x5d\xa2"
    "\x8f\x17\x1f\x99\x92\x60\x22\x9d\x6b\xe6\xb2\x5e\xb0\x5d\x26"
    "\x3f\xde\xb8\xc1\xb0\x70\x80\x1c\x00\xd0\x93\x2b\xeb\x0f\xd7"
    "\x70\x7a\x9a\x7a\xa6\x21\x23\x2c\x02\xb7\xcd\x88\x10\x9c\x2d"
    "\x0c\xd3\xfa\xc1\x33\x5b\xe1\xa1\xd4\x3d\x8f\xb8\x50\xc5\xb5"
    "\x72\xdd\x6d\x32\x1f\x58\x00\x48\xbe";

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

static int get_cipher(struct ssh_cipher_struct *cipher, const char *ciphername)
{
    struct ssh_cipher_struct *ciphers = ssh_get_ciphertab();
    int i, cmp;

    for (i = 0; ciphers[i].name != NULL; i++) {
        cmp = strcmp(ciphername, ciphers[i].name);
        if (cmp == 0) {
            memcpy(cipher, &ciphers[i], sizeof(*cipher));
            return SSH_OK;
        }
    }

    return SSH_ERROR;
}

static void *thread_crypto_aes256_cbc(void *threadid)
{
    uint8_t output[sizeof(cleartext)] = {0};
    uint8_t iv[16] = {0};
    struct ssh_cipher_struct cipher = {
        .name = NULL,
    };
    int rc;

    /* Unused */
    (void) threadid;

    rc = get_cipher(&cipher, "aes256-cbc");
    assert_int_equal(rc, SSH_OK);
    assert_non_null(cipher.set_encrypt_key);
    assert_non_null(cipher.encrypt);

    /* This is for dump static analizyer without modelling support */
    if (cipher.set_encrypt_key == NULL ||
        cipher.encrypt == NULL) {
        return NULL;
    }

    memcpy(iv, IV, sizeof(IV));
    cipher.set_encrypt_key(&cipher,
            key,
            iv
    );

    cipher.encrypt(&cipher,
            cleartext,
            output,
            sizeof(cleartext)
            );

    assert_memory_equal(output,
                        aes256_cbc_encrypted,
                        sizeof(aes256_cbc_encrypted));
    ssh_cipher_clear(&cipher);

    rc = get_cipher(&cipher, "aes256-cbc");
    assert_int_equal(rc, SSH_OK);
    assert_non_null(cipher.set_encrypt_key);
    assert_non_null(cipher.encrypt);

    /* This is for dump static analizyer without modelling support */
    if (cipher.set_encrypt_key == NULL ||
        cipher.encrypt == NULL) {
        return NULL;
    }

    memcpy(iv, IV, sizeof(IV));
    cipher.set_decrypt_key(&cipher,
            key,
            iv
    );

    memset(output, '\0', sizeof(output));
    cipher.decrypt(&cipher,
            aes256_cbc_encrypted,
            output,
            sizeof(aes256_cbc_encrypted)
            );

    assert_memory_equal(output, cleartext, sizeof(cleartext));

    ssh_cipher_clear(&cipher);

    pthread_exit(NULL);
}

static void torture_crypto_aes256_cbc(void **state)
{
    int rc;

    /* Unused */
    (void) state;

    rc = run_on_threads(thread_crypto_aes256_cbc);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void)
{
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_crypto_aes256_cbc),
    };

    /*
     * If the library is statically linked, ssh_init() is not called
     * automatically
     */
    ssh_init();
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
