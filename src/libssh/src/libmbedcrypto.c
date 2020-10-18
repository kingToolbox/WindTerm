/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2017 Sartura d.o.o.
 *
 * Author: Juraj Vijtiuk <juraj.vijtiuk@sartura.hr>
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

#include "libssh/wrapper.h"
#include "libssh/crypto.h"
#include "libssh/priv.h"
#include "libssh/misc.h"

#ifdef HAVE_LIBMBEDCRYPTO
#include <mbedtls/md.h>
#ifdef MBEDTLS_GCM_C
#include <mbedtls/gcm.h>
#endif /* MBEDTLS_GCM_C */

static mbedtls_entropy_context ssh_mbedtls_entropy;
static mbedtls_ctr_drbg_context ssh_mbedtls_ctr_drbg;

static int libmbedcrypto_initialized = 0;

void ssh_reseed(void)
{
    mbedtls_ctr_drbg_reseed(&ssh_mbedtls_ctr_drbg, NULL, 0);
}

int ssh_get_random(void *where, int len, int strong)
{
    return ssh_mbedtls_random(where, len, strong);
}

SHACTX sha1_init(void)
{
    SHACTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha1_update(SHACTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha1_final(unsigned char *md, SHACTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha1(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

static mbedtls_md_type_t nid_to_md_algo(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return MBEDTLS_MD_SHA256;
        case NID_mbedtls_nistp384:
            return MBEDTLS_MD_SHA384;
        case NID_mbedtls_nistp521:
            return MBEDTLS_MD_SHA512;
    }
    return MBEDTLS_MD_NONE;
}

void evp(int nid, unsigned char *digest, int len,
        unsigned char *hash, unsigned int *hlen)
{
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);


    if (md_info != NULL) {
        *hlen = mbedtls_md_get_size(md_info);
        mbedtls_md(md_info, digest, len, hash);
    }
}

EVPCTX evp_init(int nid)
{
    EVPCTX ctx = NULL;
    int rc;
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void evp_update(EVPCTX ctx, const void *data, unsigned long len)
{
    mbedtls_md_update(ctx, data, len);
}

void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen)
{
    *mdlen = mbedtls_md_get_size(ctx->md_info);
    mbedtls_md_finish(ctx, md);
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
}

SHA256CTX sha256_init(void)
{
    SHA256CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if(ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha256_update(SHA256CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha256_final(unsigned char *md, SHA256CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha256(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA384CTX sha384_init(void)
{
    SHA384CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha384_update(SHA384CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha384_final(unsigned char *md, SHA384CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha384(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA512CTX sha512_init(void)
{
    SHA512CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha512_update(SHA512CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha512_final(unsigned char *md, SHA512CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha512(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

MD5CTX md5_init(void)
{
    MD5CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}


void md5_update(MD5CTX c, const void *data, unsigned long len) {
    mbedtls_md_update(c, data, len);
}

void md5_final(unsigned char *md, MD5CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

int ssh_kdf(struct ssh_crypto_struct *crypto,
            unsigned char *key, size_t key_len,
            int key_type, unsigned char *output,
            size_t requested_len)
{
    return sshkdf_derive_key(crypto, key, key_len,
                             key_type, output, requested_len);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type)
{
    HMACCTX ctx = NULL;
    const mbedtls_md_info_t *md_info = NULL;
    int rc;

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    switch (type) {
        case SSH_HMAC_SHA1:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            break;
        case SSH_HMAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case SSH_HMAC_SHA512:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            goto error;
    }

    mbedtls_md_init(ctx);

    if (md_info == NULL) {
        goto error;
    }

    rc = mbedtls_md_setup(ctx, md_info, 1);
    if (rc != 0) {
        goto error;
    }

    rc = mbedtls_md_hmac_starts(ctx, key, len);
    if (rc != 0) {
        goto error;
    }

    return ctx;

error:
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
    return NULL;
}

void hmac_update(HMACCTX c, const void *data, unsigned long len)
{
    mbedtls_md_hmac_update(c, data, len);
}

void hmac_final(HMACCTX c, unsigned char *hashmacbuf, unsigned int *len)
{
    *len = mbedtls_md_get_size(c->md_info);
    mbedtls_md_hmac_finish(c, hashmacbuf);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

static int
cipher_init(struct ssh_cipher_struct *cipher,
            mbedtls_operation_t operation,
            void *key,
            void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    mbedtls_cipher_context_t *ctx;
    int rc;

    if (operation == MBEDTLS_ENCRYPT) {
        ctx = &cipher->encrypt_ctx;
    } else if (operation == MBEDTLS_DECRYPT) {
        ctx = &cipher->decrypt_ctx;
    } else {
        SSH_LOG(SSH_LOG_WARNING, "unknown operation");
        return 1;
    }

    mbedtls_cipher_init(ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(ctx, key,
                               cipher_info->key_bitlen,
                               operation);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(ctx, IV, cipher_info->iv_size);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    return 0;
error:
    mbedtls_cipher_free(ctx);
    return 1;
}

static int
cipher_set_encrypt_key(struct ssh_cipher_struct *cipher,
                       void *key,
                       void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_ENCRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    return SSH_ERROR;
}

static int
cipher_set_encrypt_key_cbc(struct ssh_cipher_struct *cipher,
                           void *key,
                           void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_ENCRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    /* libssh only encypts and decrypts packets that are multiples of a block
     * size, and no padding is used */
    rc = mbedtls_cipher_set_padding_mode(&cipher->encrypt_ctx,
            MBEDTLS_PADDING_NONE);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    return SSH_ERROR;
}

#ifdef MBEDTLS_GCM_C
static int
cipher_set_key_gcm(struct ssh_cipher_struct *cipher,
                   void *key,
                   void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    int rc;

    mbedtls_gcm_init(&cipher->gcm_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_gcm_setkey(&cipher->gcm_ctx,
                            MBEDTLS_CIPHER_ID_AES,
                            key,
                            cipher_info->key_bitlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_setkey failed");
        goto error;
    }

    /* Store the IV so we can increment the packet counter later */
    memcpy(cipher->last_iv, IV, AES_GCM_IVLEN);

    return 0;
error:
    mbedtls_gcm_free(&cipher->gcm_ctx);
    return 1;
}
#endif /* MBEDTLS_GCM_C */

static int
cipher_set_decrypt_key(struct ssh_cipher_struct *cipher,
                       void *key,
                       void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_DECRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static int
cipher_set_decrypt_key_cbc(struct ssh_cipher_struct *cipher,
                           void *key,
                           void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_DECRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    rc = mbedtls_cipher_set_padding_mode(&cipher->decrypt_ctx,
            MBEDTLS_PADDING_NONE);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static void cipher_encrypt(struct ssh_cipher_struct *cipher,
                           void *in,
                           void *out,
                           size_t len)
{
    size_t outlen = 0;
    size_t total_len = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->encrypt_ctx, (unsigned char *) out + outlen,
            &outlen);

    total_len += outlen;

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during encryption");
        return;
    }

    if (total_len != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_encrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    if (outlen != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_decrypt(struct ssh_cipher_struct *cipher,
                           void *in,
                           void *out,
                           size_t len)
{
    size_t outlen = 0;
    int rc = 0;
    size_t total_len = 0;

    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
            outlen, &outlen);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

static void cipher_decrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        unsigned long len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    /* MbedTLS caches the last block when decrypting with cbc.
     * By calling finish the block is flushed to out, however the unprocessed
     * data counter is not reset.
     * Calling mbedtls_cipher_reset resets the unprocessed data counter.
     */
    if (outlen == 0) {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, out, &outlen);
    } else if (outlen == len) {
        return;
    } else {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
                outlen , &outlen);
    }

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during decryption");
        return;
    }

    rc = mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    if (outlen != len) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
        return;
    }

}

#ifdef MBEDTLS_GCM_C
static int
cipher_gcm_get_length(struct ssh_cipher_struct *cipher,
                      void *in,
                      uint8_t *out,
                      size_t len,
                      uint64_t seq)
{
    (void)cipher;
    (void)seq;

    /* The length is not encrypted: Copy it to the result buffer */
    memcpy(out, in, len);

    return SSH_OK;
}

static void
cipher_encrypt_gcm(struct ssh_cipher_struct *cipher,
                   void *in,
                   void *out,
                   size_t len,
                   uint8_t *tag,
                   uint64_t seq)
{
    size_t authlen, aadlen;
    int rc;

    (void) seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    /* The length is not encrypted */
    memcpy(out, in, aadlen);
    rc = mbedtls_gcm_crypt_and_tag(&cipher->gcm_ctx,
                                   MBEDTLS_GCM_ENCRYPT,
                                   len - aadlen, /* encrypted data len */
                                   cipher->last_iv, /* IV */
                                   AES_GCM_IVLEN,
                                   in, /* aad */
                                   aadlen,
                                   (const unsigned char *)in + aadlen, /* input */
                                   (unsigned char *)out + aadlen, /* output */
                                   authlen,
                                   tag); /* tag */
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_crypt_and_tag failed");
        return;
    }

    /* Increment the IV for the next invocation */
    uint64_inc(cipher->last_iv + 4);
}

static int
cipher_decrypt_gcm(struct ssh_cipher_struct *cipher,
                   void *complete_packet,
                   uint8_t *out,
                   size_t encrypted_size,
                   uint64_t seq)
{
    size_t authlen, aadlen;
    int rc;

    (void) seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    rc = mbedtls_gcm_auth_decrypt(&cipher->gcm_ctx,
                                  encrypted_size, /* encrypted data len */
                                  cipher->last_iv, /* IV */
                                  AES_GCM_IVLEN,
                                  complete_packet, /* aad */
                                  aadlen,
                                  (const uint8_t *)complete_packet + aadlen + encrypted_size, /* tag */
                                  authlen,
                                  (const uint8_t *)complete_packet + aadlen, /* input */
                                  (unsigned char *)out); /* output */
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_auth_decrypt failed");
        return SSH_ERROR;
    }

    /* Increment the IV for the next invocation */
    uint64_inc(cipher->last_iv + 4);

    return SSH_OK;
}
#endif /* MBEDTLS_GCM_C */

static void cipher_cleanup(struct ssh_cipher_struct *cipher)
{
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    mbedtls_cipher_free(&cipher->decrypt_ctx);
#ifdef MBEDTLS_GCM_C
    mbedtls_gcm_free(&cipher->gcm_ctx);
#endif /* MBEDTLS_GCM_C */
}

static struct ssh_cipher_struct ssh_ciphertab[] = {
#ifdef WITH_BLOWFISH_CIPHER
    {
        .name = "blowfish-cbc",
        .blocksize = 8,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_BLOWFISH_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
#endif /* WITH_BLOWFISH_CIPHER */
    {
        .name = "aes128-ctr",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-ctr",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-ctr",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes128-cbc",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-cbc",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-cbc",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
#ifdef MBEDTLS_GCM_C
    {
        .name = "aes128-gcm@openssh.com",
        .blocksize = 16,
        .lenfield_blocksize = 4, /* not encrypted, but authenticated */
        .keysize = 128,
        .tag_size = AES_GCM_TAGLEN,
        .type = MBEDTLS_CIPHER_AES_128_GCM,
        .set_encrypt_key = cipher_set_key_gcm,
        .set_decrypt_key = cipher_set_key_gcm,
        .aead_encrypt = cipher_encrypt_gcm,
        .aead_decrypt_length = cipher_gcm_get_length,
        .aead_decrypt = cipher_decrypt_gcm,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-gcm@openssh.com",
        .blocksize = 16,
        .lenfield_blocksize = 4, /* not encrypted, but authenticated */
        .keysize = 256,
        .tag_size = AES_GCM_TAGLEN,
        .type = MBEDTLS_CIPHER_AES_256_GCM,
        .set_encrypt_key = cipher_set_key_gcm,
        .set_decrypt_key = cipher_set_key_gcm,
        .aead_encrypt = cipher_encrypt_gcm,
        .aead_decrypt_length = cipher_gcm_get_length,
        .aead_decrypt = cipher_decrypt_gcm,
        .cleanup = cipher_cleanup
    },
#endif /* MBEDTLS_GCM_C */
    {
        .name = "3des-cbc",
        .blocksize = 8,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_DES_EDE3_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "chacha20-poly1305@openssh.com"
    },
    {
        .name = NULL,
        .blocksize = 0,
        .keysize = 0,
        .set_encrypt_key = NULL,
        .set_decrypt_key = NULL,
        .encrypt = NULL,
        .decrypt = NULL,
        .cleanup = NULL
    }
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
    return ssh_ciphertab;
}

int ssh_crypto_init(void)
{
    size_t i;
    int rc;

    if (libmbedcrypto_initialized) {
        return SSH_OK;
    }

    mbedtls_entropy_init(&ssh_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&ssh_mbedtls_ctr_drbg);

    rc = mbedtls_ctr_drbg_seed(&ssh_mbedtls_ctr_drbg, mbedtls_entropy_func,
            &ssh_mbedtls_entropy, NULL, 0);
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    }

    for (i = 0; ssh_ciphertab[i].name != NULL; i++) {
        int cmp;

        cmp = strcmp(ssh_ciphertab[i].name, "chacha20-poly1305@openssh.com");
        if (cmp == 0) {
            memcpy(&ssh_ciphertab[i],
                   ssh_get_chacha20poly1305_cipher(),
                   sizeof(struct ssh_cipher_struct));
            break;
        }
    }

    libmbedcrypto_initialized = 1;

    return SSH_OK;
}

int ssh_mbedtls_random(void *where, int len, int strong)
{
    int rc = 0;
    if (strong) {
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_ON);
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_OFF);
    } else {
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
    }

    return !rc;
}

mbedtls_ctr_drbg_context *ssh_get_mbedtls_ctr_drbg_context(void)
{
    return &ssh_mbedtls_ctr_drbg;
}

void ssh_crypto_finalize(void)
{
    if (!libmbedcrypto_initialized) {
        return;
    }

    mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&ssh_mbedtls_entropy);

    libmbedcrypto_initialized = 0;
}

#endif /* HAVE_LIBMBEDCRYPTO */
