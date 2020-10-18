/*
 * pki_ed25519_common.c - Common ed25519 functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis
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

#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/buffer.h"

int pki_privkey_build_ed25519(ssh_key key,
                              ssh_string pubkey,
                              ssh_string privkey)
{
    if (ssh_string_len(pubkey) != ED25519_KEY_LEN ||
        ssh_string_len(privkey) != (2 * ED25519_KEY_LEN))
    {
        SSH_LOG(SSH_LOG_WARN, "Invalid ed25519 key len");
        return SSH_ERROR;
    }

#ifdef HAVE_OPENSSL_ED25519
    /* In OpenSSL implementation, the private key is the original private seed,
     * without the public key. */
    key->ed25519_privkey = malloc(ED25519_KEY_LEN);
#else
    /* In the internal implementation, the private key is the concatenation of
     * the private seed with the public key. */
    key->ed25519_privkey = malloc(2 * ED25519_KEY_LEN);
#endif
    if (key->ed25519_privkey == NULL) {
        goto error;
    }

    key->ed25519_pubkey = malloc(ED25519_KEY_LEN);
    if (key->ed25519_pubkey == NULL) {
        goto error;
    }

#ifdef HAVE_OPENSSL_ED25519
    memcpy(key->ed25519_privkey, ssh_string_data(privkey),
           ED25519_KEY_LEN);
#else
    memcpy(key->ed25519_privkey, ssh_string_data(privkey),
           2 * ED25519_KEY_LEN);
#endif
    memcpy(key->ed25519_pubkey, ssh_string_data(pubkey),
           ED25519_KEY_LEN);

    return SSH_OK;

error:
    SAFE_FREE(key->ed25519_privkey);
    SAFE_FREE(key->ed25519_pubkey);

    return SSH_ERROR;
}

/**
 * @internal
 *
 * @brief Compare ed25519 keys if they are equal.
 *
 * @param[in] k1        The first key to compare.
 *
 * @param[in] k2        The second key to compare.
 *
 * @param[in] what      What part or type of the key do you want to compare.
 *
 * @return              0 if equal, 1 if not.
 */
int pki_ed25519_key_cmp(const ssh_key k1,
                        const ssh_key k2,
                        enum ssh_keycmp_e what)
{
    int cmp;

    switch(what) {
    case SSH_KEY_CMP_PRIVATE:
        if (k1->ed25519_privkey == NULL || k2->ed25519_privkey == NULL) {
            return 1;
        }
#ifdef HAVE_OPENSSL_ED25519
        /* In OpenSSL implementation, the private key is the original private
         * seed, without the public key. */
        cmp = memcmp(k1->ed25519_privkey, k2->ed25519_privkey, ED25519_KEY_LEN);
#else
        /* In the internal implementation, the private key is the concatenation
         * of the private seed with the public key. */
        cmp = memcmp(k1->ed25519_privkey, k2->ed25519_privkey,
                     2 * ED25519_KEY_LEN);
#endif
        if (cmp != 0) {
            return 1;
        }
        FALL_THROUGH;
    case SSH_KEY_CMP_PUBLIC:
        if (k1->ed25519_pubkey == NULL || k2->ed25519_pubkey == NULL) {
            return 1;
        }
        cmp = memcmp(k1->ed25519_pubkey, k2->ed25519_pubkey, ED25519_KEY_LEN);
        if (cmp != 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Duplicate an Ed25519 key
 *
 * @param[out] new Pre-initialized ssh_key structure
 *
 * @param[in] key Key to copy
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_ed25519_key_dup(ssh_key new, const ssh_key key)
{
    if (key->ed25519_privkey == NULL && key->ed25519_pubkey == NULL) {
        return SSH_ERROR;
    }

    if (key->ed25519_privkey != NULL) {
#ifdef HAVE_OPENSSL_ED25519
        /* In OpenSSL implementation, the private key is the original private
         * seed, without the public key. */
        new->ed25519_privkey = malloc(ED25519_KEY_LEN);
#else
        /* In the internal implementation, the private key is the concatenation
         * of the private seed with the public key. */
        new->ed25519_privkey = malloc(2 * ED25519_KEY_LEN);
#endif
        if (new->ed25519_privkey == NULL) {
            return SSH_ERROR;
        }
#ifdef HAVE_OPENSSL_ED25519
        memcpy(new->ed25519_privkey, key->ed25519_privkey, ED25519_KEY_LEN);
#else
        memcpy(new->ed25519_privkey, key->ed25519_privkey, 2 * ED25519_KEY_LEN);
#endif
    }

    if (key->ed25519_pubkey != NULL) {
        new->ed25519_pubkey = malloc(ED25519_KEY_LEN);
        if (new->ed25519_pubkey == NULL) {
            SAFE_FREE(new->ed25519_privkey);
            return SSH_ERROR;
        }
        memcpy(new->ed25519_pubkey, key->ed25519_pubkey, ED25519_KEY_LEN);
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Outputs an Ed25519 public key in a blob buffer.
 *
 * @param[out] buffer Output buffer
 *
 * @param[in] key Key to output
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_ed25519_public_key_to_blob(ssh_buffer buffer, ssh_key key)
{
    int rc;

    if (key->ed25519_pubkey == NULL){
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(buffer,
                         "dP",
                         (uint32_t)ED25519_KEY_LEN,
                         (size_t)ED25519_KEY_LEN, key->ed25519_pubkey);

    return rc;
}

/**
 * @internal
 *
 * @brief output a signature blob from an ed25519 signature
 *
 * @param[in] sig signature to convert
 *
 * @return Signature blob in SSH string, or NULL on error
 */
ssh_string pki_ed25519_signature_to_blob(ssh_signature sig)
{
    ssh_string sig_blob;

#ifdef HAVE_OPENSSL_ED25519
    /* When using the OpenSSL implementation, the signature is stored in raw_sig
     * which is shared by all algorithms.*/
    if (sig->raw_sig == NULL) {
        return NULL;
    }
#else
    /* When using the internal implementation, the signature is stored in an
     * algorithm specific field. */
    if (sig->ed25519_sig == NULL) {
        return NULL;
    }
#endif

    sig_blob = ssh_string_new(ED25519_SIG_LEN);
    if (sig_blob == NULL) {
        return NULL;
    }

#ifdef HAVE_OPENSSL_ED25519
    ssh_string_fill(sig_blob, ssh_string_data(sig->raw_sig),
                    ssh_string_len(sig->raw_sig));
#else
    ssh_string_fill(sig_blob, sig->ed25519_sig, ED25519_SIG_LEN);
#endif

    return sig_blob;
}

/**
 * @internal
 *
 * @brief Convert a signature blob in an ed25519 signature.
 *
 * @param[out] sig a preinitialized signature
 *
 * @param[in] sig_blob a signature blob
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_signature_from_ed25519_blob(ssh_signature sig, ssh_string sig_blob)
{
    size_t len;

    len = ssh_string_len(sig_blob);
    if (len != ED25519_SIG_LEN){
        SSH_LOG(SSH_LOG_WARN, "Invalid ssh-ed25519 signature len: %zu", len);
        return SSH_ERROR;
    }

#ifdef HAVE_OPENSSL_ED25519
    sig->raw_sig = ssh_string_copy(sig_blob);
#else
    sig->ed25519_sig = malloc(ED25519_SIG_LEN);
    if (sig->ed25519_sig == NULL){
        return SSH_ERROR;
    }
    memcpy(sig->ed25519_sig, ssh_string_data(sig_blob), ED25519_SIG_LEN);
#endif

    return SSH_OK;
}

