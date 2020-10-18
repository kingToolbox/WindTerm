/*
 * pki_ed25519 .c - PKI infrastructure using ed25519
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
#include "libssh/ed25519.h"
#include "libssh/buffer.h"

int pki_key_generate_ed25519(ssh_key key)
{
    int rc;

    key->ed25519_privkey = malloc(sizeof (ed25519_privkey));
    if (key->ed25519_privkey == NULL) {
        goto error;
    }

    key->ed25519_pubkey = malloc(sizeof (ed25519_pubkey));
    if (key->ed25519_pubkey == NULL) {
        goto error;
    }

    rc = crypto_sign_ed25519_keypair(*key->ed25519_pubkey,
                                     *key->ed25519_privkey);
    if (rc != 0) {
        goto error;
    }

    return SSH_OK;
error:
    SAFE_FREE(key->ed25519_privkey);
    SAFE_FREE(key->ed25519_pubkey);

    return SSH_ERROR;
}

int pki_ed25519_sign(const ssh_key privkey,
                     ssh_signature sig,
                     const unsigned char *hash,
                     size_t hlen)
{
    int rc;
    uint8_t *buffer;
    uint64_t dlen = 0;

    buffer = malloc(hlen + ED25519_SIG_LEN);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    rc = crypto_sign_ed25519(buffer,
                             &dlen,
                             hash,
                             hlen,
                             *privkey->ed25519_privkey);
    if (rc != 0) {
        goto error;
    }

    /* This shouldn't happen */
    if (dlen - hlen != ED25519_SIG_LEN) {
        goto error;
    }

    sig->ed25519_sig = malloc(ED25519_SIG_LEN);
    if (sig->ed25519_sig == NULL) {
        goto error;
    }

    memcpy(sig->ed25519_sig, buffer, ED25519_SIG_LEN);
    SAFE_FREE(buffer);

    return SSH_OK;
error:
    SAFE_FREE(buffer);
    return SSH_ERROR;
}

int pki_ed25519_verify(const ssh_key pubkey,
                       ssh_signature sig,
                       const unsigned char *hash,
                       size_t hlen)
{
    uint64_t mlen = 0;
    uint8_t *buffer;
    uint8_t *buffer2;
    int rc;

    if (pubkey == NULL || sig == NULL ||
        hash == NULL || sig->ed25519_sig == NULL) {
        return SSH_ERROR;
    }

    buffer = malloc(hlen + ED25519_SIG_LEN);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    buffer2 = malloc(hlen + ED25519_SIG_LEN);
    if (buffer2 == NULL) {
        goto error;
    }

    memcpy(buffer, sig->ed25519_sig, ED25519_SIG_LEN);
    memcpy(buffer + ED25519_SIG_LEN, hash, hlen);

    rc = crypto_sign_ed25519_open(buffer2,
                                  &mlen,
                                  buffer,
                                  hlen + ED25519_SIG_LEN,
                                  *pubkey->ed25519_pubkey);

    explicit_bzero(buffer, hlen + ED25519_SIG_LEN);
    explicit_bzero(buffer2, hlen);
    SAFE_FREE(buffer);
    SAFE_FREE(buffer2);
    if (rc == 0) {
        return SSH_OK;
    } else {
        return SSH_ERROR;
    }
error:
    SAFE_FREE(buffer);
    SAFE_FREE(buffer2);

    return SSH_ERROR;
}

