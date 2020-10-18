/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Simo Sorce - Red Hat, Inc.
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
#include "libssh/session.h"
#include "libssh/dh.h"
#include "libssh/buffer.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

#include "openssl/crypto.h"
#include "openssl/dh.h"
#include "libcrypto-compat.h"

extern bignum ssh_dh_generator;
extern bignum ssh_dh_group1;
extern bignum ssh_dh_group14;
extern bignum ssh_dh_group16;
extern bignum ssh_dh_group18;

struct dh_ctx {
    DH *keypair[2];
};

void ssh_dh_debug_crypto(struct ssh_crypto_struct *c)
{
#ifdef DEBUG_CRYPTO
    const_bignum x = NULL, y = NULL, e = NULL, f = NULL;

    ssh_dh_keypair_get_keys(c->dh_ctx, DH_CLIENT_KEYPAIR, &x, &e);
    ssh_dh_keypair_get_keys(c->dh_ctx, DH_SERVER_KEYPAIR, &y, &f);
    ssh_print_bignum("x", x);
    ssh_print_bignum("y", y);
    ssh_print_bignum("e", e);
    ssh_print_bignum("f", f);

    ssh_log_hexdump("Session server cookie", c->server_kex.cookie, 16);
    ssh_log_hexdump("Session client cookie", c->client_kex.cookie, 16);
    ssh_print_bignum("k", c->shared_secret);

#else
    (void)c; /* UNUSED_PARAM */
#endif
}

int ssh_dh_keypair_get_keys(struct dh_ctx *ctx, int peer,
                            const_bignum *priv, const_bignum *pub)
{
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL) ||
        (ctx->keypair[peer] == NULL)) {
        return SSH_ERROR;
    }
    DH_get0_key(ctx->keypair[peer], pub, priv);
    if (priv && (*priv == NULL || bignum_num_bits(*priv) == 0)) {
        return SSH_ERROR;
    }
    if (pub && (*pub == NULL || bignum_num_bits(*pub) == 0)) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

int ssh_dh_keypair_set_keys(struct dh_ctx *ctx, int peer,
                            const bignum priv, const bignum pub)
{
    bignum priv_key = NULL;
    bignum pub_key = NULL;

    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL) ||
        (ctx->keypair[peer] == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        priv_key = priv;
    }
    if (pub) {
        pub_key = pub;
    }
    (void)DH_set0_key(ctx->keypair[peer], pub_key, priv_key);

    return SSH_OK;
}

int ssh_dh_get_parameters(struct dh_ctx *ctx,
                          const_bignum *modulus, const_bignum *generator)
{
    if (ctx == NULL || ctx->keypair[0] == NULL) {
        return SSH_ERROR;
    }
    DH_get0_pqg(ctx->keypair[0], modulus, NULL, generator);
    return SSH_OK;
}

int ssh_dh_set_parameters(struct dh_ctx *ctx,
                          const bignum modulus, const bignum generator)
{
    size_t i;
    int rc;

    if ((ctx == NULL) || (modulus == NULL) || (generator == NULL)) {
        return SSH_ERROR;
    }

    for (i = 0; i < 2; i++) {
        bignum p = NULL;
        bignum g = NULL;

        /* when setting modulus or generator,
         * make sure to invalidate existing keys */
        DH_free(ctx->keypair[i]);
        ctx->keypair[i] = DH_new();
        if (ctx->keypair[i] == NULL) {
            rc = SSH_ERROR;
            goto done;
        }

        p = BN_dup(modulus);
        g = BN_dup(generator);
        rc = DH_set0_pqg(ctx->keypair[i], p, NULL, g);
        if (rc != 1) {
            BN_free(p);
            BN_free(g);
            rc = SSH_ERROR;
            goto done;
        }
    }

    rc = SSH_OK;
done:
    if (rc != SSH_OK) {
        DH_free(ctx->keypair[0]);
        DH_free(ctx->keypair[1]);
        ctx->keypair[0] = NULL;
        ctx->keypair[1] = NULL;
    }
    return rc;
}

/**
 * @internal
 * @brief allocate and initialize ephemeral values used in dh kex
 */
int ssh_dh_init_common(struct ssh_crypto_struct *crypto)
{
    struct dh_ctx *ctx;
    int rc;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return SSH_ERROR;
    }
    crypto->dh_ctx = ctx;

    switch (crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
        rc = ssh_dh_set_parameters(ctx, ssh_dh_group1, ssh_dh_generator);
        break;
    case SSH_KEX_DH_GROUP14_SHA1:
    case SSH_KEX_DH_GROUP14_SHA256:
        rc = ssh_dh_set_parameters(ctx, ssh_dh_group14, ssh_dh_generator);
        break;
    case SSH_KEX_DH_GROUP16_SHA512:
        rc = ssh_dh_set_parameters(ctx, ssh_dh_group16, ssh_dh_generator);
        break;
    case SSH_KEX_DH_GROUP18_SHA512:
        rc = ssh_dh_set_parameters(ctx, ssh_dh_group18, ssh_dh_generator);
        break;
    default:
        rc = SSH_OK;
        break;
    }

    if (rc != SSH_OK) {
        ssh_dh_cleanup(crypto);
    }
    return rc;
}

void ssh_dh_cleanup(struct ssh_crypto_struct *crypto)
{
    if (crypto->dh_ctx != NULL) {
        DH_free(crypto->dh_ctx->keypair[0]);
        DH_free(crypto->dh_ctx->keypair[1]);
        free(crypto->dh_ctx);
        crypto->dh_ctx = NULL;
    }
}

/** @internal
 * @brief generates a secret DH parameter of at least DH_SECURITY_BITS
 *        security as well as the corresponding public key.
 * @param[out] parms a dh_ctx that will hold the new keys.
 * @param peer Select either client or server key storage. Valid values are:
 *        DH_CLIENT_KEYPAIR or DH_SERVER_KEYPAIR
 *
 * @return SSH_OK on success, SSH_ERROR on error
 */
int ssh_dh_keypair_gen_keys(struct dh_ctx *dh_ctx, int peer)
{
    int rc;

    if ((dh_ctx == NULL) || (dh_ctx->keypair[peer] == NULL)) {
        return SSH_ERROR;
    }
    rc = DH_generate_key(dh_ctx->keypair[peer]);
    if (rc != 1) {
        return SSH_ERROR;
    }
    return SSH_OK;
}

/** @internal
 * @brief generates a shared secret between the local peer and the remote
 *        peer. The local peer must have been initialized using either the
 *        ssh_dh_keypair_gen_keys() function or by seetting manually both
 *        the private and public keys. The remote peer only needs to have
 *        the remote's peer public key set.
 * @param[in] local peer identifier (DH_CLIENT_KEYPAIR or DH_SERVER_KEYPAIR)
 * @param[in] remote peer identifier (DH_CLIENT_KEYPAIR or DH_SERVER_KEYPAIR)
 * @param[out] dest a new bignum with the shared secret value is returned.
 * @return SSH_OK on success, SSH_ERROR on error
 */
int ssh_dh_compute_shared_secret(struct dh_ctx *dh_ctx, int local, int remote,
                                 bignum *dest)
{
    unsigned char *kstring = NULL;
    const_bignum pub_key = NULL;
    int klen, rc;

    if ((dh_ctx == NULL) ||
        (dh_ctx->keypair[local] == NULL) ||
        (dh_ctx->keypair[remote] == NULL)) {
        return SSH_ERROR;
    }

    kstring = malloc(DH_size(dh_ctx->keypair[local]));
    if (kstring == NULL) {
        rc = SSH_ERROR;
        goto done;
    }

    rc = ssh_dh_keypair_get_keys(dh_ctx, remote, NULL, &pub_key);
    if (rc != SSH_OK) {
        rc = SSH_ERROR;
        goto done;
    }

    klen = DH_compute_key(kstring, pub_key, dh_ctx->keypair[local]);
    if (klen == -1) {
        rc = SSH_ERROR;
        goto done;
    }

    *dest = BN_bin2bn(kstring, klen, NULL);
    if (*dest == NULL) {
        rc = SSH_ERROR;
        goto done;
    }

    rc = SSH_OK;
done:
    free(kstring);
    return rc;
}
