/*
 * dh-int.c - Diffie-Helman algorithm code against SSH 2
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2018 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2012      by Dmitriy Kuznetsov <dk@yandex.ru>
 * Copyright (c) 2019      by Simo Sorce <simo@redhat.com>
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

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/dh.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

extern bignum ssh_dh_generator;
extern bignum ssh_dh_group1;
extern bignum ssh_dh_group14;
extern bignum ssh_dh_group16;
extern bignum ssh_dh_group18;

/*
 * How many bits of security we want for fast DH. DH private key size must be
 * twice that size.
 */
#define DH_SECURITY_BITS 512

struct dh_keypair {
    bignum priv_key;
    bignum pub_key;
};

struct dh_ctx {
    /* 0 is client, 1 is server */
    struct dh_keypair keypair[2];
    bignum generator;
    bignum modulus;
};

void ssh_dh_debug_crypto(struct ssh_crypto_struct *c)
{
#ifdef DEBUG_CRYPTO
    const_bignum x = NULL, y = NULL, e = NULL, f = NULL;

    ssh_dh_keypair_get_keys(c->dh_ctx, DH_CLIENT_KEYPAIR, &x, &e);
    ssh_dh_keypair_get_keys(c->dh_ctx, DH_SERVER_KEYPAIR, &y, &f);
    ssh_print_bignum("p", c->dh_ctx->modulus);
    ssh_print_bignum("g", c->dh_ctx->generator);
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

static void ssh_dh_free_modulus(struct dh_ctx *ctx)
{
    if ((ctx->modulus != ssh_dh_group1) &&
        (ctx->modulus != ssh_dh_group14) &&
        (ctx->modulus != ssh_dh_group16) &&
        (ctx->modulus != ssh_dh_group18)) {
        bignum_safe_free(ctx->modulus);
    }
    ctx->modulus = NULL;
}

static void ssh_dh_free_generator(struct dh_ctx *ctx)
{
    if (ctx->generator != ssh_dh_generator) {
        bignum_safe_free(ctx->generator);
    }
}

static void ssh_dh_free_dh_keypair(struct dh_keypair *keypair)
{
    bignum_safe_free(keypair->priv_key);
    bignum_safe_free(keypair->pub_key);
}

static int ssh_dh_init_dh_keypair(struct dh_keypair *keypair)
{
    int rc;

    keypair->priv_key = bignum_new();
    if (keypair->priv_key == NULL) {
        rc = SSH_ERROR;
        goto done;
    }
    keypair->pub_key = bignum_new();
    if (keypair->pub_key == NULL) {
        rc = SSH_ERROR;
        goto done;
    }

    rc = SSH_OK;
done:
    if (rc != SSH_OK) {
        ssh_dh_free_dh_keypair(keypair);
    }
    return rc;
}

int ssh_dh_keypair_get_keys(struct dh_ctx *ctx, int peer,
                            const_bignum *priv, const_bignum *pub)
{
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].priv_key)) {
            *priv = ctx->keypair[peer].priv_key;
        } else {
            return SSH_ERROR;
        }
    }

    if (pub) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].pub_key)) {
            *pub = ctx->keypair[peer].pub_key;
        } else {
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

int ssh_dh_keypair_set_keys(struct dh_ctx *ctx, int peer,
                            bignum priv, bignum pub)
{
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        bignum_safe_free(ctx->keypair[peer].priv_key);
        ctx->keypair[peer].priv_key = priv;
    }
    if (pub) {
        bignum_safe_free(ctx->keypair[peer].pub_key);
        ctx->keypair[peer].pub_key = pub;
    }
    return SSH_OK;
}

int ssh_dh_get_parameters(struct dh_ctx *ctx,
                          const_bignum *modulus, const_bignum *generator)
{
    if (ctx == NULL) {
        return SSH_ERROR;
    }
    if (modulus) {
        *modulus = ctx->modulus;
    }
    if (generator) {
        *generator = ctx->generator;
    }

    return SSH_OK;
}

int ssh_dh_set_parameters(struct dh_ctx *ctx,
                          bignum modulus, bignum generator)
{
    int rc;

    if ((ctx == NULL) || ((modulus == NULL) && (generator == NULL))) {
        return SSH_ERROR;
    }
    /* when setting modulus or generator,
     * make sure to invalidate existing keys */
    ssh_dh_free_dh_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    ssh_dh_free_dh_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);

    rc = ssh_dh_init_dh_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    if (rc != SSH_OK) {
        goto done;
    }
    rc = ssh_dh_init_dh_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);
    if (rc != SSH_OK) {
        goto done;
    }

    if (modulus) {
        ssh_dh_free_modulus(ctx);
        ctx->modulus = modulus;
    }
    if (generator) {
        ssh_dh_free_generator(ctx);
        ctx->generator = generator;
    }

done:
    return rc;
}

/**
 * @internal
 * @brief allocate and initialize ephemeral values used in dh kex
 */
int ssh_dh_init_common(struct ssh_crypto_struct *crypto)
{
    struct dh_ctx *ctx = NULL;
    int rc;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return SSH_ERROR;
    }

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

    crypto->dh_ctx = ctx;

    if (rc != SSH_OK) {
        ssh_dh_cleanup(crypto);
    }
    return rc;
}

void ssh_dh_cleanup(struct ssh_crypto_struct *crypto)
{
    struct dh_ctx *ctx = crypto->dh_ctx;

    if (ctx == NULL) {
        return;
    }

    ssh_dh_free_dh_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    ssh_dh_free_dh_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);

    ssh_dh_free_modulus(ctx);
    ssh_dh_free_generator(ctx);
    free(ctx);
    crypto->dh_ctx = NULL;
}

/** @internal
 * @brief generates a secret DH parameter of at least DH_SECURITY_BITS
 *        security as well as the corresponding public key.
 * @param[out] parms a dh_kex paramters structure with preallocated bignum
 *             where to store the parameters
 * @return SSH_OK on success, SSH_ERROR on error
 */
int ssh_dh_keypair_gen_keys(struct dh_ctx *dh_ctx, int peer)
{
    bignum tmp = NULL;
    bignum_CTX ctx = NULL;
    int rc = 0;
    int bits = 0;
    int p_bits = 0;

    ctx = bignum_ctx_new();
    if (bignum_ctx_invalid(ctx)){
        goto error;
    }
    tmp = bignum_new();
    if (tmp == NULL) {
        goto error;
    }
    p_bits = bignum_num_bits(dh_ctx->modulus);
    /* we need at most DH_SECURITY_BITS */
    bits = MIN(DH_SECURITY_BITS * 2, p_bits);
    /* ensure we're not too close of p so rnd()%p stays uniform */
    if (bits <= p_bits && bits + 64 > p_bits) {
        bits += 64;
    }
    rc = bignum_rand(tmp, bits);
    if (rc != 1) {
        goto error;
    }
    rc = bignum_mod(dh_ctx->keypair[peer].priv_key, tmp, dh_ctx->modulus, ctx);
    if (rc != 1) {
        goto error;
    }
    /* Now compute the corresponding public key */
    rc = bignum_mod_exp(dh_ctx->keypair[peer].pub_key, dh_ctx->generator,
                        dh_ctx->keypair[peer].priv_key, dh_ctx->modulus, ctx);
    if (rc != 1) {
        goto error;
    }
    bignum_safe_free(tmp);
    bignum_ctx_free(ctx);
    return SSH_OK;
error:
    bignum_safe_free(tmp);
    bignum_ctx_free(ctx);
    return SSH_ERROR;
}

/** @internal
 * @brief generates a shared secret between the local peer and the remote peer
 * @param[in] local peer identifier
 * @param[in] remote peer identifier
 * @param[out] dest a preallocated bignum where to store parameter
 * @return SSH_OK on success, SSH_ERROR on error
 */
int ssh_dh_compute_shared_secret(struct dh_ctx *dh_ctx, int local, int remote,
                                 bignum *dest)
{
    int rc;
    bignum_CTX ctx = bignum_ctx_new();
    if (bignum_ctx_invalid(ctx)) {
        return -1;
    }

    if (*dest == NULL) {
        *dest = bignum_new();
        if (*dest == NULL) {
            rc = 0;
            goto done;
        }
    }

    rc = bignum_mod_exp(*dest, dh_ctx->keypair[remote].pub_key,
                        dh_ctx->keypair[local].priv_key,
                        dh_ctx->modulus, ctx);

done:
    bignum_ctx_free(ctx);
    if (rc != 1) {
        return SSH_ERROR;
    }
    return SSH_OK;
}
