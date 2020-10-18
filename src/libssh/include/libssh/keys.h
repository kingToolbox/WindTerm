/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef KEYS_H_
#define KEYS_H_

#include "config.h"
#include "libssh/libssh.h"
#include "libssh/wrapper.h"

struct ssh_public_key_struct {
    int type;
    const char *type_c; /* Don't free it ! it is static */
#if defined(HAVE_LIBGCRYPT)
    gcry_sexp_t dsa_pub;
    gcry_sexp_t rsa_pub;
#elif defined(HAVE_LIBCRYPTO)
    DSA *dsa_pub;
    RSA *rsa_pub;
#elif defined(HAVE_LIBMBEDCRYPTO)
    mbedtls_pk_context *rsa_pub;
    void *dsa_pub;
#endif
};

struct ssh_private_key_struct {
    int type;
#if defined(HAVE_LIBGCRYPT)
    gcry_sexp_t dsa_priv;
    gcry_sexp_t rsa_priv;
#elif defined(HAVE_LIBCRYPTO)
    DSA *dsa_priv;
    RSA *rsa_priv;
#elif defined(HAVE_LIBMBEDCRYPTO)
    mbedtls_pk_context *rsa_priv;
    void *dsa_priv;
#endif
};

const char *ssh_type_to_char(int type);
int ssh_type_from_name(const char *name);

ssh_public_key publickey_from_string(ssh_session session, ssh_string pubkey_s);

#endif /* KEYS_H_ */
