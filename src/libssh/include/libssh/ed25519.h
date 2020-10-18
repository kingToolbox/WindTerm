/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis
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

#ifndef ED25519_H_
#define ED25519_H_
#include "libssh/priv.h"

/**
 * @defgroup ed25519 ed25519 API
 * @internal
 * @brief API for DJB's ed25519
 *
 * @{ */

#define ED25519_PK_LEN 32
#define ED25519_SK_LEN 64
#define ED25519_SIG_LEN 64

typedef uint8_t ed25519_pubkey[ED25519_PK_LEN];
typedef uint8_t ed25519_privkey[ED25519_SK_LEN];
typedef uint8_t ed25519_signature[ED25519_SIG_LEN];

/** @internal
 * @brief generate an ed25519 key pair
 * @param[out] pk generated public key
 * @param[out] sk generated secret key
 * @return     0 on success, -1 on error.
 * */
int crypto_sign_ed25519_keypair(ed25519_pubkey pk, ed25519_privkey sk);

/** @internal
 * @brief sign a message with ed25519
 * @param[out] sm location to store the signed message.
 *                Its length should be mlen + 64.
 * @param[out] smlen pointer to the size of the signed message
 * @param[in] m message to be signed
 * @param[in] mlen length of the message to be signed
 * @param[in] sk secret key to sign the message with
 * @return    0 on success.
 */
int crypto_sign_ed25519(
    unsigned char *sm, uint64_t *smlen,
    const unsigned char *m, uint64_t mlen,
    const ed25519_privkey sk);

/** @internal
 * @brief "open" and verify the signature of a signed message
 * @param[out] m location to store the verified message.
 *               Its length should be equal to smlen.
 * @param[out] mlen pointer to the size of the verified message
 * @param[in] sm signed message to verify
 * @param[in] smlen length of the signed message to verify
 * @param[in] pk public key used to sign the message
 * @returns   0 on success (supposedly).
 */
int crypto_sign_ed25519_open(
    unsigned char *m, uint64_t *mlen,
    const unsigned char *sm, uint64_t smlen,
    const ed25519_pubkey pk);

/** @} */
#endif /* ED25519_H_ */
