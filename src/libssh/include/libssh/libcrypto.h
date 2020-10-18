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

#ifndef LIBCRYPTO_H_
#define LIBCRYPTO_H_

#include "config.h"

#ifdef HAVE_LIBCRYPTO

#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

typedef EVP_MD_CTX* SHACTX;
typedef EVP_MD_CTX* SHA256CTX;
typedef EVP_MD_CTX* SHA384CTX;
typedef EVP_MD_CTX* SHA512CTX;
typedef EVP_MD_CTX* MD5CTX;
typedef HMAC_CTX* HMACCTX;
#ifdef HAVE_ECC
typedef EVP_MD_CTX *EVPCTX;
#else
typedef void *EVPCTX;
#endif

#define SHA_DIGEST_LEN SHA_DIGEST_LENGTH
#define SHA256_DIGEST_LEN SHA256_DIGEST_LENGTH
#define SHA384_DIGEST_LEN SHA384_DIGEST_LENGTH
#define SHA512_DIGEST_LEN SHA512_DIGEST_LENGTH
#ifdef MD5_DIGEST_LEN
    #undef MD5_DIGEST_LEN
#endif
#define MD5_DIGEST_LEN MD5_DIGEST_LENGTH

#ifdef HAVE_OPENSSL_ECC
#define EVP_DIGEST_LEN EVP_MAX_MD_SIZE
#endif

#include <openssl/bn.h>
#include <openssl/opensslv.h>
#define OPENSSL_0_9_7b 0x0090702fL
#if (OPENSSL_VERSION_NUMBER <= OPENSSL_0_9_7b)
#define BROKEN_AES_CTR
#endif
typedef BIGNUM*  bignum;
typedef const BIGNUM* const_bignum;
typedef BN_CTX* bignum_CTX;

#define bignum_new() BN_new()
#define bignum_safe_free(num) do { \
    if ((num) != NULL) { \
        BN_clear_free((num)); \
        (num)=NULL; \
    } \
    } while(0)
#define bignum_set_word(bn,n) BN_set_word(bn,n)
#define bignum_bin2bn(data, datalen, dest)   \
    do {                                     \
        (*dest) = BN_new();                  \
        if ((*dest) != NULL) {               \
            BN_bin2bn(data,datalen,(*dest)); \
        }                                    \
    } while(0)
#define bignum_bn2dec(num) BN_bn2dec(num)
#define bignum_dec2bn(data, bn) BN_dec2bn(bn, data)
#define bignum_hex2bn(data, bn) BN_hex2bn(bn, data)
#define bignum_bn2hex(num, dest) (*dest)=(unsigned char *)BN_bn2hex(num)
#define bignum_rand(rnd, bits) BN_rand(rnd, bits, 0, 1)
#define bignum_rand_range(rnd, max) BN_rand_range(rnd, max)
#define bignum_ctx_new() BN_CTX_new()
#define bignum_ctx_free(num) BN_CTX_free(num)
#define bignum_ctx_invalid(ctx) ((ctx) == NULL)
#define bignum_mod_exp(dest,generator,exp,modulo,ctx) BN_mod_exp(dest,generator,exp,modulo,ctx)
#define bignum_add(dest, a, b) BN_add(dest, a, b)
#define bignum_sub(dest, a, b) BN_sub(dest, a, b)
#define bignum_mod(dest, a, b, ctx) BN_mod(dest, a, b, ctx)
#define bignum_num_bytes(num) (size_t)BN_num_bytes(num)
#define bignum_num_bits(num) (size_t)BN_num_bits(num)
#define bignum_is_bit_set(num,bit) BN_is_bit_set(num, (int)bit)
#define bignum_bn2bin(num,len, ptr) BN_bn2bin(num, ptr)
#define bignum_cmp(num1,num2) BN_cmp(num1,num2)
#define bignum_rshift1(dest, src) BN_rshift1(dest, src)
#define bignum_dup(orig, dest) do { \
        if (*(dest) == NULL) { \
            *(dest) = BN_dup(orig); \
        } else { \
            BN_copy(*(dest), orig); \
        } \
    } while(0)


/* Returns true if the OpenSSL is operating in FIPS mode */
#ifdef HAVE_OPENSSL_FIPS_MODE
#define ssh_fips_mode() (FIPS_mode() != 0)
#else
#define ssh_fips_mode() false
#endif

#endif /* HAVE_LIBCRYPTO */

#endif /* LIBCRYPTO_H_ */
