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

#ifndef LIBMBEDCRYPTO_H_
#define LIBMBEDCRYPTO_H_

#include "config.h"

#ifdef HAVE_LIBMBEDCRYPTO

#include <mbedtls/md.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef mbedtls_md_context_t *SHACTX;
typedef mbedtls_md_context_t *SHA256CTX;
typedef mbedtls_md_context_t *SHA384CTX;
typedef mbedtls_md_context_t *SHA512CTX;
typedef mbedtls_md_context_t *MD5CTX;
typedef mbedtls_md_context_t *HMACCTX;
typedef mbedtls_md_context_t *EVPCTX;

#define SHA_DIGEST_LENGTH 20
#define SHA_DIGEST_LEN SHA_DIGEST_LENGTH
#define MD5_DIGEST_LEN 16
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_LEN SHA256_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH 48
#define SHA384_DIGEST_LEN SHA384_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#define SHA512_DIGEST_LEN SHA512_DIGEST_LENGTH

#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE 64
#endif

#define EVP_DIGEST_LEN EVP_MAX_MD_SIZE

typedef mbedtls_mpi *bignum;
typedef const mbedtls_mpi *const_bignum;
typedef void* bignum_CTX;

/* Constants for curves */
#define NID_mbedtls_nistp256 0
#define NID_mbedtls_nistp384 1
#define NID_mbedtls_nistp521 2

struct mbedtls_ecdsa_sig {
    bignum r;
    bignum s;
};

bignum ssh_mbedcry_bn_new(void);
void ssh_mbedcry_bn_free(bignum num);
unsigned char *ssh_mbedcry_bn2num(const_bignum num, int radix);
int ssh_mbedcry_rand(bignum rnd, int bits, int top, int bottom);
int ssh_mbedcry_is_bit_set(bignum num, size_t pos);
int ssh_mbedcry_rand_range(bignum dest, bignum max);
int ssh_mbedcry_hex2bn(bignum *dest, char *data);

#define bignum_new() ssh_mbedcry_bn_new()
#define bignum_safe_free(num) do { \
    if ((num) != NULL) { \
        ssh_mbedcry_bn_free(num); \
        (num)=NULL; \
    } \
    } while(0)
#define bignum_ctx_new() NULL
#define bignum_ctx_free(num) do {(num) = NULL;} while(0)
#define bignum_ctx_invalid(ctx) (ctx == NULL?0:1)
#define bignum_set_word(bn, n) (mbedtls_mpi_lset(bn, n)==0?1:0) /* TODO fix
                                                          overflow/underflow */
#define bignum_bin2bn(data, datalen, bn) do { \
    *(bn) = bignum_new(); \
    if (*(bn) != NULL) { \
        mbedtls_mpi_read_binary(*(bn), data, datalen); \
    } \
    } while(0)
#define bignum_bn2dec(num) ssh_mbedcry_bn2num(num, 10)
#define bignum_dec2bn(data, bn) mbedtls_mpi_read_string(bn, 10, data)
#define bignum_bn2hex(num, dest) (*dest)=ssh_mbedcry_bn2num(num, 16)
#define bignum_hex2bn(data, dest) ssh_mbedcry_hex2bn(dest, data)
#define bignum_rand(rnd, bits) ssh_mbedcry_rand((rnd), (bits), 0, 1)
#define bignum_rand_range(rnd, max) ssh_mbedcry_rand_range(rnd, max)
#define bignum_mod_exp(dest, generator, exp, modulo, ctx) \
        (mbedtls_mpi_exp_mod(dest, generator, exp, modulo, NULL)==0?1:0)
#define bignum_add(dest, a, b) mbedtls_mpi_add_mpi(dest, a, b)
#define bignum_sub(dest, a, b) mbedtls_mpi_sub_mpi(dest, a, b)
#define bignum_mod(dest, a, b, ctx) \
    (mbedtls_mpi_mod_mpi(dest, a, b) == 0 ? 1 : 0)
#define bignum_num_bytes(num) mbedtls_mpi_size(num)
#define bignum_num_bits(num) mbedtls_mpi_bitlen(num)
#define bignum_is_bit_set(num, bit) ssh_mbedcry_is_bit_set(num, bit)
#define bignum_bn2bin(num, len, ptr) mbedtls_mpi_write_binary(num, ptr, \
        mbedtls_mpi_size(num))
#define bignum_cmp(num1, num2) mbedtls_mpi_cmp_mpi(num1, num2)
#define bignum_rshift1(dest, src) mbedtls_mpi_copy(dest, src), mbedtls_mpi_shift_r(dest, 1)
#define bignum_dup(orig, dest) do { \
    if (*(dest) == NULL) { \
        *(dest) = bignum_new(); \
    } \
    if (*(dest) != NULL) { \
        mbedtls_mpi_copy(orig, *(dest)); \
    } \
    } while(0)

mbedtls_ctr_drbg_context *ssh_get_mbedtls_ctr_drbg_context(void);

int ssh_mbedtls_random(void *where, int len, int strong);

ssh_string make_ecpoint_string(const mbedtls_ecp_group *g, const
        mbedtls_ecp_point *p);

#define ssh_fips_mode() false

#endif /* HAVE_LIBMBEDCRYPTO */
#endif /* LIBMBEDCRYPTO_H_ */
