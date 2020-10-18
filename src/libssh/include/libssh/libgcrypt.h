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

#ifndef LIBGCRYPT_H_
#define LIBGCRYPT_H_

#include "config.h"

#ifdef HAVE_LIBGCRYPT

#include <gcrypt.h>
typedef gcry_md_hd_t SHACTX;
typedef gcry_md_hd_t SHA256CTX;
typedef gcry_md_hd_t SHA384CTX;
typedef gcry_md_hd_t SHA512CTX;
typedef gcry_md_hd_t MD5CTX;
typedef gcry_md_hd_t HMACCTX;
typedef gcry_md_hd_t EVPCTX;
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

typedef gcry_mpi_t bignum;
typedef const struct gcry_mpi *const_bignum;
typedef void* bignum_CTX;

/* Constants for curves.  */
#define NID_gcrypt_nistp256 0
#define NID_gcrypt_nistp384 1
#define NID_gcrypt_nistp521 2

/* missing gcrypt functions */
int ssh_gcry_dec2bn(bignum *bn, const char *data);
char *ssh_gcry_bn2dec(bignum bn);
int ssh_gcry_rand_range(bignum rnd, bignum max);

#define bignum_new() gcry_mpi_new(0)
#define bignum_safe_free(num) do { \
    if ((num) != NULL) { \
        gcry_mpi_release((num)); \
        (num)=NULL; \
    } \
    } while (0)
#define bignum_free(num) gcry_mpi_release(num)
#define bignum_ctx_new() NULL
#define bignum_ctx_free(ctx) do {(ctx) = NULL;} while(0)
#define bignum_ctx_invalid(ctx) (ctx != NULL)
#define bignum_set_word(bn,n) (gcry_mpi_set_ui(bn,n)!=NULL ? 1 : 0)
#define bignum_bin2bn(data,datalen,dest) gcry_mpi_scan(dest,GCRYMPI_FMT_USG,data,datalen,NULL)
#define bignum_bn2dec(num) ssh_gcry_bn2dec(num)
#define bignum_dec2bn(num, data) ssh_gcry_dec2bn(data, num)

#define bignum_bn2hex(num, data) \
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, data, NULL, (const gcry_mpi_t)num)

#define bignum_hex2bn(data, num) (gcry_mpi_scan(num,GCRYMPI_FMT_HEX,data,0,NULL)==0?1:0)
#define bignum_rand(num,bits) 1,gcry_mpi_randomize(num,bits,GCRY_STRONG_RANDOM),gcry_mpi_set_bit(num,bits-1),gcry_mpi_set_bit(num,0)
#define bignum_mod_exp(dest,generator,exp,modulo, ctx) 1,gcry_mpi_powm(dest,generator,exp,modulo)
#define bignum_num_bits(num) gcry_mpi_get_nbits(num)
#define bignum_num_bytes(num) ((gcry_mpi_get_nbits(num)+7)/8)
#define bignum_is_bit_set(num,bit) gcry_mpi_test_bit(num,bit)
#define bignum_bn2bin(num,datalen,data) gcry_mpi_print(GCRYMPI_FMT_USG,data,datalen,NULL,num)
#define bignum_cmp(num1,num2) gcry_mpi_cmp(num1,num2)
#define bignum_rshift1(dest, src) gcry_mpi_rshift (dest, src, 1)
#define bignum_add(dst, a, b) gcry_mpi_add(dst, a, b)
#define bignum_sub(dst, a, b) gcry_mpi_sub(dst, a, b)
#define bignum_mod(dst, a, b, ctx) 1,gcry_mpi_mod(dst, a, b)
#define bignum_rand_range(rnd, max) ssh_gcry_rand_range(rnd, max);
#define bignum_dup(orig, dest) do { \
        if (*(dest) == NULL) { \
            *(dest) = gcry_mpi_copy(orig); \
        } else { \
            gcry_mpi_set(*(dest), orig); \
        } \
    } while(0)
/* Helper functions for data conversions.  */

/* Extract an MPI from the given s-expression SEXP named NAME which is
   encoded using INFORMAT and store it in a newly allocated ssh_string
   encoded using OUTFORMAT.  */
ssh_string ssh_sexp_extract_mpi(const gcry_sexp_t sexp,
                                const char *name,
                                enum gcry_mpi_format informat,
                                enum gcry_mpi_format outformat);

#define ssh_fips_mode() false

#endif /* HAVE_LIBGCRYPT */

#endif /* LIBGCRYPT_H_ */
