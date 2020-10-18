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

#include "libssh/priv.h"
#include "libssh/libmbedcrypto.h"

#ifdef HAVE_LIBMBEDCRYPTO
bignum ssh_mbedcry_bn_new(void)
{
    bignum bn;

    bn = malloc(sizeof(mbedtls_mpi));
    if (bn) {
        mbedtls_mpi_init(bn);
    }

    return bn;
}

void ssh_mbedcry_bn_free(bignum bn)
{
    mbedtls_mpi_free(bn);
    SAFE_FREE(bn);
}

unsigned char *ssh_mbedcry_bn2num(const_bignum num, int radix)
{
    char *buf = NULL;
    size_t olen;
    int rc;

    rc = mbedtls_mpi_write_string(num, radix, buf, 0, &olen);
    if (rc != 0 && rc != MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
        return NULL;
    }

    buf = malloc(olen);
    if (buf == NULL) {
        return NULL;
    }

    rc = mbedtls_mpi_write_string(num, radix, buf, olen, &olen);
    if (rc != 0) {
        SAFE_FREE(buf);
        return NULL;
    }

    return (unsigned char *) buf;
}

int ssh_mbedcry_rand(bignum rnd, int bits, int top, int bottom)
{
    size_t len;
    int rc;
    int i;

    if (bits <= 0) {
        return 0;
    }

    len = bits / 8 + 1;
    /* FIXME weird bug: over 1024, fill_random function returns an error code
     * MBEDTLS_ERR_MPI_BAD_INPUT_DATA   -0x0004
     */
    if (len > 1024){
        len = 1024;
    }
    rc = mbedtls_mpi_fill_random(rnd,
                                 len,
                                 mbedtls_ctr_drbg_random,
                                 ssh_get_mbedtls_ctr_drbg_context());
    if (rc != 0) {
        return 0;
    }

    for (i = len * 8 - 1; i >= bits; i--) {
        rc = mbedtls_mpi_set_bit(rnd, i, 0);
        if (rc != 0) {
            return 0;
        }
    }

    if (top == 0) {
        rc = mbedtls_mpi_set_bit(rnd, bits - 1, 0);
        if (rc != 0) {
            return 0;
        }
    }

    if (top == 1) {
        if (bits < 2) {
            return 0;
        }

        rc = mbedtls_mpi_set_bit(rnd, bits - 2, 0);
        if (rc != 0) {
            return 0;
        }
    }

    if (bottom) {
        rc = mbedtls_mpi_set_bit(rnd, 0, 1);
        if (rc != 0) {
            return 0;
        }
    }

    return 1;
}

int ssh_mbedcry_is_bit_set(bignum num, size_t pos)
{
    int bit;
    bit = mbedtls_mpi_get_bit(num, pos);
    return bit;
}

/** @brief generates a random integer between 0 and max
 * @returns 1 in case of success, 0 otherwise
 */
int ssh_mbedcry_rand_range(bignum dest, bignum max)
{
    size_t bits;
    bignum rnd;
    int rc;

    bits = bignum_num_bits(max) + 64;
    rnd = bignum_new();
    if (rnd == NULL){
        return 0;
    }
    rc = bignum_rand(rnd, bits);
    if (rc != 1) {
        bignum_safe_free(rnd);
        return rc;
    }
    mbedtls_mpi_mod_mpi(dest, rnd, max);
    bignum_safe_free(rnd);
    return 1;
}

int ssh_mbedcry_hex2bn(bignum *dest, char *data)
{
    int rc;

    *dest = bignum_new();
    if (*dest == NULL){
        return 0;
    }
    rc = mbedtls_mpi_read_string(*dest, 16, data);
    if (rc == 0) {
        return 1;
    }

    return 0;
}

#endif
