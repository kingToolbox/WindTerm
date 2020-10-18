/*
 * gcrypt_missing.c - routines that are in OpenSSL but not in libgcrypt.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2006 by Aris Adamantiadis
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

#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/libgcrypt.h"

#ifdef HAVE_LIBGCRYPT
int ssh_gcry_dec2bn(bignum *bn, const char *data) {
  int count;

  *bn = bignum_new();
  if (*bn == NULL) {
    return 0;
  }
  gcry_mpi_set_ui(*bn, 0);
  for (count = 0; data[count]; count++) {
    gcry_mpi_mul_ui(*bn, *bn, 10);
    gcry_mpi_add_ui(*bn, *bn, data[count] - '0');
  }

  return count;
}

char *ssh_gcry_bn2dec(bignum bn) {
  bignum bndup, num, ten;
  char *ret;
  int count, count2;
  int size, rsize;
  char decnum;

  size = gcry_mpi_get_nbits(bn) * 3;
  rsize = size / 10 + size / 1000 + 2;

  ret = malloc(rsize + 1);
  if (ret == NULL) {
    return NULL;
  }

  if (!gcry_mpi_cmp_ui(bn, 0)) {
    strcpy(ret, "0");
  } else {
    ten = bignum_new();
    if (ten == NULL) {
      SAFE_FREE(ret);
      return NULL;
    }

    num = bignum_new();
    if (num == NULL) {
      SAFE_FREE(ret);
      bignum_safe_free(ten);
      return NULL;
    }

    for (bndup = gcry_mpi_copy(bn), bignum_set_word(ten, 10), count = rsize;
        count; count--) {
      gcry_mpi_div(bndup, num, bndup, ten, 0);
      for (decnum = 0, count2 = gcry_mpi_get_nbits(num); count2;
          decnum *= 2, decnum += (gcry_mpi_test_bit(num, count2 - 1) ? 1 : 0),
          count2--)
        ;
      ret[count - 1] = decnum + '0';
    }
    for (count = 0; count < rsize && ret[count] == '0'; count++)
      ;
    for (count2 = 0; count2 < rsize - count; ++count2) {
      ret[count2] = ret[count2 + count];
    }
    ret[count2] = 0;
    bignum_safe_free(num);
    bignum_safe_free(bndup);
    bignum_safe_free(ten);
  }

  return ret;
}

/** @brief generates a random integer between 0 and max
 * @returns 1 in case of success, 0 otherwise
 */
int ssh_gcry_rand_range(bignum dest, bignum max)
{
    size_t bits;
    bignum rnd;
    int rc;

    bits = bignum_num_bits(max) + 64;
    rnd = bignum_new();
    if (rnd == NULL) {
        return 0;
    }
    rc = bignum_rand(rnd, bits);
    if (rc != 1) {
        return rc;
    }
    gcry_mpi_mod(dest, rnd, max);
    bignum_safe_free(rnd);
    return 1;
}
#endif
