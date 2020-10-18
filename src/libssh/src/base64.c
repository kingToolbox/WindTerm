/*
 * base64.c - support for base64 alphabet system, described in RFC1521
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2005 by Aris Adamantiadis
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

/* just the dirtiest part of code i ever made */
#include "config.h"

#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"

static
const uint8_t alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "abcdefghijklmnopqrstuvwxyz"
                         "0123456789+/";

/* Transformations */
#define SET_A(n, i) do { (n) |= ((i) & 63) <<18; } while (0)
#define SET_B(n, i) do { (n) |= ((i) & 63) <<12; } while (0)
#define SET_C(n, i) do { (n) |= ((i) & 63) << 6; } while (0)
#define SET_D(n, i) do { (n) |= ((i) & 63); } while (0)

#define GET_A(n) (unsigned char) (((n) & 0xff0000) >> 16)
#define GET_B(n) (unsigned char) (((n) & 0xff00) >> 8)
#define GET_C(n) (unsigned char) ((n) & 0xff)

static int _base64_to_bin(unsigned char dest[3], const char *source, int num);
static int get_equals(char *string);

/* First part: base64 to binary */

/**
 * @internal
 *
 * @brief Translates a base64 string into a binary one.
 *
 * @returns A buffer containing the decoded string, NULL if something went
 *          wrong (e.g. incorrect char).
 */
ssh_buffer base64_to_bin(const char *source) {
  ssh_buffer buffer = NULL;
  unsigned char block[3];
  char *base64;
  char *ptr;
  size_t len;
  int equals;

  base64 = strdup(source);
  if (base64 == NULL) {
    return NULL;
  }
  ptr = base64;

  /* Get the number of equals signs, which mirrors the padding */
  equals = get_equals(ptr);
  if (equals > 2) {
    SAFE_FREE(base64);
    return NULL;
  }

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    SAFE_FREE(base64);
    return NULL;
  }
  /*
   * The base64 buffer often contains sensitive data. Make sure we don't leak
   * sensitive data
   */
  ssh_buffer_set_secure(buffer);

  len = strlen(ptr);
  while (len > 4) {
    if (_base64_to_bin(block, ptr, 3) < 0) {
      goto error;
    }
    if (ssh_buffer_add_data(buffer, block, 3) < 0) {
      goto error;
    }
    len -= 4;
    ptr += 4;
  }

  /*
   * Depending on the number of bytes resting, there are 3 possibilities
   * from the RFC.
   */
  switch (len) {
    /*
     * (1) The final quantum of encoding input is an integral multiple of
     *     24 bits. Here, the final unit of encoded output will be an integral
     *     multiple of 4 characters with no "=" padding
     */
    case 4:
      if (equals != 0) {
        goto error;
      }
      if (_base64_to_bin(block, ptr, 3) < 0) {
        goto error;
      }
      if (ssh_buffer_add_data(buffer, block, 3) < 0) {
        goto error;
      }
      SAFE_FREE(base64);

      return buffer;
    /*
     * (2) The final quantum of encoding input is exactly 8 bits; here, the
     *     final unit of encoded output will be two characters followed by
     *     two "=" padding characters.
     */
    case 2:
      if (equals != 2){
        goto error;
      }

      if (_base64_to_bin(block, ptr, 1) < 0) {
        goto error;
      }
      if (ssh_buffer_add_data(buffer, block, 1) < 0) {
        goto error;
      }
      SAFE_FREE(base64);

      return buffer;
    /*
     * The final quantum of encoding input is exactly 16 bits. Here, the final
     * unit of encoded output will be three characters followed by one "="
     * padding character.
     */
    case 3:
      if (equals != 1) {
        goto error;
      }
      if (_base64_to_bin(block, ptr, 2) < 0) {
        goto error;
      }
      if (ssh_buffer_add_data(buffer,block,2) < 0) {
        goto error;
      }
      SAFE_FREE(base64);

      return buffer;
    default:
      /* 4,3,2 are the only padding size allowed */
      goto error;
  }

error:
  SAFE_FREE(base64);
  SSH_BUFFER_FREE(buffer);
  return NULL;
}

#define BLOCK(letter, n) do {ptr = strchr((const char *)alphabet, source[n]); \
                             if(!ptr) return -1; \
                             i = ptr - (const char *)alphabet; \
                             SET_##letter(*block, i); \
                         } while(0)

/* Returns 0 if ok, -1 if not (ie invalid char into the stuff) */
static int to_block4(unsigned long *block, const char *source, int num) {
  const char *ptr = NULL;
  unsigned int i;

  *block = 0;
  if (num < 1) {
    return 0;
  }

  BLOCK(A, 0); /* 6 bit */
  BLOCK(B,1); /* 12 bit */

  if (num < 2) {
    return 0;
  }

  BLOCK(C, 2); /* 18 bit */

  if (num < 3) {
    return 0;
  }

  BLOCK(D, 3); /* 24 bit */

  return 0;
}

/* num = numbers of final bytes to be decoded */
static int _base64_to_bin(unsigned char dest[3], const char *source, int num) {
  unsigned long block;

  if (to_block4(&block, source, num) < 0) {
    return -1;
  }
  dest[0] = GET_A(block);
  dest[1] = GET_B(block);
  dest[2] = GET_C(block);

  return 0;
}

/* Count the number of "=" signs and replace them by zeroes */
static int get_equals(char *string) {
  char *ptr = string;
  int num = 0;

  while ((ptr=strchr(ptr,'=')) != NULL) {
    num++;
    *ptr = '\0';
    ptr++;
  }

  return num;
}

/* thanks sysk for debugging my mess :) */
static void _bin_to_base64(uint8_t *dest,
                           const uint8_t source[3],
                           size_t len)
{
#define BITS(n) ((1 << (n)) - 1)
    switch (len) {
        case 1:
            dest[0] = alphabet[(source[0] >> 2)];
            dest[1] = alphabet[((source[0] & BITS(2)) << 4)];
            dest[2] = '=';
            dest[3] = '=';
            break;
        case 2:
            dest[0] = alphabet[source[0] >> 2];
            dest[1] = alphabet[(source[1] >> 4) | ((source[0] & BITS(2)) << 4)];
            dest[2] = alphabet[(source[1] & BITS(4)) << 2];
            dest[3] = '=';
            break;
        case 3:
            dest[0] = alphabet[(source[0] >> 2)];
            dest[1] = alphabet[(source[1] >> 4) | ((source[0] & BITS(2)) << 4)];
            dest[2] = alphabet[(source[2] >> 6) | (source[1] & BITS(4)) << 2];
            dest[3] = alphabet[source[2] & BITS(6)];
            break;
    }
#undef BITS
}

/**
 * @internal
 *
 * @brief Converts binary data to a base64 string.
 *
 * @returns the converted string
 */
uint8_t *bin_to_base64(const uint8_t *source, size_t len)
{
    uint8_t *base64 = NULL;
    uint8_t *ptr = NULL;
    size_t flen = len + (3 - (len % 3)); /* round to upper 3 multiple */
    flen = (4 * flen) / 3 + 1;

    base64 = malloc(flen);
    if (base64 == NULL) {
        return NULL;
    }
    ptr = base64;

    while(len > 0){
        _bin_to_base64(ptr, source, len > 3 ? 3 : len);
        ptr += 4;
        if (len < 3) {
            break;
        }
        source += 3;
        len -= 3;
    }
    ptr[0] = '\0';

    return base64;
}
