/*
 * crypt.c - blowfish-cbc code
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003 by Aris Adamantiadis
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef OPENSSL_CRYPTO
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/wrapper.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/bytearray.h"

/** @internal
 * @brief decrypt the packet length from a raw encrypted packet, and store the first decrypted
 * blocksize.
 * @returns native byte-ordered decrypted length of the upcoming packet
 */
uint32_t ssh_packet_decrypt_len(ssh_session session,
                                uint8_t *destination,
                                uint8_t *source)
{
    struct ssh_crypto_struct *crypto = NULL;
    uint32_t decrypted;
    int rc;

    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_IN);
    if (crypto != NULL) {
        if (crypto->in_cipher->aead_decrypt_length != NULL) {
            rc = crypto->in_cipher->aead_decrypt_length(
                    crypto->in_cipher, source, destination,
                    crypto->in_cipher->lenfield_blocksize,
                    session->recv_seq);
        } else {
            rc = ssh_packet_decrypt(
                    session,
                    destination,
                    source,
                    0,
                    crypto->in_cipher->blocksize);
        }
        if (rc < 0) {
            return 0;
        }
    } else {
        memcpy(destination, source, 8);
    }
    memcpy(&decrypted,destination,sizeof(decrypted));

    return ntohl(decrypted);
}

/** @internal
 * @brief decrypts the content of an SSH packet.
 * @param[source] source packet, including the encrypted length field
 * @param[start] index in the packet that was not decrypted yet.
 * @param[encrypted_size] size of the encrypted data to be decrypted after start.
 */
int ssh_packet_decrypt(ssh_session session,
                       uint8_t *destination,
                       uint8_t *source,
                       size_t start,
                       size_t encrypted_size)
{
    struct ssh_crypto_struct *crypto = NULL;
    struct ssh_cipher_struct *cipher = NULL;

    if (encrypted_size <= 0) {
        return SSH_ERROR;
    }

    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_IN);
    if (crypto == NULL) {
        return SSH_ERROR;
    }
    cipher = crypto->in_cipher;

    if (encrypted_size % cipher->blocksize != 0) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Cryptographic functions must be used on multiple of "
                      "blocksize (received %" PRIdS ")",
                      encrypted_size);
        return SSH_ERROR;
    }

    if (cipher->aead_decrypt != NULL) {
        return cipher->aead_decrypt(cipher,
                                    source,
                                    destination,
                                    encrypted_size,
                                    session->recv_seq);
    } else {
        cipher->decrypt(cipher, source + start, destination, encrypted_size);
    }

    return 0;
}

unsigned char *ssh_packet_encrypt(ssh_session session, void *data, uint32_t len)
{
  struct ssh_crypto_struct *crypto = NULL;
  struct ssh_cipher_struct *cipher = NULL;
  HMACCTX ctx = NULL;
  char *out = NULL;
  int etm_packet_offset = 0;
  unsigned int finallen, blocksize;
  uint32_t seq, lenfield_blocksize;
  enum ssh_hmac_e type;
  bool etm;

  assert(len);

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_OUT);
  if (crypto == NULL) {
      return NULL; /* nothing to do here */
  }

  blocksize = crypto->out_cipher->blocksize;
  lenfield_blocksize = crypto->out_cipher->lenfield_blocksize;

  type = crypto->out_hmac;
  etm = crypto->out_hmac_etm;

  if (etm) {
      etm_packet_offset = sizeof(uint32_t);
  }

  if ((len - lenfield_blocksize - etm_packet_offset) % blocksize != 0) {
      ssh_set_error(session, SSH_FATAL, "Cryptographic functions must be set"
                    " on at least one blocksize (received %d)", len);
      return NULL;
  }
  out = calloc(1, len);
  if (out == NULL) {
    return NULL;
  }

  seq = ntohl(session->send_seq);
  cipher = crypto->out_cipher;

  if (cipher->aead_encrypt != NULL) {
      cipher->aead_encrypt(cipher, data, out, len,
            crypto->hmacbuf, session->send_seq);
      memcpy(data, out, len);
  } else {
      ctx = hmac_init(crypto->encryptMAC, hmac_digest_len(type), type);
      if (ctx == NULL) {
        SAFE_FREE(out);
        return NULL;
      }

      if (!etm) {
          hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
          hmac_update(ctx, data, len);
          hmac_final(ctx, crypto->hmacbuf, &finallen);
      }

      cipher->encrypt(cipher, (uint8_t*)data + etm_packet_offset, out, len - etm_packet_offset);
      memcpy((uint8_t*)data + etm_packet_offset, out, len - etm_packet_offset);

      if (etm) {
          PUSH_BE_U32(data, 0, len - etm_packet_offset);
          hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
          hmac_update(ctx, data, len);
          hmac_final(ctx, crypto->hmacbuf, &finallen);
      }
#ifdef DEBUG_CRYPTO
      ssh_log_hexdump("mac: ", data, len);
      if (finallen != hmac_digest_len(type)) {
          printf("Final len is %d\n", finallen);
      }
      ssh_log_hexdump("Packet hmac", crypto->hmacbuf, hmac_digest_len(type));
#endif
  }
  explicit_bzero(out, len);
  SAFE_FREE(out);

  return crypto->hmacbuf;
}

static int secure_memcmp(const void *s1, const void *s2, size_t n)
{
    int rc = 0;
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;
    for (; n > 0; --n) {
        rc |= *p1++ ^ *p2++;
    }
    return (rc != 0);
}

/**
 * @internal
 *
 * @brief Verify the hmac of a packet
 *
 * @param  session      The session to use.
 * @param  data         The pointer to the data to verify the hmac from.
 * @param  len          The length of the given data.
 * @param  mac          The mac to compare with the hmac.
 *
 * @return              0 if hmac and mac are equal, < 0 if not or an error
 *                      occurred.
 */
int ssh_packet_hmac_verify(ssh_session session,
                           const void *data,
                           size_t len,
                           uint8_t *mac,
                           enum ssh_hmac_e type)
{
  struct ssh_crypto_struct *crypto = NULL;
  unsigned char hmacbuf[DIGEST_MAX_LEN] = {0};
  HMACCTX ctx;
  unsigned int hmaclen;
  uint32_t seq;

  /* AEAD types have no mac checking */
  if (type == SSH_HMAC_AEAD_POLY1305 ||
      type == SSH_HMAC_AEAD_GCM) {
      return SSH_OK;
  }

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_IN);
  if (crypto == NULL) {
      return SSH_ERROR;
  }

  ctx = hmac_init(crypto->decryptMAC, hmac_digest_len(type), type);
  if (ctx == NULL) {
    return -1;
  }

  seq = htonl(session->recv_seq);

  hmac_update(ctx, (unsigned char *) &seq, sizeof(uint32_t));
  hmac_update(ctx, data, len);
  hmac_final(ctx, hmacbuf, &hmaclen);

#ifdef DEBUG_CRYPTO
  ssh_log_hexdump("received mac",mac,hmaclen);
  ssh_log_hexdump("Computed mac",hmacbuf,hmaclen);
  ssh_log_hexdump("seq",(unsigned char *)&seq,sizeof(uint32_t));
#endif
  if (secure_memcmp(mac, hmacbuf, hmaclen) == 0) {
    return 0;
  }

  return -1;
}
