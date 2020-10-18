/*
 * gzip.c - hooks for compression of packets
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003      by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <asn@cryptomilk.org>
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

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/session.h"

#define BLOCKSIZE 4092

static z_stream *initcompress(ssh_session session, int level) {
  z_stream *stream = NULL;
  int status;

  stream = calloc(1, sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }

  status = deflateInit(stream, level);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "status %d inititalising zlib deflate", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer gzip_compress(ssh_session session, ssh_buffer source, int level)
{
  struct ssh_crypto_struct *crypto = NULL;
  z_stream *zout = NULL;
  void *in_ptr = ssh_buffer_get(source);
  unsigned long in_size = ssh_buffer_get_len(source);
  ssh_buffer dest = NULL;
  unsigned char out_buf[BLOCKSIZE] = {0};
  unsigned long len;
  int status;

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_OUT);
  if (crypto == NULL) {
      return NULL;
  }
  zout = crypto->compress_out_ctx;
  if (zout == NULL) {
    zout = crypto->compress_out_ctx = initcompress(session, level);
    if (zout == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zout->next_out = out_buf;
  zout->next_in = in_ptr;
  zout->avail_in = in_size;
  do {
    zout->avail_out = BLOCKSIZE;
    status = deflate(zout, Z_PARTIAL_FLUSH);
    if (status != Z_OK) {
      SSH_BUFFER_FREE(dest);
      ssh_set_error(session, SSH_FATAL,
          "status %d deflating zlib packet", status);
      return NULL;
    }
    len = BLOCKSIZE - zout->avail_out;
    if (ssh_buffer_add_data(dest, out_buf, len) < 0) {
      SSH_BUFFER_FREE(dest);
      return NULL;
    }
    zout->next_out = out_buf;
  } while (zout->avail_out == 0);

  return dest;
}

int compress_buffer(ssh_session session, ssh_buffer buf) {
  ssh_buffer dest = NULL;

  dest = gzip_compress(session, buf, session->opts.compressionlevel);
  if (dest == NULL) {
    return -1;
  }

  if (ssh_buffer_reinit(buf) < 0) {
    SSH_BUFFER_FREE(dest);
    return -1;
  }

  if (ssh_buffer_add_data(buf, ssh_buffer_get(dest), ssh_buffer_get_len(dest)) < 0) {
    SSH_BUFFER_FREE(dest);
    return -1;
  }

  SSH_BUFFER_FREE(dest);
  return 0;
}

/* decompression */

static z_stream *initdecompress(ssh_session session) {
  z_stream *stream = NULL;
  int status;

  stream = calloc(1, sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }

  status = inflateInit(stream);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "Status = %d initiating inflate context!", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer gzip_decompress(ssh_session session, ssh_buffer source, size_t maxlen)
{
  struct ssh_crypto_struct *crypto = NULL;
  z_stream *zin = NULL;
  void *in_ptr = ssh_buffer_get(source);
  unsigned long in_size = ssh_buffer_get_len(source);
  unsigned char out_buf[BLOCKSIZE] = {0};
  ssh_buffer dest = NULL;
  unsigned long len;
  int status;

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_IN);
  if (crypto == NULL) {
      return NULL;
  }

  zin = crypto->compress_in_ctx;
  if (zin == NULL) {
    zin = crypto->compress_in_ctx = initdecompress(session);
    if (zin == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zin->next_out = out_buf;
  zin->next_in = in_ptr;
  zin->avail_in = in_size;

  do {
    zin->avail_out = BLOCKSIZE;
    status = inflate(zin, Z_PARTIAL_FLUSH);
    if (status != Z_OK && status != Z_BUF_ERROR) {
      ssh_set_error(session, SSH_FATAL,
          "status %d inflating zlib packet", status);
      SSH_BUFFER_FREE(dest);
      return NULL;
    }

    len = BLOCKSIZE - zin->avail_out;
    if (ssh_buffer_add_data(dest,out_buf,len) < 0) {
      SSH_BUFFER_FREE(dest);
      return NULL;
    }
    if (ssh_buffer_get_len(dest) > maxlen){
      /* Size of packet exceeded, avoid a denial of service attack */
      SSH_BUFFER_FREE(dest);
      return NULL;
    }
    zin->next_out = out_buf;
  } while (zin->avail_out == 0);

  return dest;
}

int decompress_buffer(ssh_session session,ssh_buffer buf, size_t maxlen){
  ssh_buffer dest = NULL;

  dest = gzip_decompress(session,buf, maxlen);
  if (dest == NULL) {
    return -1;
  }

  if (ssh_buffer_reinit(buf) < 0) {
    SSH_BUFFER_FREE(dest);
    return -1;
  }

  if (ssh_buffer_add_data(buf, ssh_buffer_get(dest), ssh_buffer_get_len(dest)) < 0) {
    SSH_BUFFER_FREE(dest);
    return -1;
  }

  SSH_BUFFER_FREE(dest);
  return 0;
}
