/*
 * wrapper.c - wrapper for crytpo functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013   by Aris Adamantiadis
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

/*
 * Why a wrapper?
 *
 * Let's say you want to port libssh from libcrypto of openssl to libfoo
 * you are going to spend hours to remove every references to SHA1_Update()
 * to libfoo_sha1_update after the work is finished, you're going to have
 * only this file to modify it's not needed to say that your modifications
 * are welcome.
 */

#include "config.h"


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"
#include "libssh/pki.h"
#include "libssh/poly1305.h"
#include "libssh/dh.h"
#ifdef WITH_GEX
#include "libssh/dh-gex.h"
#endif /* WITH_GEX */
#include "libssh/ecdh.h"
#include "libssh/curve25519.h"

static struct ssh_hmac_struct ssh_hmac_tab[] = {
  { "hmac-sha1",                     SSH_HMAC_SHA1,          false },
  { "hmac-sha2-256",                 SSH_HMAC_SHA256,        false },
  { "hmac-sha2-512",                 SSH_HMAC_SHA512,        false },
  { "hmac-md5",                      SSH_HMAC_MD5,           false },
  { "aead-poly1305",                 SSH_HMAC_AEAD_POLY1305, false },
  { "aead-gcm",                      SSH_HMAC_AEAD_GCM,      false },
  { "hmac-sha1-etm@openssh.com",     SSH_HMAC_SHA1,          true  },
  { "hmac-sha2-256-etm@openssh.com", SSH_HMAC_SHA256,        true  },
  { "hmac-sha2-512-etm@openssh.com", SSH_HMAC_SHA512,        true  },
  { "hmac-md5-etm@openssh.com",      SSH_HMAC_MD5,           true  },
  { NULL,                            0,                      false }
};

struct ssh_hmac_struct *ssh_get_hmactab(void) {
  return ssh_hmac_tab;
}

size_t hmac_digest_len(enum ssh_hmac_e type) {
  switch(type) {
    case SSH_HMAC_SHA1:
      return SHA_DIGEST_LEN;
    case SSH_HMAC_SHA256:
      return SHA256_DIGEST_LEN;
    case SSH_HMAC_SHA512:
      return SHA512_DIGEST_LEN;
    case SSH_HMAC_MD5:
      return MD5_DIGEST_LEN;
    case SSH_HMAC_AEAD_POLY1305:
      return POLY1305_TAGLEN;
    case SSH_HMAC_AEAD_GCM:
      return AES_GCM_TAGLEN;
    default:
      return 0;
  }
}

const char *ssh_hmac_type_to_string(enum ssh_hmac_e hmac_type, bool etm)
{
  int i = 0;
  struct ssh_hmac_struct *ssh_hmactab = ssh_get_hmactab();
  while (ssh_hmactab[i].name &&
         ((ssh_hmactab[i].hmac_type != hmac_type) ||
          (ssh_hmactab[i].etm != etm))) {
    i++;
  }
  return ssh_hmactab[i].name;
}

/* it allocates a new cipher structure based on its offset into the global table */
static struct ssh_cipher_struct *cipher_new(int offset) {
  struct ssh_cipher_struct *cipher = NULL;

  cipher = malloc(sizeof(struct ssh_cipher_struct));
  if (cipher == NULL) {
    return NULL;
  }

  /* note the memcpy will copy the pointers : so, you shouldn't free them */
  memcpy(cipher, &ssh_get_ciphertab()[offset], sizeof(*cipher));

  return cipher;
}

void ssh_cipher_clear(struct ssh_cipher_struct *cipher){
#ifdef HAVE_LIBGCRYPT
    unsigned int i;
#endif

    if (cipher == NULL) {
        return;
    }

#ifdef HAVE_LIBGCRYPT
    if (cipher->key) {
        for (i = 0; i < (cipher->keylen / sizeof(gcry_cipher_hd_t)); i++) {
            gcry_cipher_close(cipher->key[i]);
        }
        SAFE_FREE(cipher->key);
    }
#endif

    if (cipher->cleanup != NULL) {
        cipher->cleanup(cipher);
    }
}

static void cipher_free(struct ssh_cipher_struct *cipher) {
  ssh_cipher_clear(cipher);
  SAFE_FREE(cipher);
}

struct ssh_crypto_struct *crypto_new(void) {
   struct ssh_crypto_struct *crypto;

  crypto = malloc(sizeof(struct ssh_crypto_struct));
  if (crypto == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(crypto);
  return crypto;
}

void crypto_free(struct ssh_crypto_struct *crypto)
{
    size_t i;

    if (crypto == NULL) {
        return;
    }

    ssh_key_free(crypto->server_pubkey);

    ssh_dh_cleanup(crypto);
    bignum_safe_free(crypto->shared_secret);
#ifdef HAVE_ECDH
    SAFE_FREE(crypto->ecdh_client_pubkey);
    SAFE_FREE(crypto->ecdh_server_pubkey);
    if(crypto->ecdh_privkey != NULL){
#ifdef HAVE_OPENSSL_ECC
        EC_KEY_free(crypto->ecdh_privkey);
#elif defined HAVE_GCRYPT_ECC
        gcry_sexp_release(crypto->ecdh_privkey);
#endif
        crypto->ecdh_privkey = NULL;
    }
#endif
    if (crypto->session_id != NULL) {
        explicit_bzero(crypto->session_id, crypto->digest_len);
        SAFE_FREE(crypto->session_id);
    }
    if (crypto->secret_hash != NULL) {
        explicit_bzero(crypto->secret_hash, crypto->digest_len);
        SAFE_FREE(crypto->secret_hash);
    }
#ifdef WITH_ZLIB
    if (crypto->compress_out_ctx &&
        (deflateEnd(crypto->compress_out_ctx) != 0)) {
        inflateEnd(crypto->compress_out_ctx);
    }
    SAFE_FREE(crypto->compress_out_ctx);

    if (crypto->compress_in_ctx &&
        (deflateEnd(crypto->compress_in_ctx) != 0)) {
        inflateEnd(crypto->compress_in_ctx);
    }
    SAFE_FREE(crypto->compress_in_ctx);
#endif /* WITH_ZLIB */
    SAFE_FREE(crypto->encryptIV);
    SAFE_FREE(crypto->decryptIV);
    SAFE_FREE(crypto->encryptMAC);
    SAFE_FREE(crypto->decryptMAC);
    if (crypto->encryptkey != NULL) {
        explicit_bzero(crypto->encryptkey, crypto->out_cipher->keysize / 8);
        SAFE_FREE(crypto->encryptkey);
    }
    if (crypto->decryptkey != NULL) {
        explicit_bzero(crypto->decryptkey, crypto->in_cipher->keysize / 8);
        SAFE_FREE(crypto->decryptkey);
    }

    cipher_free(crypto->in_cipher);
    cipher_free(crypto->out_cipher);

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        SAFE_FREE(crypto->client_kex.methods[i]);
        SAFE_FREE(crypto->server_kex.methods[i]);
        SAFE_FREE(crypto->kex_methods[i]);
    }

    explicit_bzero(crypto, sizeof(struct ssh_crypto_struct));

    SAFE_FREE(crypto);
}

static int crypt_set_algorithms2(ssh_session session)
{
    const char *wanted = NULL;
    struct ssh_cipher_struct *ssh_ciphertab=ssh_get_ciphertab();
    struct ssh_hmac_struct *ssh_hmactab=ssh_get_hmactab();
    size_t i = 0;
    int cmp;

    /*
     * We must scan the kex entries to find crypto algorithms and set their
     * appropriate structure.
     */

    /* out */
    wanted = session->next_crypto->kex_methods[SSH_CRYPT_C_S];
    for (i = 0; i < 64 && ssh_ciphertab[i].name != NULL; ++i) {
        cmp = strcmp(wanted, ssh_ciphertab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_ciphertab[i].name == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "crypt_set_algorithms2: no crypto algorithm function found for %s",
                wanted);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set output algorithm to %s", wanted);

    session->next_crypto->out_cipher = cipher_new(i);
    if (session->next_crypto->out_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    if (session->next_crypto->out_cipher->aead_encrypt != NULL) {
        /* this cipher has integrated MAC */
        if (session->next_crypto->out_cipher->ciphertype == SSH_AEAD_CHACHA20_POLY1305) {
            wanted = "aead-poly1305";
        } else {
            wanted = "aead-gcm";
        }
    } else {
        /*
         * We must scan the kex entries to find hmac algorithms and set their
         * appropriate structure.
         */

        /* out */
        wanted = session->next_crypto->kex_methods[SSH_MAC_C_S];
    }

    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(wanted, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_hmactab[i].name == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "crypt_set_algorithms2: no hmac algorithm function found for %s",
                wanted);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC output algorithm to %s", wanted);

    session->next_crypto->out_hmac = ssh_hmactab[i].hmac_type;
    session->next_crypto->out_hmac_etm = ssh_hmactab[i].etm;

    /* in */
    wanted = session->next_crypto->kex_methods[SSH_CRYPT_S_C];

    for (i = 0; ssh_ciphertab[i].name != NULL; i++) {
        cmp = strcmp(wanted, ssh_ciphertab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_ciphertab[i].name == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "Crypt_set_algorithms: no crypto algorithm function found for %s",
                wanted);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set input algorithm to %s", wanted);

    session->next_crypto->in_cipher = cipher_new(i);
    if (session->next_crypto->in_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    if (session->next_crypto->in_cipher->aead_encrypt != NULL){
        /* this cipher has integrated MAC */
        if (session->next_crypto->in_cipher->ciphertype == SSH_AEAD_CHACHA20_POLY1305) {
            wanted = "aead-poly1305";
        } else {
            wanted = "aead-gcm";
        }
    } else {
        /* we must scan the kex entries to find hmac algorithms and set their appropriate structure */
        wanted = session->next_crypto->kex_methods[SSH_MAC_S_C];
    }

    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(wanted, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_hmactab[i].name == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "crypt_set_algorithms2: no hmac algorithm function found for %s",
                wanted);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC input algorithm to %s", wanted);

    session->next_crypto->in_hmac = ssh_hmactab[i].hmac_type;
    session->next_crypto->in_hmac_etm = ssh_hmactab[i].etm;

    /* compression */
    cmp = strcmp(session->next_crypto->kex_methods[SSH_COMP_C_S], "zlib");
    if (cmp == 0) {
        session->next_crypto->do_compress_out = 1;
    }
    cmp = strcmp(session->next_crypto->kex_methods[SSH_COMP_S_C], "zlib");
    if (cmp == 0) {
        session->next_crypto->do_compress_in = 1;
    }
    cmp = strcmp(session->next_crypto->kex_methods[SSH_COMP_C_S], "zlib@openssh.com");
    if (cmp == 0) {
        session->next_crypto->delayed_compress_out = 1;
    }
    cmp = strcmp(session->next_crypto->kex_methods[SSH_COMP_S_C], "zlib@openssh.com");
    if (cmp == 0) {
        session->next_crypto->delayed_compress_in = 1;
    }

    return SSH_OK;
}

int crypt_set_algorithms_client(ssh_session session)
{
    return crypt_set_algorithms2(session);
}

#ifdef WITH_SERVER
int crypt_set_algorithms_server(ssh_session session){
    const char *method = NULL;
    size_t i = 0;
    struct ssh_cipher_struct *ssh_ciphertab=ssh_get_ciphertab();
    struct ssh_hmac_struct   *ssh_hmactab=ssh_get_hmactab();
    int cmp;


    if (session == NULL) {
        return SSH_ERROR;
    }

    /*
     * We must scan the kex entries to find crypto algorithms and set their
     * appropriate structure
     */
    /* out */
    method = session->next_crypto->kex_methods[SSH_CRYPT_S_C];

    for (i = 0; ssh_ciphertab[i].name != NULL; i++) {
        cmp = strcmp(method, ssh_ciphertab[i].name);
        if (cmp == 0) {
          break;
        }
    }

    if (ssh_ciphertab[i].name == NULL) {
        ssh_set_error(session,SSH_FATAL,"crypt_set_algorithms_server : "
                "no crypto algorithm function found for %s",method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET,"Set output algorithm %s",method);

    session->next_crypto->out_cipher = cipher_new(i);
    if (session->next_crypto->out_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    if (session->next_crypto->out_cipher->aead_encrypt != NULL){
        /* this cipher has integrated MAC */
        if (session->next_crypto->out_cipher->ciphertype == SSH_AEAD_CHACHA20_POLY1305) {
            method = "aead-poly1305";
        } else {
            method = "aead-gcm";
        }
    } else {
        /* we must scan the kex entries to find hmac algorithms and set their appropriate structure */
        /* out */
        method = session->next_crypto->kex_methods[SSH_MAC_S_C];
    }
    /* HMAC algorithm selection */

    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(method, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_hmactab[i].name == NULL) {
      ssh_set_error(session, SSH_FATAL,
          "crypt_set_algorithms_server: no hmac algorithm function found for %s",
          method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC output algorithm to %s", method);

    session->next_crypto->out_hmac = ssh_hmactab[i].hmac_type;
    session->next_crypto->out_hmac_etm = ssh_hmactab[i].etm;

    /* in */
    method = session->next_crypto->kex_methods[SSH_CRYPT_C_S];

    for (i = 0; ssh_ciphertab[i].name; i++) {
        cmp = strcmp(method, ssh_ciphertab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_ciphertab[i].name == NULL) {
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms_server :"
                "no crypto algorithm function found for %s",method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET,"Set input algorithm %s",method);

    session->next_crypto->in_cipher = cipher_new(i);
    if (session->next_crypto->in_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    if (session->next_crypto->in_cipher->aead_encrypt != NULL){
        /* this cipher has integrated MAC */
        if (session->next_crypto->in_cipher->ciphertype == SSH_AEAD_CHACHA20_POLY1305) {
            method = "aead-poly1305";
        } else {
            method = "aead-gcm";
        }
    } else {
        /* we must scan the kex entries to find hmac algorithms and set their appropriate structure */
        method = session->next_crypto->kex_methods[SSH_MAC_C_S];
    }

    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(method, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }

    if (ssh_hmactab[i].name == NULL) {
      ssh_set_error(session, SSH_FATAL,
          "crypt_set_algorithms_server: no hmac algorithm function found for %s",
          method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC input algorithm to %s", method);

    session->next_crypto->in_hmac = ssh_hmactab[i].hmac_type;
    session->next_crypto->in_hmac_etm = ssh_hmactab[i].etm;

    /* compression */
    method = session->next_crypto->kex_methods[SSH_COMP_C_S];
    if(strcmp(method,"zlib") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling C->S compression");
        session->next_crypto->do_compress_in=1;
    }
    if(strcmp(method,"zlib@openssh.com") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling C->S delayed compression");

        if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) {
            session->next_crypto->do_compress_in = 1;
        } else {
            session->next_crypto->delayed_compress_in = 1;
        }
    }

    method = session->next_crypto->kex_methods[SSH_COMP_S_C];
    if(strcmp(method,"zlib") == 0){
        SSH_LOG(SSH_LOG_PACKET, "enabling S->C compression");
        session->next_crypto->do_compress_out=1;
    }
    if(strcmp(method,"zlib@openssh.com") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling S->C delayed compression");

        if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) {
            session->next_crypto->do_compress_out = 1;
        } else {
            session->next_crypto->delayed_compress_out = 1;
        }
    }

    method = session->next_crypto->kex_methods[SSH_HOSTKEYS];
    session->srv.hostkey = ssh_key_type_from_signature_name(method);
    session->srv.hostkey_digest = ssh_key_hash_from_name(method);

    /* setup DH key exchange type */
    switch (session->next_crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
    case SSH_KEX_DH_GROUP14_SHA256:
    case SSH_KEX_DH_GROUP16_SHA512:
    case SSH_KEX_DH_GROUP18_SHA512:
      ssh_server_dh_init(session);
      break;
#ifdef WITH_GEX
    case SSH_KEX_DH_GEX_SHA1:
    case SSH_KEX_DH_GEX_SHA256:
      ssh_server_dhgex_init(session);
      break;
#endif /* WITH_GEX */
#ifdef HAVE_ECDH
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_ECDH_SHA2_NISTP384:
    case SSH_KEX_ECDH_SHA2_NISTP521:
      ssh_server_ecdh_init(session);
      break;
#endif
#ifdef HAVE_CURVE25519
    case SSH_KEX_CURVE25519_SHA256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
        ssh_server_curve25519_init(session);
        break;
#endif
    default:
        ssh_set_error(session,
                      SSH_FATAL,
                      "crypt_set_algorithms_server: could not find init "
                      "handler for kex type %d",
                      session->next_crypto->kex_type);
        return SSH_ERROR;
    }
    return SSH_OK;
}

#endif /* WITH_SERVER */
