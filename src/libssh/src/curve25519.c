/*
 * curve25519.c - Curve25519 ECDH functions for key exchange
 * curve25519-sha256@libssh.org and curve25519-sha256
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013      by Aris Adamantiadis <aris@badcode.be>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 2.1 of the License.
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

#include "libssh/curve25519.h"
#ifdef HAVE_CURVE25519

#ifdef WITH_NACL
#include "nacl/crypto_scalarmult_curve25519.h"
#endif

#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

#ifdef HAVE_OPENSSL_X25519
#include <openssl/err.h>
#endif

static SSH_PACKET_CALLBACK(ssh_packet_client_curve25519_reply);

static ssh_packet_callback dh_client_callbacks[] = {
    ssh_packet_client_curve25519_reply
};

static struct ssh_packet_callbacks_struct ssh_curve25519_client_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_REPLY,
    .n_callbacks = 1,
    .callbacks = dh_client_callbacks,
    .user = NULL
};

static int ssh_curve25519_init(ssh_session session)
{
    int rc;
#ifdef HAVE_OPENSSL_X25519
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pubkey_len = CURVE25519_PUBKEY_SIZE;
    size_t pkey_len = CURVE25519_PRIVKEY_SIZE;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    rc = EVP_PKEY_keygen_init(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(pctx);
        return SSH_ERROR;
    }

    rc = EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to generate X25519 keys: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    if (session->server) {
        rc = EVP_PKEY_get_raw_public_key(pkey,
                                         session->next_crypto->curve25519_server_pubkey,
                                         &pubkey_len);
    } else {
        rc = EVP_PKEY_get_raw_public_key(pkey,
                                         session->next_crypto->curve25519_client_pubkey,
                                         &pubkey_len);
    }

    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to get X25519 raw public key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return SSH_ERROR;
    }

    rc = EVP_PKEY_get_raw_private_key(pkey,
                                      session->next_crypto->curve25519_privkey,
                                      &pkey_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to get X25519 raw private key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return SSH_ERROR;
    }

    EVP_PKEY_free(pkey);
#else
    rc = ssh_get_random(session->next_crypto->curve25519_privkey,
                        CURVE25519_PRIVKEY_SIZE, 1);
    if (rc != 1) {
        ssh_set_error(session, SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    if (session->server) {
        crypto_scalarmult_base(session->next_crypto->curve25519_server_pubkey,
                               session->next_crypto->curve25519_privkey);
    } else {
        crypto_scalarmult_base(session->next_crypto->curve25519_client_pubkey,
                               session->next_crypto->curve25519_privkey);
    }
#endif /* HAVE_OPENSSL_X25519 */

    return SSH_OK;
}

/** @internal
 * @brief Starts curve25519-sha256@libssh.org / curve25519-sha256 key exchange
 */
int ssh_client_curve25519_init(ssh_session session)
{
    int rc;

    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bdP",
                         SSH2_MSG_KEX_ECDH_INIT,
                         CURVE25519_PUBKEY_SIZE,
                         (size_t)CURVE25519_PUBKEY_SIZE,
                         session->next_crypto->curve25519_client_pubkey);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_curve25519_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;
    rc = ssh_packet_send(session);

    return rc;
}

static int ssh_curve25519_build_k(ssh_session session)
{
    ssh_curve25519_pubkey k;

#ifdef HAVE_OPENSSL_X25519
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL, *pubkey = NULL;
    size_t shared_key_len = sizeof(k);
    int rc, ret = SSH_ERROR;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                        session->next_crypto->curve25519_privkey,
                                        CURVE25519_PRIVKEY_SIZE);
    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create X25519 EVP_PKEY: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive_init(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 key derivation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (session->server) {
        pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                             session->next_crypto->curve25519_client_pubkey,
                                             CURVE25519_PUBKEY_SIZE);
    } else {
        pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                             session->next_crypto->curve25519_server_pubkey,
                                             CURVE25519_PUBKEY_SIZE);
    }
    if (pubkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create X25519 public key EVP_PKEY: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive_set_peer(pctx, pubkey);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to set peer X25519 public key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive(pctx, k, &shared_key_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to derive X25519 shared secret: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    ret = SSH_OK;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(pctx);
    if (ret == SSH_ERROR) {
        return ret;
    }
#else
    if (session->server) {
        crypto_scalarmult(k, session->next_crypto->curve25519_privkey,
                          session->next_crypto->curve25519_client_pubkey);
    } else {
        crypto_scalarmult(k, session->next_crypto->curve25519_privkey,
                          session->next_crypto->curve25519_server_pubkey);
    }
#endif /* HAVE_OPENSSL_X25519 */

    bignum_bin2bn(k, CURVE25519_PUBKEY_SIZE, &session->next_crypto->shared_secret);
    if (session->next_crypto->shared_secret == NULL) {
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("Session server cookie",
                   session->next_crypto->server_kex.cookie, 16);
    ssh_log_hexdump("Session client cookie",
                   session->next_crypto->client_kex.cookie, 16);
    ssh_print_bignum("Shared secret key", session->next_crypto->shared_secret);
#endif

  return 0;
}

/** @internal
 * @brief parses a SSH_MSG_KEX_ECDH_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
static SSH_PACKET_CALLBACK(ssh_packet_client_curve25519_reply){
  ssh_string q_s_string = NULL;
  ssh_string pubkey_blob = NULL;
  ssh_string signature = NULL;
  int rc;
  (void)type;
  (void)user;

  ssh_packet_remove_callbacks(session, &ssh_curve25519_client_callbacks);

  pubkey_blob = ssh_buffer_get_ssh_string(packet);
  if (pubkey_blob == NULL) {
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }

  rc = ssh_dh_import_next_pubkey_blob(session, pubkey_blob);
  SSH_STRING_FREE(pubkey_blob);
  if (rc != 0) {
      ssh_set_error(session,
                    SSH_FATAL,
                    "Failed to import next public key");
      goto error;
  }

  q_s_string = ssh_buffer_get_ssh_string(packet);
  if (q_s_string == NULL) {
	  ssh_set_error(session,SSH_FATAL, "No Q_S ECC point in packet");
	  goto error;
  }
  if (ssh_string_len(q_s_string) != CURVE25519_PUBKEY_SIZE){
	  ssh_set_error(session, SSH_FATAL, "Incorrect size for server Curve25519 public key: %d",
			  (int)ssh_string_len(q_s_string));
	  SSH_STRING_FREE(q_s_string);
	  goto error;
  }
  memcpy(session->next_crypto->curve25519_server_pubkey, ssh_string_data(q_s_string), CURVE25519_PUBKEY_SIZE);
  SSH_STRING_FREE(q_s_string);

  signature = ssh_buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  /* TODO: verify signature now instead of waiting for NEWKEYS */
  if (ssh_curve25519_build_k(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot build k number");
    goto error;
  }

  /* Send the MSG_NEWKEYS */
  if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
    goto error;
  }

  rc=ssh_packet_send(session);
  if (rc == SSH_ERROR) {
    goto error;
  }

  SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");
  session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

  return SSH_PACKET_USED;

error:
  session->session_state=SSH_SESSION_STATE_ERROR;
  return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

static SSH_PACKET_CALLBACK(ssh_packet_server_curve25519_init);

static ssh_packet_callback dh_server_callbacks[]= {
    ssh_packet_server_curve25519_init
};

static struct ssh_packet_callbacks_struct ssh_curve25519_server_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_INIT,
    .n_callbacks = 1,
    .callbacks = dh_server_callbacks,
    .user = NULL
};

/** @internal
 * @brief sets up the curve25519-sha256@libssh.org kex callbacks
 */
void ssh_server_curve25519_init(ssh_session session){
    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_curve25519_server_callbacks);
}

/** @brief Parse a SSH_MSG_KEXDH_INIT packet (server) and send a
 * SSH_MSG_KEXDH_REPLY
 */
static SSH_PACKET_CALLBACK(ssh_packet_server_curve25519_init){
    /* ECDH keys */
    ssh_string q_c_string;
    ssh_string q_s_string;
    ssh_string server_pubkey_blob = NULL;

    /* SSH host keys (rsa,dsa,ecdsa) */
    ssh_key privkey;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    int rc;
    (void)type;
    (void)user;

    ssh_packet_remove_callbacks(session, &ssh_curve25519_server_callbacks);

    /* Extract the client pubkey from the init packet */
    q_c_string = ssh_buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session,SSH_FATAL, "No Q_C ECC point in packet");
        goto error;
    }
    if (ssh_string_len(q_c_string) != CURVE25519_PUBKEY_SIZE){
        ssh_set_error(session,
                      SSH_FATAL,
                      "Incorrect size for server Curve25519 public key: %zu",
                      ssh_string_len(q_c_string));
        SSH_STRING_FREE(q_c_string);
        goto error;
    }

    memcpy(session->next_crypto->curve25519_client_pubkey,
           ssh_string_data(q_c_string), CURVE25519_PUBKEY_SIZE);
    SSH_STRING_FREE(q_c_string);
    /* Build server's keypair */

    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Failed to generate curve25519 keys");
        goto error;
    }

    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_ECDH_REPLY);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* build k and session_id */
    rc = ssh_curve25519_build_k(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto error;
    }

    /* privkey is not allocated */
    rc = ssh_get_key_params(session, &privkey, &digest);
    if (rc == SSH_ERROR) {
        goto error;
    }

    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto error;
    }

    rc = ssh_dh_get_next_server_publickey_blob(session, &server_pubkey_blob);
    if (rc != 0) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        goto error;
    }

    /* add host's public key */
    rc = ssh_buffer_add_ssh_string(session->out_buffer,
                                   server_pubkey_blob);
    SSH_STRING_FREE(server_pubkey_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* add ecdh public key */
    q_s_string = ssh_string_new(CURVE25519_PUBKEY_SIZE);
    if (q_s_string == NULL) {
        goto error;
    }

    ssh_string_fill(q_s_string,
                    session->next_crypto->curve25519_server_pubkey,
                    CURVE25519_PUBKEY_SIZE);

    rc = ssh_buffer_add_ssh_string(session->out_buffer, q_s_string);
    SSH_STRING_FREE(q_s_string);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }
    /* add signature blob */
    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey, digest);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        goto error;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, sig_blob);
    SSH_STRING_FREE(sig_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEX_ECDH_REPLY sent");
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    /* Send the MSG_NEWKEYS */
    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc < 0) {
        goto error;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");

    return SSH_PACKET_USED;
error:
    ssh_buffer_reinit(session->out_buffer);
    session->session_state=SSH_SESSION_STATE_ERROR;
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

#endif /* HAVE_CURVE25519 */
