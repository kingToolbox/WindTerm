/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011-2013 by Aris Adamantiadis
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
#include "libssh/session.h"
#include "libssh/ecdh.h"
#include "libssh/dh.h"
#include "libssh/buffer.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

#ifdef HAVE_ECDH

static SSH_PACKET_CALLBACK(ssh_packet_client_ecdh_reply);

static ssh_packet_callback ecdh_client_callbacks[]= {
    ssh_packet_client_ecdh_reply
};

struct ssh_packet_callbacks_struct ssh_ecdh_client_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_REPLY,
    .n_callbacks = 1,
    .callbacks = ecdh_client_callbacks,
    .user = NULL
};

/** @internal
 * @brief parses a SSH_MSG_KEX_ECDH_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
SSH_PACKET_CALLBACK(ssh_packet_client_ecdh_reply){
  ssh_string q_s_string = NULL;
  ssh_string pubkey_blob = NULL;
  ssh_string signature = NULL;
  int rc;
  (void)type;
  (void)user;

  ssh_packet_remove_callbacks(session, &ssh_ecdh_client_callbacks);
  pubkey_blob = ssh_buffer_get_ssh_string(packet);
  if (pubkey_blob == NULL) {
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }

  rc = ssh_dh_import_next_pubkey_blob(session, pubkey_blob);
  SSH_STRING_FREE(pubkey_blob);
  if (rc != 0) {
      goto error;
  }

  q_s_string = ssh_buffer_get_ssh_string(packet);
  if (q_s_string == NULL) {
    ssh_set_error(session,SSH_FATAL, "No Q_S ECC point in packet");
    goto error;
  }
  session->next_crypto->ecdh_server_pubkey = q_s_string;
  signature = ssh_buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  /* TODO: verify signature now instead of waiting for NEWKEYS */
  if (ecdh_build_k(session) < 0) {
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

static ssh_packet_callback ecdh_server_callbacks[] = {
    ssh_packet_server_ecdh_init
};

struct ssh_packet_callbacks_struct ssh_ecdh_server_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_INIT,
    .n_callbacks = 1,
    .callbacks = ecdh_server_callbacks,
    .user = NULL
};

/** @internal
 * @brief sets up the ecdh kex callbacks
 */
void ssh_server_ecdh_init(ssh_session session){
    ssh_packet_set_callbacks(session, &ssh_ecdh_server_callbacks);
}

#endif /* WITH_SERVER */
#endif /* HAVE_ECDH */
