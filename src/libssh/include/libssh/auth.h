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

#ifndef AUTH_H_
#define AUTH_H_
#include "config.h"
#include "libssh/callbacks.h"

SSH_PACKET_CALLBACK(ssh_packet_userauth_banner);
SSH_PACKET_CALLBACK(ssh_packet_userauth_failure);
SSH_PACKET_CALLBACK(ssh_packet_userauth_success);
SSH_PACKET_CALLBACK(ssh_packet_userauth_pk_ok);
SSH_PACKET_CALLBACK(ssh_packet_userauth_info_request);
SSH_PACKET_CALLBACK(ssh_packet_userauth_info_response);

/** @internal
 * kdbint structure must be shared with message.c
 * and server.c
 */
struct ssh_kbdint_struct {
    uint32_t nprompts;
    uint32_t nanswers;
    char *name;
    char *instruction;
    char **prompts;
    unsigned char *echo; /* bool array */
    char **answers;
};
typedef struct ssh_kbdint_struct* ssh_kbdint;

ssh_kbdint ssh_kbdint_new(void);
void ssh_kbdint_clean(ssh_kbdint kbd);
void ssh_kbdint_free(ssh_kbdint kbd);

/** @internal
 * States of authentication in the client-side. They describe
 * what was the last response from the server
 */
enum ssh_auth_state_e {
  /** No authentication asked */
  SSH_AUTH_STATE_NONE=0,
  /** Last authentication response was a partial success */
  SSH_AUTH_STATE_PARTIAL,
  /** Last authentication response was a success */
  SSH_AUTH_STATE_SUCCESS,
  /** Last authentication response was failed */
  SSH_AUTH_STATE_FAILED,
  /** Last authentication was erroneous */
  SSH_AUTH_STATE_ERROR,
  /** Last state was a keyboard-interactive ask for info */
  SSH_AUTH_STATE_INFO,
  /** Last state was a public key accepted for authentication */
  SSH_AUTH_STATE_PK_OK,
  /** We asked for a keyboard-interactive authentication */
  SSH_AUTH_STATE_KBDINT_SENT,
  /** We have sent an userauth request with gssapi-with-mic */
  SSH_AUTH_STATE_GSSAPI_REQUEST_SENT,
  /** We are exchanging tokens until authentication */
  SSH_AUTH_STATE_GSSAPI_TOKEN,
  /** We have sent the MIC and expecting to be authenticated */
  SSH_AUTH_STATE_GSSAPI_MIC_SENT,
  /** We have offered a pubkey to check if it is supported */
  SSH_AUTH_STATE_PUBKEY_OFFER_SENT,
  /** We have sent pubkey and signature expecting to be authenticated */
  SSH_AUTH_STATE_PUBKEY_AUTH_SENT,
  /** We have sent a password expecting to be authenticated */
  SSH_AUTH_STATE_PASSWORD_AUTH_SENT,
  /** We have sent a request without auth information (method 'none') */
  SSH_AUTH_STATE_AUTH_NONE_SENT,
};

/** @internal
 * @brief states of the authentication service request
 */
enum ssh_auth_service_state_e {
  /** initial state */
  SSH_AUTH_SERVICE_NONE=0,
  /** Authentication service request packet sent */
  SSH_AUTH_SERVICE_SENT,
  /** Service accepted */
  SSH_AUTH_SERVICE_ACCEPTED,
  /** Access to service denied (fatal) */
  SSH_AUTH_SERVICE_DENIED,
};

#endif /* AUTH_H_ */
