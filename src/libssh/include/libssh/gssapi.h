/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Aris Adamantiadis
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

#ifndef GSSAPI_H_
#define GSSAPI_H_

#include "config.h"
#include "session.h"

/* all OID begin with the tag identifier + length */
#define SSH_OID_TAG 06

typedef struct ssh_gssapi_struct *ssh_gssapi;

#ifdef WITH_SERVER
int ssh_gssapi_handle_userauth(ssh_session session, const char *user, uint32_t n_oid, ssh_string *oids);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_server);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic);
#endif /* WITH_SERVER */

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_client);
SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_response);


int ssh_gssapi_auth_mic(ssh_session session);

#endif /* GSSAPI_H */
