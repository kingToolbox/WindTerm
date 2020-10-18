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

#ifndef PACKET_H_
#define PACKET_H_

#include "libssh/wrapper.h"

struct ssh_socket_struct;

/* this structure should go someday */
typedef struct packet_struct {
	int valid;
	uint32_t len;
	uint8_t type;
} PACKET;

/** different state of packet reading. */
enum ssh_packet_state_e {
  /** Packet not initialized, must read the size of packet */
  PACKET_STATE_INIT,
  /** Size was read, waiting for the rest of data */
  PACKET_STATE_SIZEREAD,
  /** Full packet was read and callbacks are being called. Future packets
   * should wait for the end of the callback. */
  PACKET_STATE_PROCESSING
};

enum ssh_packet_filter_result_e {
    SSH_PACKET_UNKNOWN,
    SSH_PACKET_ALLOWED,
    SSH_PACKET_DENIED
};

int ssh_packet_send(ssh_session session);

SSH_PACKET_CALLBACK(ssh_packet_unimplemented);
SSH_PACKET_CALLBACK(ssh_packet_disconnect_callback);
SSH_PACKET_CALLBACK(ssh_packet_ignore_callback);
SSH_PACKET_CALLBACK(ssh_packet_dh_reply);
SSH_PACKET_CALLBACK(ssh_packet_newkeys);
SSH_PACKET_CALLBACK(ssh_packet_service_accept);
SSH_PACKET_CALLBACK(ssh_packet_ext_info);

#ifdef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_kexdh_init);
#endif

int ssh_packet_send_unimplemented(ssh_session session, uint32_t seqnum);
int ssh_packet_parse_type(ssh_session session);
//int packet_flush(ssh_session session, int enforce_blocking);

int ssh_packet_socket_callback(const void *data, size_t len, void *user);
void ssh_packet_register_socket_callback(ssh_session session, struct ssh_socket_struct *s);
void ssh_packet_set_callbacks(ssh_session session, ssh_packet_callbacks callbacks);
void ssh_packet_remove_callbacks(ssh_session session, ssh_packet_callbacks callbacks);
void ssh_packet_set_default_callbacks(ssh_session session);
void ssh_packet_process(ssh_session session, uint8_t type);

/* PACKET CRYPT */
uint32_t ssh_packet_decrypt_len(ssh_session session, uint8_t *destination, uint8_t *source);
int ssh_packet_decrypt(ssh_session session, uint8_t *destination, uint8_t *source,
        size_t start, size_t encrypted_size);
unsigned char *ssh_packet_encrypt(ssh_session session,
                                  void *packet,
                                  unsigned int len);
int ssh_packet_hmac_verify(ssh_session session, const void *data, size_t len,
                           unsigned char *mac, enum ssh_hmac_e type);
int ssh_packet_set_newkeys(ssh_session session,
                           enum ssh_crypto_direction_e direction);
struct ssh_crypto_struct *ssh_packet_get_current_crypto(ssh_session session,
        enum ssh_crypto_direction_e direction);

#endif /* PACKET_H_ */
