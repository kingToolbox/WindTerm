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

#ifndef PCAP_H_
#define PCAP_H_

#include "config.h"
#include "libssh/libssh.h"

#ifdef WITH_PCAP
typedef struct ssh_pcap_context_struct* ssh_pcap_context;

int ssh_pcap_file_write_packet(ssh_pcap_file pcap, ssh_buffer packet, uint32_t original_len);

ssh_pcap_context ssh_pcap_context_new(ssh_session session);
void ssh_pcap_context_free(ssh_pcap_context ctx);

enum ssh_pcap_direction{
	SSH_PCAP_DIR_IN,
	SSH_PCAP_DIR_OUT
};
void ssh_pcap_context_set_file(ssh_pcap_context, ssh_pcap_file);
int ssh_pcap_context_write(ssh_pcap_context,enum ssh_pcap_direction direction, void *data,
		uint32_t len, uint32_t origlen);


#endif /* WITH_PCAP */
#endif /* PCAP_H_ */
