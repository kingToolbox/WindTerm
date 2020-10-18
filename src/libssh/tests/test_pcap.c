/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

/* Simple test for the pcap functions */

#include <libssh/libssh.h>
#include <libssh/pcap.h>
#include <libssh/buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
	ssh_pcap_file pcap;
	ssh_pcap_context ctx;
	ssh_buffer buffer=ssh_buffer_new();
	char *str="Hello, this is a test string to test the capabilities of the"
			"pcap file writer.";
	printf("Simple pcap tester\n");
	pcap=ssh_pcap_file_new();
	if(ssh_pcap_file_open(pcap,"test.cap") != SSH_OK){
		printf("error happened\n");
		return EXIT_FAILURE;
	}
	buffer_add_data(buffer,str,strlen(str));
	ctx=ssh_pcap_context_new(NULL);
	ssh_pcap_context_set_file(ctx,pcap);
	ssh_pcap_context_write(ctx,SSH_PCAP_DIR_OUT,str,strlen(str),strlen(str));

	return EXIT_SUCCESS;
}
