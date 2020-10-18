/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#ifndef _SCP_H
#define _SCP_H

enum ssh_scp_states {
  SSH_SCP_NEW,          //Data structure just created
  SSH_SCP_WRITE_INITED, //Gave our intention to write
  SSH_SCP_WRITE_WRITING,//File was opened and currently writing
  SSH_SCP_READ_INITED,  //Gave our intention to read
  SSH_SCP_READ_REQUESTED, //We got a read request
  SSH_SCP_READ_READING, //File is opened and reading
  SSH_SCP_ERROR,         //Something bad happened
  SSH_SCP_TERMINATED	//Transfer finished
};

struct ssh_scp_struct {
  ssh_session session;
  int mode;
  int recursive;
  ssh_channel channel;
  char *location;
  enum ssh_scp_states state;
  uint64_t filelen;
  uint64_t processed;
  enum ssh_scp_request_types request_type;
  char *request_name;
  char *warning;
  int request_mode;
};

int ssh_scp_read_string(ssh_scp scp, char *buffer, size_t len);
int ssh_scp_integer_mode(const char *mode);
char *ssh_scp_string_mode(int mode);
int ssh_scp_response(ssh_scp scp, char **response);

#endif
