/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#ifndef BIND_H_
#define BIND_H_

#include "libssh/priv.h"
#include "libssh/kex.h"
#include "libssh/session.h"

struct ssh_bind_struct {
  struct ssh_common_struct common; /* stuff common to ssh_bind and ssh_session */
  struct ssh_bind_callbacks_struct *bind_callbacks;
  void *bind_callbacks_userdata;

  struct ssh_poll_handle_struct *poll;
  /* options */
  char *wanted_methods[SSH_KEX_METHODS];
  char *banner;
  char *ecdsakey;
  char *dsakey;
  char *rsakey;
  char *ed25519key;
  ssh_key ecdsa;
  ssh_key dsa;
  ssh_key rsa;
  ssh_key ed25519;
  char *bindaddr;
  socket_t bindfd;
  unsigned int bindport;
  int blocking;
  int toaccept;
  bool config_processed;
  char *config_dir;
  char *pubkey_accepted_key_types;
};

struct ssh_poll_handle_struct *ssh_bind_get_poll(struct ssh_bind_struct
    *sshbind);


#endif /* BIND_H_ */
