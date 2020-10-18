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

#ifndef SOCKET_H_
#define SOCKET_H_

#include "libssh/callbacks.h"
struct ssh_poll_handle_struct;
/* socket.c */

struct ssh_socket_struct;
typedef struct ssh_socket_struct* ssh_socket;

int ssh_socket_init(void);
void ssh_socket_cleanup(void);
ssh_socket ssh_socket_new(ssh_session session);
void ssh_socket_reset(ssh_socket s);
void ssh_socket_free(ssh_socket s);
void ssh_socket_set_fd(ssh_socket s, socket_t fd);
socket_t ssh_socket_get_fd(ssh_socket s);
#ifndef _WIN32
int ssh_socket_unix(ssh_socket s, const char *path);
void ssh_execute_command(const char *command, socket_t in, socket_t out);
int ssh_socket_connect_proxycommand(ssh_socket s, const char *command);
#endif
void ssh_socket_close(ssh_socket s);
int ssh_socket_write(ssh_socket s,const void *buffer, int len);
int ssh_socket_is_open(ssh_socket s);
int ssh_socket_fd_isset(ssh_socket s, fd_set *set);
void ssh_socket_fd_set(ssh_socket s, fd_set *set, socket_t *max_fd);
void ssh_socket_set_fd_in(ssh_socket s, socket_t fd);
void ssh_socket_set_fd_out(ssh_socket s, socket_t fd);
int ssh_socket_nonblocking_flush(ssh_socket s);
void ssh_socket_set_write_wontblock(ssh_socket s);
void ssh_socket_set_read_wontblock(ssh_socket s);
void ssh_socket_set_except(ssh_socket s);
int ssh_socket_get_status(ssh_socket s);
int ssh_socket_get_poll_flags(ssh_socket s);
int ssh_socket_buffered_write_bytes(ssh_socket s);
int ssh_socket_data_available(ssh_socket s);
int ssh_socket_data_writable(ssh_socket s);
int ssh_socket_set_nonblocking(socket_t fd);
int ssh_socket_set_blocking(socket_t fd);

void ssh_socket_set_callbacks(ssh_socket s, ssh_socket_callbacks callbacks);
int ssh_socket_pollcallback(struct ssh_poll_handle_struct *p, socket_t fd, int revents, void *v_s);
struct ssh_poll_handle_struct * ssh_socket_get_poll_handle(ssh_socket s);

int ssh_socket_connect(ssh_socket s,
                       const char *host,
                       uint16_t port,
                       const char *bind_addr);

#endif /* SOCKET_H_ */
