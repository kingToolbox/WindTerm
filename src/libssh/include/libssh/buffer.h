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

#ifndef BUFFER_H_
#define BUFFER_H_

#include <stdarg.h>

#include "libssh/libssh.h"

#define SSH_BUFFER_PACK_END ((uint32_t) 0x4f65feb3)

void ssh_buffer_set_secure(ssh_buffer buffer);
int ssh_buffer_add_ssh_string(ssh_buffer buffer, ssh_string string);
int ssh_buffer_add_u8(ssh_buffer buffer, uint8_t data);
int ssh_buffer_add_u16(ssh_buffer buffer, uint16_t data);
int ssh_buffer_add_u32(ssh_buffer buffer, uint32_t data);
int ssh_buffer_add_u64(ssh_buffer buffer, uint64_t data);

int ssh_buffer_validate_length(struct ssh_buffer_struct *buffer, size_t len);

void *ssh_buffer_allocate(struct ssh_buffer_struct *buffer, uint32_t len);
int ssh_buffer_allocate_size(struct ssh_buffer_struct *buffer, uint32_t len);
int ssh_buffer_pack_va(struct ssh_buffer_struct *buffer,
                       const char *format,
                       size_t argc,
                       va_list ap);
int _ssh_buffer_pack(struct ssh_buffer_struct *buffer,
                     const char *format,
                     size_t argc,
                     ...);
#define ssh_buffer_pack(buffer, format, ...) \
    _ssh_buffer_pack((buffer), (format), __VA_NARG__(__VA_ARGS__), __VA_ARGS__, SSH_BUFFER_PACK_END)

int ssh_buffer_unpack_va(struct ssh_buffer_struct *buffer,
                         const char *format, size_t argc,
                         va_list ap);
int _ssh_buffer_unpack(struct ssh_buffer_struct *buffer,
                       const char *format,
                       size_t argc,
                       ...);
#define ssh_buffer_unpack(buffer, format, ...) \
    _ssh_buffer_unpack((buffer), (format), __VA_NARG__(__VA_ARGS__), __VA_ARGS__, SSH_BUFFER_PACK_END)

int ssh_buffer_prepend_data(ssh_buffer buffer, const void *data, uint32_t len);
int ssh_buffer_add_buffer(ssh_buffer buffer, ssh_buffer source);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
int ssh_buffer_get_u8(ssh_buffer buffer, uint8_t *data);
int ssh_buffer_get_u32(ssh_buffer buffer, uint32_t *data);
int ssh_buffer_get_u64(ssh_buffer buffer, uint64_t *data);

/* ssh_buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
ssh_string ssh_buffer_get_ssh_string(ssh_buffer buffer);

/* ssh_buffer_pass_bytes acts as if len bytes have been read (used for padding) */
uint32_t ssh_buffer_pass_bytes_end(ssh_buffer buffer, uint32_t len);
uint32_t ssh_buffer_pass_bytes(ssh_buffer buffer, uint32_t len);

#endif /* BUFFER_H_ */
