/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#ifndef SFTP_PRIV_H
#define SFTP_PRIV_H

sftp_packet sftp_packet_read(sftp_session sftp);
ssize_t sftp_packet_write(sftp_session sftp, uint8_t type, ssh_buffer payload);
void sftp_packet_free(sftp_packet packet);
int buffer_add_attributes(ssh_buffer buffer, sftp_attributes attr);
sftp_attributes sftp_parse_attr(sftp_session session,
                                ssh_buffer buf,
                                int expectname);

#endif /* SFTP_PRIV_H */
