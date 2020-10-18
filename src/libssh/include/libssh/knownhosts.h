/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 20014 by Aris Adamantiadis <aris@badcode.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
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


#ifndef SSH_KNOWNHOSTS_H_
#define SSH_KNOWNHOSTS_H_

struct ssh_list *ssh_known_hosts_get_algorithms(ssh_session session);
char *ssh_known_hosts_get_algorithms_names(ssh_session session);
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry_file(ssh_session session,
                                       const char *filename,
                                       struct ssh_knownhosts_entry **pentry);

#endif /* SSH_KNOWNHOSTS_H_ */
