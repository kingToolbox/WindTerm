/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011      Andreas Schneider <asn@cryptomilk.org>
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

#ifndef _OPTIONS_H
#define _OPTIONS_H

int ssh_config_parse_file(ssh_session session, const char *filename);
int ssh_options_set_algo(ssh_session session,
                         enum ssh_kex_types_e algo,
                         const char *list);
int ssh_options_apply(ssh_session session);

#endif /* _OPTIONS_H */
