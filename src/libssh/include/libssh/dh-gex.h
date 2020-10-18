/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2016 by Aris Adamantiadis <aris@0xbadc0de.be>
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


#ifndef SRC_DH_GEX_H_
#define SRC_DH_GEX_H_

int ssh_client_dhgex_init(ssh_session session);

#ifdef WITH_SERVER
void ssh_server_dhgex_init(ssh_session session);
#endif /* WITH_SERVER */

#endif /* SRC_DH_GEX_H_ */
