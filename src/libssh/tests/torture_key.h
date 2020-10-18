/*
 * torture_key.h - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
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

#ifndef _TORTURE_KEY_H
#define _TORTURE_KEY_H

#include <stdbool.h>

#define TORTURE_TESTKEY_PASSWORD "libssh-rocks"

/* Return the encrypted private key in a new OpenSSH format */
const char *torture_get_openssh_testkey(enum ssh_keytypes_e type,
                                        bool with_passphrase);

/* Return the private key in the legacy PEM format */
const char *torture_get_testkey(enum ssh_keytypes_e type,
                                bool with_passphrase);
const char *torture_get_testkey_passphrase(void);

const char *torture_get_testkey_pub(enum ssh_keytypes_e type);

#endif /* _TORTURE_KEY_H */
