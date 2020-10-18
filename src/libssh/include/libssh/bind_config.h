/*
 * bind_config.h - Parse the SSH server configuration file
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2019 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
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

#ifndef BIND_CONFIG_H_
#define BIND_CONFIG_H_

#include "libssh/server.h"

enum ssh_bind_config_opcode_e {
    /* Known but not allowed in Match block */
    BIND_CFG_NOT_ALLOWED_IN_MATCH = -4,
    /* Unknown opcode */
    BIND_CFG_UNKNOWN = -3,
    /* Known and not applicable to libssh */
    BIND_CFG_NA = -2,
    /* Known but not supported by current libssh version */
    BIND_CFG_UNSUPPORTED = -1,
    BIND_CFG_INCLUDE,
    BIND_CFG_HOSTKEY,
    BIND_CFG_LISTENADDRESS,
    BIND_CFG_PORT,
    BIND_CFG_LOGLEVEL,
    BIND_CFG_CIPHERS,
    BIND_CFG_MACS,
    BIND_CFG_KEXALGORITHMS,
    BIND_CFG_MATCH,
    BIND_CFG_PUBKEY_ACCEPTED_KEY_TYPES,
    BIND_CFG_HOSTKEY_ALGORITHMS,

    BIND_CFG_MAX /* Keep this one last in the list */
};

/* @brief Parse configuration file and set the options to the given ssh_bind
 *
 * @params[in] sshbind   The ssh_bind context to be configured
 * @params[in] filename  The path to the configuration file
 *
 * @returns    0 on successful parsing the configuration file, -1 on error
 */
int ssh_bind_config_parse_file(ssh_bind sshbind, const char *filename);

#endif /* BIND_CONFIG_H_ */
