/*
 * config_parser.h - Common configuration file parser functions
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

#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

char *ssh_config_get_cmd(char **str);

char *ssh_config_get_token(char **str);

long ssh_config_get_long(char **str, long notfound);

const char *ssh_config_get_str_tok(char **str, const char *def);

int ssh_config_get_yesno(char **str, int notfound);

/* @brief Parse SSH URI in format [user@]host[:port] from the given string
 *
 * @param[in]   tok      String to parse
 * @param[out]  username Pointer to the location, where the new username will
 *                       be stored or NULL if we do not care about the result.
 * @param[out]  hostname Pointer to the location, where the new hostname will
 *                       be stored or NULL if we do not care about the result.
 * @param[out]  port     Pointer to the location, where the new port will
 *                       be stored or NULL if we do not care about the result.
 *
 * @returns     SSH_OK if the provided string is in format of SSH URI,
 *              SSH_ERROR on failure
 */
int ssh_config_parse_uri(const char *tok,
        char **username,
        char **hostname,
        char **port);

#endif /* LIBSSH_CONFIG_H_ */
