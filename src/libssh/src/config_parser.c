/*
 * config_parser.c - Common configuration file parser functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013    by Andreas Schneider <asn@cryptomilk.org>
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

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libssh/config_parser.h"
#include "libssh/priv.h"

char *ssh_config_get_cmd(char **str)
{
    register char *c;
    char *r;

    /* Ignore leading spaces */
    for (c = *str; *c; c++) {
        if (! isblank(*c)) {
            break;
        }
    }

    if (*c == '\"') {
        for (r = ++c; *c; c++) {
            if (*c == '\"') {
                *c = '\0';
                goto out;
            }
        }
    }

    for (r = c; *c; c++) {
        if (*c == '\n') {
            *c = '\0';
            goto out;
        }
    }

out:
    *str = c + 1;

    return r;
}

char *ssh_config_get_token(char **str)
{
    register char *c;
    char *r;

    c = ssh_config_get_cmd(str);

    for (r = c; *c; c++) {
        if (isblank(*c) || *c == '=') {
            *c = '\0';
            goto out;
        }
    }

out:
    *str = c + 1;

    return r;
}

long ssh_config_get_long(char **str, long notfound)
{
    char *p, *endp;
    long i;

    p = ssh_config_get_token(str);
    if (p && *p) {
        i = strtol(p, &endp, 10);
        if (p == endp) {
            return notfound;
        }
        return i;
    }

    return notfound;
}

const char *ssh_config_get_str_tok(char **str, const char *def)
{
    char *p;

    p = ssh_config_get_token(str);
    if (p && *p) {
        return p;
    }

    return def;
}

int ssh_config_get_yesno(char **str, int notfound)
{
    const char *p;

    p = ssh_config_get_str_tok(str, NULL);
    if (p == NULL) {
        return notfound;
    }

    if (strncasecmp(p, "yes", 3) == 0) {
        return 1;
    } else if (strncasecmp(p, "no", 2) == 0) {
        return 0;
    }

    return notfound;
}

int ssh_config_parse_uri(const char *tok,
        char **username,
        char **hostname,
        char **port)
{
    char *endp = NULL;
    long port_n;

    /* Sanitize inputs */
    if (username != NULL) {
        *username = NULL;
    }
    if (hostname != NULL) {
        *hostname = NULL;
    }
    if (port != NULL) {
        *port = NULL;
    }

    /* Username part (optional) */
    endp = strchr(tok, '@');
    if (endp != NULL) {
        /* Zero-length username is not valid */
        if (tok == endp) {
            goto error;
        }
        if (username != NULL) {
            *username = strndup(tok, endp - tok);
            if (*username == NULL) {
                goto error;
            }
        }
        tok = endp + 1;
        /* If there is second @ character, this does not look like our URI */
        endp = strchr(tok, '@');
        if (endp != NULL) {
            goto error;
        }
    }

    /* Hostname */
    if (*tok == '[') {
        /* IPv6 address is enclosed with square brackets */
        tok++;
        endp = strchr(tok, ']');
        if (endp == NULL) {
            goto error;
        }
    } else {
        /* Hostnames or aliases expand to the last colon or to the end */
        endp = strrchr(tok, ':');
        if (endp == NULL) {
            endp = strchr(tok, '\0');
        }
    }
    if (tok == endp) {
        /* Zero-length hostnames are not valid */
        goto error;
    }
    if (hostname != NULL) {
        *hostname = strndup(tok, endp - tok);
        if (*hostname == NULL) {
            goto error;
        }
    }
    /* Skip also the closing bracket */
    if (*endp == ']') {
        endp++;
    }

    /* Port (optional) */
    if (*endp != '\0') {
        char *port_end = NULL;

        /* Verify the port is valid positive number */
        port_n = strtol(endp + 1, &port_end, 10);
        if (port_n < 1 || *port_end != '\0') {
            SSH_LOG(SSH_LOG_WARN, "Failed to parse port number."
                    " The value '%ld' is invalid or there are some"
                    " trailing characters: '%s'", port_n, port_end);
            goto error;
        }
        if (port != NULL) {
            *port = strdup(endp + 1);
            if (*port == NULL) {
                goto error;
            }
        }
    }

    return SSH_OK;

error:
    if (username != NULL) {
        SAFE_FREE(*username);
    }
    if (hostname != NULL) {
        SAFE_FREE(*hostname);
    }
    if (port != NULL) {
        SAFE_FREE(*port);
    }
    return SSH_ERROR;
}
