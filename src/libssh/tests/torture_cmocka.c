/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2018      by Andreas Schneider <asn@cryptomilk.org>
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

#define LIBSSH_STATIC

#include "torture.h"

void _assert_ssh_return_code(ssh_session session,
                             int rc,
                             const char * const file,
                             const int line)
{
    char ssh_error[1024] = {0};

    if (session != NULL) {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code - %s",
                 ssh_get_error(session));
    } else {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code");
    }

    _assert_true(rc == SSH_OK,
                 ssh_error,
                 file,
                 line);
}

void _assert_ssh_return_code_equal(ssh_session session,
                                   int rc,
                                   int expected_rc,
                                   const char * const file,
                                   const int line)
{
    char ssh_error[1024] = {0};

    if (session != NULL) {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code - %s",
                 ssh_get_error(session));
    } else {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code");
    }

    _assert_true((rc == expected_rc),
                 ssh_error,
                 file,
                 line);
}

void _assert_ssh_return_code_not_equal(ssh_session session,
                                       int rc,
                                       int unexpected_rc,
                                       const char * const file,
                                       const int line)
{
    char ssh_error[1024] = {0};

    if (session != NULL) {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code - %s",
                 ssh_get_error(session));
    } else {
        snprintf(ssh_error,
                 sizeof(ssh_error),
                 "ERROR: Invalid return code");
    }

    _assert_true((rc != unexpected_rc),
                 ssh_error,
                 file,
                 line);
}
