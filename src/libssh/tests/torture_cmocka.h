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

#ifndef _TORTURE_CMOCKA_H
#define _TORTURE_CMOCKA_H

#include "libssh/session.h"

void _assert_ssh_return_code(ssh_session session,
                             int rc,
                             const char * const file,
                             const int line);

#define assert_ssh_return_code(session, rc) \
    _assert_ssh_return_code((session), (rc), __FILE__, __LINE__)

void _assert_ssh_return_code_equal(ssh_session session,
                                   int rc,
                                   int expected_rc,
                                   const char * const file,
                                   const int line);

#define assert_ssh_return_code_equal(session, rc, expected_rc) \
    _assert_ssh_return_code_equal((session), (rc), (expected_rc), __FILE__, __LINE__)

void _assert_ssh_return_code_not_equal(ssh_session session,
                                       int rc,
                                       int expected_rc,
                                       const char * const file,
                                       const int line);

#define assert_ssh_return_code_not_equal(session, rc, unexpected_rc) \
    _assert_ssh_return_code_not_equal((session), (rc), (unexpected_rc), __FILE__, __LINE__)

#endif /* _TORTURE_CMOCKA_H */
