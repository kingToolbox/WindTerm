/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis <aris@badcode.be>
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

#ifndef BIGNUM_H_
#define BIGNUM_H_

#include "libssh/libcrypto.h"
#include "libssh/libgcrypt.h"
#include "libssh/libmbedcrypto.h"

bignum ssh_make_string_bn(ssh_string string);
ssh_string ssh_make_bignum_string(bignum num);
void ssh_print_bignum(const char *which, const_bignum num);


#endif /* BIGNUM_H_ */
