/*
 * token.h - Tokens list handling
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

#ifndef TOKEN_H_
#define TOKEN_H_

struct ssh_tokens_st {
    char *buffer;
    char **tokens;
};

struct ssh_tokens_st *ssh_tokenize(const char *chain, char separator);

void ssh_tokens_free(struct ssh_tokens_st *tokens);

char *ssh_find_matching(const char *available_d,
                        const char *preferred_d);

char *ssh_find_all_matching(const char *available_d,
                            const char *preferred_d);

char *ssh_remove_duplicates(const char *list);

char *ssh_append_without_duplicates(const char *list,
                                    const char *appended_list);
#endif /* TOKEN_H_ */
