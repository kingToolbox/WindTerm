/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef MISC_H_
#define MISC_H_

/* in misc.c */
/* gets the user home dir. */
char *ssh_get_user_home_dir(void);
char *ssh_get_local_username(void);
int ssh_file_readaccess_ok(const char *file);
int ssh_dir_writeable(const char *path);

char *ssh_path_expand_tilde(const char *d);
char *ssh_path_expand_escape(ssh_session session, const char *s);
int ssh_analyze_banner(ssh_session session, int server);
int ssh_is_ipaddr_v4(const char *str);
int ssh_is_ipaddr(const char *str);

/* list processing */

struct ssh_list {
  struct ssh_iterator *root;
  struct ssh_iterator *end;
};

struct ssh_iterator {
  struct ssh_iterator *next;
  const void *data;
};

struct ssh_timestamp {
  long seconds;
  long useconds;
};

enum ssh_quote_state_e {
    NO_QUOTE,
    SINGLE_QUOTE,
    DOUBLE_QUOTE
};

struct ssh_list *ssh_list_new(void);
void ssh_list_free(struct ssh_list *list);
struct ssh_iterator *ssh_list_get_iterator(const struct ssh_list *list);
struct ssh_iterator *ssh_list_find(const struct ssh_list *list, void *value);
size_t ssh_list_count(const struct ssh_list *list);
int ssh_list_append(struct ssh_list *list, const void *data);
int ssh_list_prepend(struct ssh_list *list, const void *data);
void ssh_list_remove(struct ssh_list *list, struct ssh_iterator *iterator);
char *ssh_lowercase(const char* str);
char *ssh_hostport(const char *host, int port);

const void *_ssh_list_pop_head(struct ssh_list *list);

#define ssh_iterator_value(type, iterator)\
  ((type)((iterator)->data))

/** @brief fetch the head element of a list and remove it from list
 * @param type type of the element to return
 * @param list the ssh_list to use
 * @return the first element of the list, or NULL if the list is empty
 */
#define ssh_list_pop_head(type, ssh_list)\
  ((type)_ssh_list_pop_head(ssh_list))

int ssh_make_milliseconds(long sec, long usec);
void ssh_timestamp_init(struct ssh_timestamp *ts);
int ssh_timeout_elapsed(struct ssh_timestamp *ts, int timeout);
int ssh_timeout_update(struct ssh_timestamp *ts, int timeout);

int ssh_match_group(const char *group, const char *object);

void uint64_inc(unsigned char *counter);

void ssh_log_hexdump(const char *descr, const unsigned char *what, size_t len);

int ssh_mkdirs(const char *pathname, mode_t mode);

int ssh_quote_file_name(const char *file_name, char *buf, size_t buf_len);
int ssh_newline_vis(const char *string, char *buf, size_t buf_len);

#endif /* MISC_H_ */
