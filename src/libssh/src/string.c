/*
 * string.c - ssh string functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include <errno.h>
#include <limits.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/string.h"

/* String maximum size is 256M */
#define STRING_SIZE_MAX 0x10000000

/**
 * @defgroup libssh_string The SSH string functions
 * @ingroup libssh
 *
 * @brief String manipulations used in libssh.
 *
 * @{
 */

/**
 * @brief Create a new SSH String object.
 *
 * @param[in] size       The size of the string.
 *
 * @return               The newly allocated string, NULL on error.
 */
struct ssh_string_struct *ssh_string_new(size_t size)
{
    struct ssh_string_struct *str = NULL;

    if (size > STRING_SIZE_MAX) {
        errno = EINVAL;
        return NULL;
    }

    str = malloc(sizeof(struct ssh_string_struct) + size);
    if (str == NULL) {
        return NULL;
    }

    str->size = htonl(size);
    str->data[0] = 0;

    return str;
}

/**
 * @brief Fill a string with given data. The string should be big enough.
 *
 * @param s        An allocated string to fill with data.
 *
 * @param data     The data to fill the string with.
 *
 * @param len      Size of data.
 *
 * @return         0 on success, < 0 on error.
 */
int ssh_string_fill(struct ssh_string_struct *s, const void *data, size_t len) {
  if ((s == NULL) || (data == NULL) ||
      (len == 0) || (len > ssh_string_len(s))) {
    return -1;
  }

  memcpy(s->data, data, len);

  return 0;
}

/**
 * @brief Create a ssh string using a C string
 *
 * @param[in] what      The source 0-terminated C string.
 *
 * @return              The newly allocated string, NULL on error with errno
 *                      set.
 *
 * @note The nul byte is not copied nor counted in the ouput string.
 */
struct ssh_string_struct *ssh_string_from_char(const char *what) {
  struct ssh_string_struct *ptr;
  size_t len;

  if(what == NULL) {
      errno = EINVAL;
      return NULL;
  }

  len = strlen(what);

  ptr = ssh_string_new(len);
  if (ptr == NULL) {
    return NULL;
  }

  memcpy(ptr->data, what, len);

  return ptr;
}

/**
 * @brief Return the size of a SSH string.
 *
 * @param[in] s         The the input SSH string.
 *
 * @return The size of the content of the string, 0 on error.
 */
size_t ssh_string_len(struct ssh_string_struct *s) {
    size_t size;

    if (s == NULL) {
        return 0;
    }

    size = ntohl(s->size);
    if (size > 0 && size <= STRING_SIZE_MAX) {
        return size;
    }

    return 0;
}

/**
 * @brief Get the the string as a C nul-terminated string.
 *
 * This is only available as long as the SSH string exists.
 *
 * @param[in] s         The SSH string to get the C string from.
 *
 * @return              The char pointer, NULL on error.
 */
const char *ssh_string_get_char(struct ssh_string_struct *s)
{
    if (s == NULL) {
        return NULL;
    }
    s->data[ssh_string_len(s)] = '\0';

    return (const char *) s->data;
}

/**
 * @brief Convert a SSH string to a C nul-terminated string.
 *
 * @param[in] s         The SSH input string.
 *
 * @return              An allocated string pointer, NULL on error with errno
 *                      set.
 *
 * @note If the input SSH string contains zeroes, some parts of the output
 * string may not be readable with regular libc functions.
 */
char *ssh_string_to_char(struct ssh_string_struct *s) {
  size_t len;
  char *new;

  if (s == NULL) {
      return NULL;
  }

  len = ssh_string_len(s);
  if (len + 1 < len) {
    return NULL;
  }

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }
  memcpy(new, s->data, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief Deallocate a char string object.
 *
 * @param[in] s         The string to delete.
 */
void ssh_string_free_char(char *s) {
    SAFE_FREE(s);
}

/**
 * @brief Copy a string, return a newly allocated string. The caller has to
 *        free the string.
 *
 * @param[in] s         String to copy.
 *
 * @return              Newly allocated copy of the string, NULL on error.
 */
struct ssh_string_struct *ssh_string_copy(struct ssh_string_struct *s) {
  struct ssh_string_struct *new;
  size_t len;

  if (s == NULL) {
      return NULL;
  }

  len = ssh_string_len(s);
  if (len == 0) {
      return NULL;
  }

  new = ssh_string_new(len);
  if (new == NULL) {
    return NULL;
  }

  memcpy(new->data, s->data, len);

  return new;
}

/**
 * @brief Destroy the data in a string so it couldn't appear in a core dump.
 *
 * @param[in] s         The string to burn.
 */
void ssh_string_burn(struct ssh_string_struct *s) {
    if (s == NULL || s->size == 0) {
        return;
    }

    explicit_bzero(s->data, ssh_string_len(s));
}

/**
 * @brief Get the payload of the string.
 *
 * @param s             The string to get the data from.
 *
 * @return              Return the data of the string or NULL on error.
 */
void *ssh_string_data(struct ssh_string_struct *s) {
  if (s == NULL) {
    return NULL;
  }

  return s->data;
}

/**
 * @brief Deallocate a SSH string object.
 *
 * \param[in] s         The SSH string to delete.
 */
void ssh_string_free(struct ssh_string_struct *s) {
  SAFE_FREE(s);
}

/** @} */
