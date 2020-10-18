/*
 * misc.c - useful client functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#include "config.h"

#ifndef _WIN32
/* This is needed for a standard getpwuid_r on opensolaris */
#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif /* _WIN32 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */


#ifdef _WIN32

#ifndef _WIN32_IE
# define _WIN32_IE 0x0501 // SHGetSpecialFolderPath
#endif

#include <winsock2.h> // Must be the first to include
#include <ws2tcpip.h>
#include <shlobj.h>
#include <direct.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif /* HAVE_IO_H */

#endif /* _WIN32 */

#include "libssh/priv.h"
#include "libssh/misc.h"
#include "libssh/session.h"

#ifdef HAVE_LIBGCRYPT
#define GCRYPT_STRING "/gnutls"
#else
#define GCRYPT_STRING ""
#endif

#ifdef HAVE_LIBCRYPTO
#define CRYPTO_STRING "/openssl"
#else
#define CRYPTO_STRING ""
#endif

#ifdef HAVE_LIBMBEDCRYPTO
#define MBED_STRING "/mbedtls"
#else
#define MBED_STRING ""
#endif

#ifdef WITH_ZLIB
#define ZLIB_STRING "/zlib"
#else
#define ZLIB_STRING ""
#endif

/**
 * @defgroup libssh_misc The SSH helper functions.
 * @ingroup libssh
 *
 * Different helper functions used in the SSH Library.
 *
 * @{
 */

#ifdef _WIN32
char *ssh_get_user_home_dir(void) {
  char tmp[MAX_PATH] = {0};
  char *szPath = NULL;

  if (SHGetSpecialFolderPathA(NULL, tmp, CSIDL_PROFILE, TRUE)) {
    szPath = malloc(strlen(tmp) + 1);
    if (szPath == NULL) {
      return NULL;
    }

    strcpy(szPath, tmp);
    return szPath;
  }

  return NULL;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file) {
  if (_access(file, 4) < 0) {
    return 0;
  }

  return 1;
}

/**
 * @brief Check if the given path is an existing directory and that is
 * accessible for writing.
 *
 * @param[in] path Path to the directory to be checked
 *
 * @return Return 1 if the directory exists and is accessible; 0 otherwise
 * */
int ssh_dir_writeable(const char *path)
{
    struct _stat buffer;
    int rc;

    rc = _stat(path, &buffer);
    if (rc < 0) {
        return 0;
    }

    if ((buffer.st_mode & _S_IFDIR) && (buffer.st_mode & _S_IWRITE)) {
        return 1;
    }

    return 0;
}

#define SSH_USEC_IN_SEC         1000000LL
#define SSH_SECONDS_SINCE_1601  11644473600LL

int gettimeofday(struct timeval *__p, void *__t) {
  union {
    unsigned long long ns100; /* time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } now;

  GetSystemTimeAsFileTime (&now.ft);
  __p->tv_usec = (long) ((now.ns100 / 10LL) % SSH_USEC_IN_SEC);
  __p->tv_sec  = (long)(((now.ns100 / 10LL ) / SSH_USEC_IN_SEC) - SSH_SECONDS_SINCE_1601);

  return (0);
}

char *ssh_get_local_username(void) {
    DWORD size = 0;
    char *user;

    /* get the size */
    GetUserName(NULL, &size);

    user = (char *) malloc(size);
    if (user == NULL) {
        return NULL;
    }

    if (GetUserName(user, &size)) {
        return user;
    }

    return NULL;
}

int ssh_is_ipaddr_v4(const char *str) {
    struct sockaddr_storage ss;
    int sslen = sizeof(ss);
    int rc = SOCKET_ERROR;

    /* WSAStringToAddressA thinks that 0.0.0 is a valid IP */
    if (strlen(str) < 7) {
        return 0;
    }

    rc = WSAStringToAddressA((LPSTR) str,
                             AF_INET,
                             NULL,
                             (struct sockaddr*)&ss,
                             &sslen);
    if (rc == 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str) {
    int rc = SOCKET_ERROR;

    if (strchr(str, ':')) {
        struct sockaddr_storage ss;
        int sslen = sizeof(ss);

        /* TODO link-local (IP:v6:addr%ifname). */
        rc = WSAStringToAddressA((LPSTR) str,
                                 AF_INET6,
                                 NULL,
                                 (struct sockaddr*)&ss,
                                 &sslen);
        if (rc == 0) {
            return 1;
        }
    }

    return ssh_is_ipaddr_v4(str);
}
#else /* _WIN32 */

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD 4096
#endif /* NSS_BUFLEN_PASSWD */

char *ssh_get_user_home_dir(void)
{
    char *szPath = NULL;
    struct passwd pwd;
    struct passwd *pwdbuf = NULL;
    char buf[NSS_BUFLEN_PASSWD] = {0};
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0 || pwdbuf == NULL ) {
        szPath = getenv("HOME");
        if (szPath == NULL) {
            return NULL;
        }
        snprintf(buf, sizeof(buf), "%s", szPath);

        return strdup(buf);
    }

    szPath = strdup(pwd.pw_dir);

    return szPath;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file)
{
    if (access(file, R_OK) < 0) {
        return 0;
    }

    return 1;
}

/**
 * @brief Check if the given path is an existing directory and that is
 * accessible for writing.
 *
 * @param[in] path Path to the directory to be checked
 *
 * @return Return 1 if the directory exists and is accessible; 0 otherwise
 * */
int ssh_dir_writeable(const char *path)
{
    struct stat buffer;
    int rc;

    rc = stat(path, &buffer);
    if (rc < 0) {
        return 0;
    }

    if (S_ISDIR(buffer.st_mode) && (buffer.st_mode & S_IWRITE)) {
        return 1;
    }

    return 0;
}

char *ssh_get_local_username(void)
{
    struct passwd pwd;
    struct passwd *pwdbuf = NULL;
    char buf[NSS_BUFLEN_PASSWD];
    char *name;
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0 || pwdbuf == NULL) {
        return NULL;
    }

    name = strdup(pwd.pw_name);

    if (name == NULL) {
        return NULL;
    }

    return name;
}

int ssh_is_ipaddr_v4(const char *str) {
    int rc = -1;
    struct in_addr dest;

    rc = inet_pton(AF_INET, str, &dest);
    if (rc > 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str) {
    int rc = -1;

    if (strchr(str, ':')) {
        struct in6_addr dest6;

        /* TODO link-local (IP:v6:addr%ifname). */
        rc = inet_pton(AF_INET6, str, &dest6);
        if (rc > 0) {
            return 1;
        }
    }

    return ssh_is_ipaddr_v4(str);
}

#endif /* _WIN32 */

char *ssh_lowercase(const char* str) {
  char *new, *p;

  if (str == NULL) {
    return NULL;
  }

  new = strdup(str);
  if (new == NULL) {
    return NULL;
  }

  for (p = new; *p; p++) {
    *p = tolower(*p);
  }

  return new;
}

char *ssh_hostport(const char *host, int port)
{
    char *dest = NULL;
    size_t len;

    if (host == NULL) {
        return NULL;
    }

    /* 3 for []:, 5 for 65536 and 1 for nul */
    len = strlen(host) + 3 + 5 + 1;
    dest = malloc(len);
    if (dest == NULL) {
        return NULL;
    }
    snprintf(dest, len, "[%s]:%d", host, port);

    return dest;
}

/**
 * @brief Convert a buffer into a colon separated hex string.
 * The caller has to free the memory.
 *
 * @param  what         What should be converted to a hex string.
 *
 * @param  len          Length of the buffer to convert.
 *
 * @return              The hex string or NULL on error.
 *
 * @see ssh_string_free_char()
 */
char *ssh_get_hexa(const unsigned char *what, size_t len) {
    const char h[] = "0123456789abcdef";
    char *hexa;
    size_t i;
    size_t hlen = len * 3;

    if (len > (UINT_MAX - 1) / 3) {
        return NULL;
    }

    hexa = malloc(hlen + 1);
    if (hexa == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        hexa[i * 3] = h[(what[i] >> 4) & 0xF];
        hexa[i * 3 + 1] = h[what[i] & 0xF];
        hexa[i * 3 + 2] = ':';
    }
    hexa[hlen - 1] = '\0';

    return hexa;
}

/**
 * @deprecated          Please use ssh_print_hash() instead
 */
void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len) {
    char *hexa = ssh_get_hexa(what, len);

    if (hexa == NULL) {
      return;
    }
    fprintf(stderr, "%s: %s\n", descr, hexa);

    free(hexa);
}

/**
 * @brief Log the content of a buffer in hexadecimal format, similar to the
 * output of 'hexdump -C' command.
 *
 * The first logged line is the given description followed by the length.
 * Then the content of the buffer is logged 16 bytes per line in the following
 * format:
 *
 * (offset) (first 8 bytes) (last 8 bytes) (the 16 bytes as ASCII char values)
 *
 * The output for a 16 bytes array containing values from 0x00 to 0x0f would be:
 *
 * "Example (16 bytes):"
 * "  00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  ................"
 *
 * The value for each byte as corresponding ASCII character is printed at the
 * end if the value is printable. Otherwise it is replace with '.'.
 *
 * @param[in] descr A description for the content to be logged
 * @param[in] what  The buffer to be logged
 * @param[in] len   The length of the buffer given in what
 *
 * @note If a too long description is provided (which would result in a first
 * line longer than 80 bytes), the function will fail.
 */
void ssh_log_hexdump(const char *descr, const unsigned char *what, size_t len)
{
    size_t i;
    char ascii[17];
    const unsigned char *pc = NULL;
    size_t count = 0;
    ssize_t printed = 0;

    /* The required buffer size is calculated from:
     *
     *  2 bytes for spaces at the beginning
     *  8 bytes for the offset
     *  2 bytes for spaces
     * 24 bytes to print the first 8 bytes + spaces
     *  1 byte for an extra space
     * 24 bytes to print next 8 bytes + spaces
     *  2 bytes for extra spaces
     * 16 bytes for the content as ASCII characters at the end
     *  1 byte for the ending '\0'
     *
     * Resulting in 80 bytes.
     *
     * Except for the first line (description + size), all lines have fixed
     * length. If a too long description is used, the function will fail.
     * */
    char buffer[80];

    /* Print description */
    if (descr != NULL) {
        printed = snprintf(buffer, sizeof(buffer), "%s ", descr);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    } else {
        printed = snprintf(buffer, sizeof(buffer), "(NULL description) ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (len == 0) {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(zero length):");
        if (printed < 0) {
            goto error;
        }
        SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
        return;
    } else {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(%zu bytes):", len);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (what == NULL) {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(NULL)");
        if (printed < 0) {
            goto error;
        }
        SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
        return;
    }

    SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);

    /* Reset state */
    count = 0;
    pc = what;

    for (i = 0; i < len; i++) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        /* Log previous line and reset state for new line */
        if ((i % 16) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count,
                                   "  %s", ascii);
                if (printed < 0) {
                    goto error;
                }
                SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);
                count = 0;
            }

            /* Start a new line with the offset */
            printed = snprintf(buffer, sizeof(buffer),
                               "  %08zx ", i);
            if (printed < 0) {
                goto error;
            }
            count += printed;
        }

        /* Print the current byte hexadecimal representation */
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           " %02x", pc[i]);
        if (printed < 0) {
            goto error;
        }
        count += printed;

        /* If printable, store the ASCII character */
        if (isprint(pc[i])) {
            ascii[i % 16] = pc[i];
        } else {
            ascii[i % 16] = '.';
        }
        ascii[(i % 16) + 1] = '\0';
    }

    /* Add padding if not exactly 16 characters */
    while ((i % 16) != 0) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        printed = snprintf(buffer + count, sizeof(buffer) - count, "   ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
        i++;
    }

    /* Print the last printable part */
    printed = snprintf(buffer + count, sizeof(buffer) - count,
                       "   %s", ascii);
    if (printed < 0) {
        goto error;
    }

    SSH_LOG(SSH_LOG_DEBUG, "%s", buffer);

    return;

error:
    SSH_LOG(SSH_LOG_WARN, "Could not print to buffer");
    return;
}

/**
 * @brief Check if libssh is the required version or get the version
 * string.
 *
 * @param[in]  req_version The version required.
 *
 * @return              If the version of libssh is newer than the version
 *                      required it will return a version string.
 *                      NULL if the version is older.
 *
 * Example:
 *
 * @code
 *  if (ssh_version(SSH_VERSION_INT(0,2,1)) == NULL) {
 *    fprintf(stderr, "libssh version is too old!\n");
 *    exit(1);
 *  }
 *
 *  if (debug) {
 *    printf("libssh %s\n", ssh_version(0));
 *  }
 * @endcode
 */
const char *ssh_version(int req_version) {
  if (req_version <= LIBSSH_VERSION_INT) {
    return SSH_STRINGIFY(LIBSSH_VERSION) GCRYPT_STRING CRYPTO_STRING MBED_STRING
      ZLIB_STRING;
  }

  return NULL;
}

struct ssh_list *ssh_list_new(void) {
  struct ssh_list *ret=malloc(sizeof(struct ssh_list));
  if(!ret)
    return NULL;
  ret->root=ret->end=NULL;
  return ret;
}

void ssh_list_free(struct ssh_list *list){
  struct ssh_iterator *ptr,*next;
  if(!list)
    return;
  ptr=list->root;
  while(ptr){
    next=ptr->next;
    SAFE_FREE(ptr);
    ptr=next;
  }
  SAFE_FREE(list);
}

struct ssh_iterator *ssh_list_get_iterator(const struct ssh_list *list){
  if(!list)
    return NULL;
  return list->root;
}

struct ssh_iterator *ssh_list_find(const struct ssh_list *list, void *value){
  struct ssh_iterator *it;
  for(it = ssh_list_get_iterator(list); it != NULL ;it=it->next)
    if(it->data==value)
      return it;
  return NULL;
}

/**
 * @brief Get the number of elements in the list
 *
 * @param[in]  list     The list to count.
 *
 * @return The number of elements in the list.
 */
size_t ssh_list_count(const struct ssh_list *list)
{
  struct ssh_iterator *it = NULL;
  int count = 0;

  for (it = ssh_list_get_iterator(list); it != NULL ; it = it->next) {
      count++;
  }

  return count;
}

static struct ssh_iterator *ssh_iterator_new(const void *data){
  struct ssh_iterator *iterator=malloc(sizeof(struct ssh_iterator));
  if(!iterator)
    return NULL;
  iterator->next=NULL;
  iterator->data=data;
  return iterator;
}

int ssh_list_append(struct ssh_list *list,const void *data){
  struct ssh_iterator *iterator = NULL;

  if (list == NULL) {
      return SSH_ERROR;
  }

  iterator = ssh_iterator_new(data);
  if (iterator == NULL) {
      return SSH_ERROR;
  }

  if(!list->end){
    /* list is empty */
    list->root=list->end=iterator;
  } else {
    /* put it on end of list */
    list->end->next=iterator;
    list->end=iterator;
  }
  return SSH_OK;
}

int ssh_list_prepend(struct ssh_list *list, const void *data){
  struct ssh_iterator *it = NULL;

  if (list == NULL) {
      return SSH_ERROR;
  }

  it = ssh_iterator_new(data);
  if (it == NULL) {
    return SSH_ERROR;
  }

  if (list->end == NULL) {
    /* list is empty */
    list->root = list->end = it;
  } else {
    /* set as new root */
    it->next = list->root;
    list->root = it;
  }

  return SSH_OK;
}

void ssh_list_remove(struct ssh_list *list, struct ssh_iterator *iterator){
  struct ssh_iterator *ptr,*prev;

  if (list == NULL) {
      return;
  }

  prev=NULL;
  ptr=list->root;
  while(ptr && ptr != iterator){
    prev=ptr;
    ptr=ptr->next;
  }
  if(!ptr){
    /* we did not find the element */
    return;
  }
  /* unlink it */
  if(prev)
    prev->next=ptr->next;
  /* if iterator was the head */
  if(list->root == iterator)
    list->root=iterator->next;
  /* if iterator was the tail */
  if(list->end == iterator)
    list->end = prev;
  SAFE_FREE(iterator);
}

/**
 * @internal
 *
 * @brief Removes the top element of the list and returns the data value
 * attached to it.
 *
 * @param[in[  list     The ssh_list to remove the element.
 *
 * @returns             A pointer to the element being stored in head, or NULL
 *                      if the list is empty.
 */
const void *_ssh_list_pop_head(struct ssh_list *list){
  struct ssh_iterator *iterator = NULL;
  const void *data = NULL;

  if (list == NULL) {
      return NULL;
  }

  iterator = list->root;
  if (iterator == NULL) {
      return NULL;
  }
  data=iterator->data;
  list->root=iterator->next;
  if(list->end==iterator)
    list->end=NULL;
  SAFE_FREE(iterator);
  return data;
}

/**
 * @brief Parse directory component.
 *
 * dirname breaks a null-terminated pathname string into a directory component.
 * In the usual case, ssh_dirname() returns the string up to, but not including,
 * the final '/'. Trailing '/' characters are  not  counted as part of the
 * pathname. The caller must free the memory.
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The dirname of path or NULL if we can't allocate memory.
 *                      If path does not contain a slash, c_dirname() returns
 *                      the string ".".  If path is the string "/", it returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned.
 */
char *ssh_dirname (const char *path) {
  char *new = NULL;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);

  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  /* goto next slash */
  while(len > 0 && path[len - 1] != '/') --len;

  if (len == 0) {
    return strdup(".");
  } else if (len == 1) {
    return strdup("/");
  }

  /* Remove slashes again */
  while(len > 0 && path[len - 1] == '/') --len;

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, path, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief basename - parse filename component.
 *
 * basename breaks a null-terminated pathname string into a filename component.
 * ssh_basename() returns the component following the final '/'.  Trailing '/'
 * characters are not counted as part of the pathname.
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The filename of path or NULL if we can't allocate
 *                      memory. If path is a the string "/", basename returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned.
 */
char *ssh_basename (const char *path) {
  char *new = NULL;
  const char *s;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);
  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  while(len > 0 && path[len - 1] != '/') --len;

  if (len > 0) {
    s = path + len;
    len = strlen(s);

    while(len > 0 && s[len - 1] == '/') --len;
  } else {
    return strdup(path);
  }

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, s, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief Attempts to create a directory with the given pathname.
 *
 * This is the portable version of mkdir, mode is ignored on Windows systems.
 *
 * @param[in]  pathname The path name to create the directory.
 *
 * @param[in]  mode     The permissions to use.
 *
 * @return              0 on success, < 0 on error with errno set.
 */
int ssh_mkdir(const char *pathname, mode_t mode)
{
    int r;
#ifdef _WIN32
    r = _mkdir(pathname);
#else
    r = mkdir(pathname, mode);
#endif

    return r;
}

/**
 * @brief Attempts to create a directory with the given pathname. The missing
 * directories in the given pathname are created recursively.
 *
 * @param[in]  pathname The path name to create the directory.
 *
 * @param[in]  mode     The permissions to use.
 *
 * @return              0 on success, < 0 on error with errno set.
 *
 * @note mode is ignored on Windows systems.
 */
int ssh_mkdirs(const char *pathname, mode_t mode)
{
    int rc = 0;
    char *parent = NULL;

    if (pathname == NULL ||
        pathname[0] == '\0' ||
        !strcmp(pathname, "/") ||
        !strcmp(pathname, "."))
    {
        errno = EINVAL;
        return -1;
    }

    errno = 0;

#ifdef _WIN32
    rc = _mkdir(pathname);
#else
    rc = mkdir(pathname, mode);
#endif

    if (rc < 0) {
        /* If a directory was missing, try to create the parent */
        if (errno == ENOENT) {
            parent = ssh_dirname(pathname);
            if (parent == NULL) {
                errno = ENOMEM;
                return -1;
            }

            rc = ssh_mkdirs(parent, mode);
            if (rc < 0) {
                /* We could not create the parent */
                SAFE_FREE(parent);
                return -1;
            }

            SAFE_FREE(parent);

            /* Try again */
            errno = 0;
#ifdef _WIN32
            rc = _mkdir(pathname);
#else
            rc = mkdir(pathname, mode);
#endif
        }
    }

    return rc;
}

/**
 * @brief Expand a directory starting with a tilde '~'
 *
 * @param[in]  d        The directory to expand.
 *
 * @return              The expanded directory, NULL on error.
 */
char *ssh_path_expand_tilde(const char *d) {
    char *h = NULL, *r;
    const char *p;
    size_t ld;
    size_t lh = 0;

    if (d[0] != '~') {
        return strdup(d);
    }
    d++;

    /* handle ~user/path */
    p = strchr(d, '/');
    if (p != NULL && p > d) {
#ifdef _WIN32
        return strdup(d);
#else
        struct passwd *pw;
        size_t s = p - d;
        char u[128];

        if (s >= sizeof(u)) {
            return NULL;
        }
        memcpy(u, d, s);
        u[s] = '\0';
        pw = getpwnam(u);
        if (pw == NULL) {
            return NULL;
        }
        ld = strlen(p);
        h = strdup(pw->pw_dir);
#endif
    } else {
        ld = strlen(d);
        p = (char *) d;
        h = ssh_get_user_home_dir();
    }
    if (h == NULL) {
        return NULL;
    }
    lh = strlen(h);

    r = malloc(ld + lh + 1);
    if (r == NULL) {
        SAFE_FREE(h);
        return NULL;
    }

    if (lh > 0) {
        memcpy(r, h, lh);
    }
    SAFE_FREE(h);
    memcpy(r + lh, p, ld + 1);

    return r;
}

/** @internal
 * @brief expands a string in function of session options
 * @param[in] s Format string to expand. Known parameters:
 *              %d SSH configuration directory (~/.ssh)
 *              %h target host name
 *              %u local username
 *              %l local hostname
 *              %r remote username
 *              %p remote port
 * @returns Expanded string.
 */
char *ssh_path_expand_escape(ssh_session session, const char *s) {
    char host[NI_MAXHOST];
    char buf[MAX_BUF_SIZE];
    char *r, *x = NULL;
    const char *p;
    size_t i, l;

    r = ssh_path_expand_tilde(s);
    if (r == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (strlen(r) > MAX_BUF_SIZE) {
        ssh_set_error(session, SSH_FATAL, "string to expand too long");
        free(r);
        return NULL;
    }

    p = r;
    buf[0] = '\0';

    for (i = 0; *p != '\0'; p++) {
        if (*p != '%') {
        escape:
            buf[i] = *p;
            i++;
            if (i >= MAX_BUF_SIZE) {
                free(r);
                return NULL;
            }
            buf[i] = '\0';
            continue;
        }

        p++;
        if (*p == '\0') {
            break;
        }

        switch (*p) {
            case '%':
                goto escape;
            case 'd':
                x = strdup(session->opts.sshdir);
                break;
            case 'u':
                x = ssh_get_local_username();
                break;
            case 'l':
                if (gethostname(host, sizeof(host) == 0)) {
                    x = strdup(host);
                }
                break;
            case 'h':
                x = strdup(session->opts.host);
                break;
            case 'r':
                x = strdup(session->opts.username);
                break;
            case 'p':
                if (session->opts.port < 65536) {
                    char tmp[6];

                    snprintf(tmp,
                             sizeof(tmp),
                             "%u",
                             session->opts.port > 0 ? session->opts.port : 22);
                    x = strdup(tmp);
                }
                break;
            default:
                ssh_set_error(session, SSH_FATAL,
                        "Wrong escape sequence detected");
                free(r);
                return NULL;
        }

        if (x == NULL) {
            ssh_set_error_oom(session);
            free(r);
            return NULL;
        }

        i += strlen(x);
        if (i >= MAX_BUF_SIZE) {
            ssh_set_error(session, SSH_FATAL,
                    "String too long");
            free(x);
            free(r);
            return NULL;
        }
        l = strlen(buf);
        strncpy(buf + l, x, sizeof(buf) - l - 1);
        buf[i] = '\0';
        SAFE_FREE(x);
    }

    free(r);
    return strdup(buf);
#undef MAX_BUF_SIZE
}

/**
 * @internal
 *
 * @brief Analyze the SSH banner to extract version information.
 *
 * @param  session      The session to analyze the banner from.
 * @param  server       0 means we are a client, 1 a server.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_get_issue_banner()
 */
int ssh_analyze_banner(ssh_session session, int server)
{
    const char *banner;
    const char *openssh;

    if (server) {
        banner = session->clientbanner;
    } else {
        banner = session->serverbanner;
    }

    if (banner == NULL) {
        ssh_set_error(session, SSH_FATAL, "Invalid banner");
        return -1;
    }

    /*
     * Typical banners e.g. are:
     *
     * SSH-1.5-openSSH_5.4
     * SSH-1.99-openSSH_3.0
     *
     * SSH-2.0-something
     * 012345678901234567890
     */
    if (strlen(banner) < 6 ||
        strncmp(banner, "SSH-", 4) != 0) {
          ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", banner);
          return -1;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "Analyzing banner: %s", banner);

    switch (banner[4]) {
        case '2':
            break;
        case '1':
            if (strlen(banner) > 6) {
                if (banner[6] == '9') {
                    break;
                }
            }
            FALL_THROUGH;
        default:
            ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", banner);
            return -1;
    }

    /* Make a best-effort to extract OpenSSH version numbers. */
    openssh = strstr(banner, "OpenSSH");
    if (openssh != NULL) {
        char *tmp = NULL;
        unsigned long int major = 0UL;
        unsigned long int minor = 0UL;

        /*
         * The banner is typical:
         * OpenSSH_5.4
         * 012345678901234567890
         */
        if (strlen(openssh) > 9) {
            major = strtoul(openssh + 8, &tmp, 10);
            if ((tmp == (openssh + 8)) ||
                ((errno == ERANGE) && (major == ULONG_MAX)) ||
                ((errno != 0) && (major == 0)) ||
                ((major < 1) || (major > 100))) {
                /* invalid major */
                goto done;
            }

            minor = strtoul(openssh + 10, &tmp, 10);
            if ((tmp == (openssh + 10)) ||
                ((errno == ERANGE) && (major == ULONG_MAX)) ||
                ((errno != 0) && (major == 0)) ||
                (minor > 100)) {
                /* invalid minor */
                goto done;
            }

            session->openssh = SSH_VERSION_INT(((int) major), ((int) minor), 0);

            SSH_LOG(SSH_LOG_PROTOCOL,
                    "We are talking to an OpenSSH client version: %lu.%lu (%x)",
                    major, minor, session->openssh);
        }
    }

done:
    return 0;
}

/* try the Monotonic clock if possible for perfs reasons */
#ifdef _POSIX_MONOTONIC_CLOCK
#define CLOCK CLOCK_MONOTONIC
#else
#define CLOCK CLOCK_REALTIME
#endif

/**
 * @internal
 * @brief initializes a timestamp to the current time
 * @param[out] ts pointer to an allocated ssh_timestamp structure
 */
void ssh_timestamp_init(struct ssh_timestamp *ts){
#ifdef HAVE_CLOCK_GETTIME
  struct timespec tp;
  clock_gettime(CLOCK, &tp);
  ts->useconds = tp.tv_nsec / 1000;
#else
  struct timeval tp;
  gettimeofday(&tp, NULL);
  ts->useconds = tp.tv_usec;
#endif
  ts->seconds = tp.tv_sec;
}

#undef CLOCK

/**
 * @internal
 * @brief gets the time difference between two timestamps in ms
 * @param[in] old older value
 * @param[in] new newer value
 * @returns difference in milliseconds
 */

static int ssh_timestamp_difference(struct ssh_timestamp *old,
    struct ssh_timestamp *new){
  long seconds, usecs, msecs;
  seconds = new->seconds - old->seconds;
  usecs = new->useconds - old->useconds;
  if (usecs < 0){
    seconds--;
    usecs += 1000000;
  }
  msecs = seconds * 1000 + usecs/1000;
  return msecs;
}

/**
 * @internal
 * @brief turn seconds and microseconds pair (as provided by user-set options)
 * into millisecond value
 * @param[in] sec number of seconds
 * @param[in] usec number of microseconds
 * @returns milliseconds, or 10000 if user supplied values are equal to zero
 */
int ssh_make_milliseconds(long sec, long usec) {
	int res = usec ? (usec / 1000) : 0;
	res += (sec * 1000);
	if (res == 0) {
		res = 10 * 1000; /* use a reasonable default value in case
				* SSH_OPTIONS_TIMEOUT is not set in options. */
	}
	return res;
}

/**
 * @internal
 * @brief Checks if a timeout is elapsed, in function of a previous
 * timestamp and an assigned timeout
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *                   timeout
 * @returns 1 if timeout is elapsed
 *          0 otherwise
 */
int ssh_timeout_elapsed(struct ssh_timestamp *ts, int timeout) {
    struct ssh_timestamp now;

    switch(timeout) {
        case -2: /*
                  * -2 means user-defined timeout as available in
                  * session->timeout, session->timeout_usec.
                  */
            SSH_LOG(SSH_LOG_WARN, "ssh_timeout_elapsed called with -2. this needs to "
                            "be fixed. please set a breakpoint on misc.c:%d and "
                            "fix the caller\n", __LINE__);
            return 0;
        case -1: /* -1 means infinite timeout */
            return 0;
        case 0: /* 0 means no timeout */
            return 1;
        default:
            break;
    }

    ssh_timestamp_init(&now);

    return (ssh_timestamp_difference(ts,&now) >= timeout);
}

/**
 * @brief updates a timeout value so it reflects the remaining time
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *             timeout
 * @returns   remaining time in milliseconds, 0 if elapsed, -1 if never.
 */
int ssh_timeout_update(struct ssh_timestamp *ts, int timeout){
  struct ssh_timestamp now;
  int ms, ret;
  if (timeout <= 0) {
      return timeout;
  }
  ssh_timestamp_init(&now);
  ms = ssh_timestamp_difference(ts,&now);
  if(ms < 0)
    ms = 0;
  ret = timeout - ms;
  return ret >= 0 ? ret: 0;
}


int ssh_match_group(const char *group, const char *object)
{
    const char *a;
    const char *z;

    z = group;
    do {
        a = strchr(z, ',');
        if (a == NULL) {
            if (strcmp(z, object) == 0) {
                return 1;
            }
            return 0;
        } else {
            if (strncmp(z, object, a - z) == 0) {
                return 1;
            }
        }
        z = a + 1;
    } while(1);

    /* not reached */
    return 0;
}

#if !defined(HAVE_EXPLICIT_BZERO)
void explicit_bzero(void *s, size_t n)
{
#if defined(HAVE_MEMSET_S)
    memset_s(s, n, '\0', n);
#elif defined(HAVE_SECURE_ZERO_MEMORY)
    SecureZeroMemory(s, n);
#else
    memset(s, '\0', n);
#if defined(HAVE_GCC_VOLATILE_MEMORY_PROTECTION)
    /* See http://llvm.org/bugs/show_bug.cgi?id=15495 */
    __asm__ volatile("" : : "g"(s) : "memory");
#endif /* HAVE_GCC_VOLATILE_MEMORY_PROTECTION */
#endif
}
#endif /* !HAVE_EXPLICIT_BZERO */

#if !defined(HAVE_STRNDUP)
char *strndup(const char *s, size_t n)
{
    char *x = NULL;

    if (n + 1 < n) {
        return NULL;
    }

    x = malloc(n + 1);
    if (x == NULL) {
        return NULL;
    }

    memcpy(x, s, n);
    x[n] = '\0';

    return x;
}
#endif /* ! HAVE_STRNDUP */

/* Increment 64b integer in network byte order */
void
uint64_inc(unsigned char *counter)
{
    int i;

    for (i = 7; i >= 0; i--) {
        counter[i]++;
        if (counter[i])
          return;
    }
}

/**
 * @internal
 *
 * @brief Quote file name to be used on shell.
 *
 * Try to put the given file name between single quotes. There are special
 * cases:
 *
 * - When the '\'' char is found in the file name, it is double quoted
 *   - example:
 *     input: a'b
 *     output: 'a'"'"'b'
 * - When the '!' char is found in the file name, it is replaced by an unquoted
 *   verbatim char "\!"
 *   - example:
 *     input: a!b
 *     output 'a'\!'b'
 *
 * @param[in]   file_name  File name string to be quoted before used on shell
 * @param[out]  buf       Buffer to receive the final quoted file name.  Must
 *                        have room for the final quoted string.  The maximum
 *                        output length would be (3 * strlen(file_name) + 1)
 *                        since in the worst case each character would be
 *                        replaced by 3 characters, plus the terminating '\0'.
 * @param[in]   buf_len   The size of the provided output buffer
 *
 * @returns SSH_ERROR on error; length of the resulting string not counting the
 * string terminator '\0'
 * */
int ssh_quote_file_name(const char *file_name, char *buf, size_t buf_len)
{
    const char *src = NULL;
    char *dst = NULL;
    size_t required_buf_len;

    enum ssh_quote_state_e state = NO_QUOTE;

    if (file_name == NULL || buf == NULL || buf_len == 0) {
        SSH_LOG(SSH_LOG_WARNING, "Invalid parameter");
        return SSH_ERROR;
    }

    /* Only allow file names smaller than 32kb. */
    if (strlen(file_name) > 32 * 1024) {
        SSH_LOG(SSH_LOG_WARNING, "File name too long");
        return SSH_ERROR;
    }

    /* Paranoia check */
    required_buf_len = (size_t)3 * strlen(file_name) + 1;
    if (required_buf_len > buf_len) {
        SSH_LOG(SSH_LOG_WARNING, "Buffer too small");
        return SSH_ERROR;
    }

    src = file_name;
    dst = buf;

    while ((*src != '\0')) {
        switch (*src) {

        /* The '\'' char is double quoted */

        case '\'':
            switch (state) {
            case NO_QUOTE:
                /* Start a new double quoted string. The '\'' char will be
                 * copied to the beginning of it at the end of the loop. */
                *dst++ = '"';
                break;
            case SINGLE_QUOTE:
                /* Close the current single quoted string and start a new double
                 * quoted string. The '\'' char will be copied to the beginning
                 * of it at the end of the loop. */
                *dst++ = '\'';
                *dst++ = '"';
                break;
            case DOUBLE_QUOTE:
                /* If already in the double quoted string, keep copying the
                 * sequence of chars. */
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When the '\'' char is found, the resulting state will be
             * DOUBLE_QUOTE in any case*/
            state = DOUBLE_QUOTE;
            break;

        /* The '!' char is replaced by unquoted "\!" */

        case '!':
            switch (state) {
            case NO_QUOTE:
                /* The '!' char is interpreted in some shells (e.g. CSH) even
                 * when is quoted with single quotes.  Replace it with unquoted
                 * "\!" which is correctly interpreted as the '!' character. */
                *dst++ = '\\';
                break;
            case SINGLE_QUOTE:
                /* Close the current quoted string and replace '!' for unquoted
                 * "\!" */
                *dst++ = '\'';
                *dst++ = '\\';
                break;
            case DOUBLE_QUOTE:
                /* Close current quoted string and replace  "!" for unquoted
                 * "\!" */
                *dst++ = '"';
                *dst++ = '\\';
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When the '!' char is found, the resulting state will be NO_QUOTE
             * in any case*/
            state = NO_QUOTE;
            break;

        /* Ordinary chars are single quoted */

        default:
            switch (state) {
            case NO_QUOTE:
                /* Start a new single quoted string */
                *dst++ = '\'';
                break;
            case SINGLE_QUOTE:
                /* If already in the single quoted string, keep copying the
                 * sequence of chars. */
                break;
            case DOUBLE_QUOTE:
                /* Close current double quoted string and start a new single
                 * quoted string. */
                *dst++ = '"';
                *dst++ = '\'';
                break;
            default:
                /* Should never be reached */
                goto error;
            }

            /* When an ordinary char is found, the resulting state will be
             * SINGLE_QUOTE in any case*/
            state = SINGLE_QUOTE;
            break;
        }

        /* Copy the current char to output */
        *dst++ = *src++;
    }

    /* Close the quoted string when necessary */

    switch (state) {
    case NO_QUOTE:
        /* No open string */
        break;
    case SINGLE_QUOTE:
        /* Close current single quoted string */
        *dst++ = '\'';
        break;
    case DOUBLE_QUOTE:
        /* Close current double quoted string */
        *dst++ = '"';
        break;
    default:
        /* Should never be reached */
        goto error;
    }

    /* Put the string terminator */
    *dst = '\0';

    return dst - buf;

error:
    return SSH_ERROR;
}

/**
 * @internal
 *
 * @brief Given a string, encode existing newlines as the string "\\n"
 *
 * @param[in]  string   Input string
 * @param[out] buf      Output buffer. This buffer must be at least (2 *
 *                      strlen(string)) + 1 long.  In the worst case,
 *                      each character can be encoded as 2 characters plus the
 *                      terminating '\0'.
 * @param[in]  buf_len  Size of the provided output buffer
 *
 * @returns SSH_ERROR on error; length of the resulting string not counting the
 * terminating '\0' otherwise
 */
int ssh_newline_vis(const char *string, char *buf, size_t buf_len)
{
    const char *in = NULL;
    char *out = NULL;

    if (string == NULL || buf == NULL || buf_len == 0) {
        return SSH_ERROR;
    }

    if ((2 * strlen(string) + 1) > buf_len) {
        SSH_LOG(SSH_LOG_WARNING, "Buffer too small");
        return SSH_ERROR;
    }

    out = buf;
    for (in = string; *in != '\0'; in++) {
        if (*in == '\n') {
            *out++ = '\\';
            *out++ = 'n';
        } else {
            *out++ = *in;
        }
    }
    *out = '\0';

    return out - buf;
}

/** @} */
