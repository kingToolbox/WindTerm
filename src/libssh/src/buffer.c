/*
 * buffer.c - buffer functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include "libssh/bignum.h"

/*
 * Describes a buffer state
 * [XXXXXXXXXXXXDATA PAYLOAD       XXXXXXXXXXXXXXXXXXXXXXXX]
 * ^            ^                  ^                       ^]
 * \_data points\_pos points here  \_used points here |    /
 *   here                                          Allocated
 */
struct ssh_buffer_struct {
    bool secure;
    size_t used;
    size_t allocated;
    size_t pos;
    uint8_t *data;
};

/* Buffer size maximum is 256M */
#define BUFFER_SIZE_MAX 0x10000000

/**
 * @defgroup libssh_buffer The SSH buffer functions.
 * @ingroup libssh
 *
 * Functions to handle SSH buffers.
 *
 * @{
 */


#ifdef DEBUG_BUFFER
/**
 * @internal
 *
 * @brief Check that preconditions and postconditions are valid.
 *
 * @param[in]  buf      The buffer to check.
 */
static void buffer_verify(ssh_buffer buf)
{
    bool do_abort = false;

    if (buf->data == NULL) {
        return;
    }

    if (buf->used > buf->allocated) {
        fprintf(stderr,
                "BUFFER ERROR: allocated %zu, used %zu\n",
                buf->allocated,
                buf->used);
        do_abort = true;
    }
    if (buf->pos > buf->used) {
        fprintf(stderr,
                "BUFFER ERROR: position %zu, used %zu\n",
                buf->pos,
                buf->used);
        do_abort = true;
    }
    if (buf->pos > buf->allocated) {
        fprintf(stderr,
                "BUFFER ERROR: position %zu, allocated %zu\n",
                buf->pos,
                buf->allocated);
        do_abort = true;
    }
    if (do_abort) {
        abort();
    }
}

#else
#define buffer_verify(x)
#endif

/**
 * @brief Create a new SSH buffer.
 *
 * @return A newly initialized SSH buffer, NULL on error.
 */
struct ssh_buffer_struct *ssh_buffer_new(void)
{
    struct ssh_buffer_struct *buf = NULL;
    int rc;

    buf = calloc(1, sizeof(struct ssh_buffer_struct));
    if (buf == NULL) {
        return NULL;
    }

    /*
     * Always preallocate 64 bytes.
     *
     * -1 for ralloc_buffer magic.
     */
    rc = ssh_buffer_allocate_size(buf, 64 - 1);
    if (rc != 0) {
        SAFE_FREE(buf);
        return NULL;
    }
    buffer_verify(buf);

    return buf;
}

/**
 * @brief Deallocate a SSH buffer.
 *
 * \param[in]  buffer   The buffer to free.
 */
void ssh_buffer_free(struct ssh_buffer_struct *buffer)
{
    if (buffer == NULL) {
        return;
    }
    buffer_verify(buffer);

    if (buffer->secure && buffer->allocated > 0) {
        /* burn the data */
        explicit_bzero(buffer->data, buffer->allocated);
        SAFE_FREE(buffer->data);

        explicit_bzero(buffer, sizeof(struct ssh_buffer_struct));
    } else {
        SAFE_FREE(buffer->data);
    }
    SAFE_FREE(buffer);
}

/**
 * @brief Sets the buffer as secure.
 *
 * A secure buffer will never leave cleartext data in the heap
 * after being reallocated or freed.
 *
 * @param[in] buffer buffer to set secure.
 */
void ssh_buffer_set_secure(ssh_buffer buffer)
{
    buffer->secure = true;
}

static int realloc_buffer(struct ssh_buffer_struct *buffer, size_t needed)
{
    size_t smallest = 1;
    uint8_t *new = NULL;

    buffer_verify(buffer);

    /* Find the smallest power of two which is greater or equal to needed */
    while(smallest <= needed) {
        if (smallest == 0) {
            return -1;
        }
        smallest <<= 1;
    }
    needed = smallest;

    if (needed > BUFFER_SIZE_MAX) {
        return -1;
    }

    if (buffer->secure) {
        new = malloc(needed);
        if (new == NULL) {
            return -1;
        }
        memcpy(new, buffer->data, buffer->used);
        explicit_bzero(buffer->data, buffer->used);
        SAFE_FREE(buffer->data);
    } else {
        new = realloc(buffer->data, needed);
        if (new == NULL) {
            return -1;
        }
    }
    buffer->data = new;
    buffer->allocated = needed;

    buffer_verify(buffer);
    return 0;
}

/** @internal
 * @brief shifts a buffer to remove unused data in the beginning
 * @param buffer SSH buffer
 */
static void buffer_shift(ssh_buffer buffer)
{
    size_t burn_pos = buffer->pos;

    buffer_verify(buffer);

    if (buffer->pos == 0) {
        return;
    }
    memmove(buffer->data,
            buffer->data + buffer->pos,
            buffer->used - buffer->pos);
    buffer->used -= buffer->pos;
    buffer->pos = 0;

    if (buffer->secure) {
        void *ptr = buffer->data + buffer->used;
        explicit_bzero(ptr, burn_pos);
    }

    buffer_verify(buffer);
}

/**
 * @brief Reinitialize a SSH buffer.
 *
 * In case the buffer has exceeded 64K in size, the buffer will be reallocated
 * to 64K.
 *
 * @param[in]  buffer   The buffer to reinitialize.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_reinit(struct ssh_buffer_struct *buffer)
{
    if (buffer == NULL) {
        return -1;
    }

    buffer_verify(buffer);

    if (buffer->secure && buffer->allocated > 0) {
        explicit_bzero(buffer->data, buffer->allocated);
    }
    buffer->used = 0;
    buffer->pos = 0;

    /* If the buffer is bigger then 64K, reset it to 64K */
    if (buffer->allocated > 65536) {
        int rc;

        /* -1 for realloc_buffer magic */
        rc = realloc_buffer(buffer, 65536 - 1);
        if (rc != 0) {
            return -1;
        }
    }

    buffer_verify(buffer);

    return 0;
}

/**
 * @brief Add data at the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  data     A pointer to the data to add.
 *
 * @param[in]  len      The length of the data to add.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_add_data(struct ssh_buffer_struct *buffer, const void *data, uint32_t len)
{
    if (buffer == NULL) {
        return -1;
    }

    buffer_verify(buffer);

    if (data == NULL) {
        return -1;
    }

    if (buffer->used + len < len) {
        return -1;
    }

    if (buffer->allocated < (buffer->used + len)) {
        if (buffer->pos > 0) {
            buffer_shift(buffer);
        }
        if (realloc_buffer(buffer, buffer->used + len) < 0) {
            return -1;
        }
    }

    memcpy(buffer->data + buffer->used, data, len);
    buffer->used += len;
    buffer_verify(buffer);
    return 0;
}

/**
 * @brief Ensure the buffer has at least a certain preallocated size.
 *
 * @param[in]  buffer   The buffer to enlarge.
 *
 * @param[in]  len      The length to ensure as allocated.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_allocate_size(struct ssh_buffer_struct *buffer,
                             uint32_t len)
{
    buffer_verify(buffer);

    if (buffer->allocated < len) {
        if (buffer->pos > 0) {
            buffer_shift(buffer);
        }
        if (realloc_buffer(buffer, len) < 0) {
            return -1;
        }
    }

    buffer_verify(buffer);

    return 0;
}

/**
 * @internal
 *
 * @brief Allocate space for data at the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  len      The length of the data to add.
 *
 * @return              Pointer on the allocated space
 *                      NULL on error.
 */
void *ssh_buffer_allocate(struct ssh_buffer_struct *buffer, uint32_t len)
{
    void *ptr;
    buffer_verify(buffer);

    if (buffer->used + len < len) {
        return NULL;
    }

    if (buffer->allocated < (buffer->used + len)) {
        if (buffer->pos > 0) {
            buffer_shift(buffer);
        }

        if (realloc_buffer(buffer, buffer->used + len) < 0) {
            return NULL;
        }
    }

    ptr = buffer->data + buffer->used;
    buffer->used+=len;
    buffer_verify(buffer);

    return ptr;
}

/**
 * @internal
 *
 * @brief Add a SSH string to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the string.
 *
 * @param[in]  string   The SSH String to add.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_add_ssh_string(struct ssh_buffer_struct *buffer,
    struct ssh_string_struct *string) {
  uint32_t len = 0;

  if (string == NULL) {
      return -1;
  }

  len = ssh_string_len(string);
  if (ssh_buffer_add_data(buffer, string, len + sizeof(uint32_t)) < 0) {
    return -1;
  }

  return 0;
}

/**
 * @internal
 *
 * @brief Add a 32 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 32 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_add_u32(struct ssh_buffer_struct *buffer,uint32_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 16 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 16 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_add_u16(struct ssh_buffer_struct *buffer,uint16_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 64 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 64 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_add_u64(struct ssh_buffer_struct *buffer, uint64_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 8 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 8 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_add_u8(struct ssh_buffer_struct *buffer,uint8_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(uint8_t));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add data at the head of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  data     The data to prepend.
 *
 * @param[in]  len      The length of data to prepend.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_prepend_data(struct ssh_buffer_struct *buffer, const void *data,
    uint32_t len) {
  buffer_verify(buffer);

  if(len <= buffer->pos){
    /* It's possible to insert data between begin and pos */
    memcpy(buffer->data + (buffer->pos - len), data, len);
    buffer->pos -= len;
    buffer_verify(buffer);
    return 0;
  }
  /* pos isn't high enough */
  if (buffer->used - buffer->pos + len < len) {
    return -1;
  }

  if (buffer->allocated < (buffer->used - buffer->pos + len)) {
    if (realloc_buffer(buffer, buffer->used - buffer->pos + len) < 0) {
      return -1;
    }
  }
  memmove(buffer->data + len, buffer->data + buffer->pos, buffer->used - buffer->pos);
  memcpy(buffer->data, data, len);
  buffer->used += len - buffer->pos;
  buffer->pos = 0;
  buffer_verify(buffer);
  return 0;
}

/**
 * @internal
 *
 * @brief Append data from a buffer to the tail of another buffer.
 *
 * @param[in]  buffer   The destination buffer.
 *
 * @param[in]  source   The source buffer to append. It doesn't take the
 *                      position of the buffer into account.
 *
 * @return              0 on success, -1 on error.
 */
int ssh_buffer_add_buffer(struct ssh_buffer_struct *buffer,
    struct ssh_buffer_struct *source)
{
    int rc;

    rc = ssh_buffer_add_data(buffer,
                             ssh_buffer_get(source),
                             ssh_buffer_get_len(source));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Get a pointer to the head of a buffer at the current position.
 *
 * @param[in]  buffer   The buffer to get the head pointer.
 *
 * @return              A pointer to the data from current position.
 *
 * @see ssh_buffer_get_len()
 */
void *ssh_buffer_get(struct ssh_buffer_struct *buffer){
    return buffer->data + buffer->pos;
}

/**
 * @brief Get the length of the buffer from the current position.
 *
 * @param[in]  buffer   The buffer to get the length from.
 *
 * @return              The length of the buffer.
 *
 * @see ssh_buffer_get()
 */
uint32_t ssh_buffer_get_len(struct ssh_buffer_struct *buffer){
  buffer_verify(buffer);
  return buffer->used - buffer->pos;
}

/**
 * @internal
 *
 * @brief Advance the position in the buffer.
 *
 * This has effect to "eat" bytes at head of the buffer.
 *
 * @param[in]  buffer   The buffer to advance the position.
 *
 * @param[in]  len      The number of bytes to eat.
 *
 * @return              The new size of the buffer.
 */
uint32_t ssh_buffer_pass_bytes(struct ssh_buffer_struct *buffer, uint32_t len){
    buffer_verify(buffer);

    if (buffer->pos + len < len || buffer->used < buffer->pos + len) {
        return 0;
    }

    buffer->pos+=len;
    /* if the buffer is empty after having passed the whole bytes into it, we can clean it */
    if(buffer->pos==buffer->used){
        buffer->pos=0;
        buffer->used=0;
    }
    buffer_verify(buffer);
    return len;
}

/**
 * @internal
 *
 * @brief Cut the end of the buffer.
 *
 * @param[in]  buffer   The buffer to cut.
 *
 * @param[in]  len      The number of bytes to remove from the tail.
 *
 * @return              The new size of the buffer.
 */
uint32_t ssh_buffer_pass_bytes_end(struct ssh_buffer_struct *buffer, uint32_t len){
  buffer_verify(buffer);

  if (buffer->used < len) {
      return 0;
  }

  buffer->used-=len;
  buffer_verify(buffer);
  return len;
}

/**
 * @brief Get the remaining data out of the buffer and adjust the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     The data buffer where to store the data.
 *
 * @param[in]  len      The length to read from the buffer.
 *
 * @returns             0 if there is not enough data in buffer, len otherwise.
 */
uint32_t ssh_buffer_get_data(struct ssh_buffer_struct *buffer, void *data, uint32_t len)
{
    int rc;

    /*
     * Check for a integer overflow first, then check if not enough data is in
     * the buffer.
     */
    rc = ssh_buffer_validate_length(buffer, len);
    if (rc != SSH_OK) {
        return 0;
    }
    memcpy(data,buffer->data+buffer->pos,len);
    buffer->pos+=len;
    return len;   /* no yet support for partial reads (is it really needed ?? ) */
}

/**
 * @internal
 *
 * @brief Get a 8 bits unsigned int out of the buffer and adjusts the read
 * pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     A pointer to a uint8_t where to store the data.
 *
 * @returns             0 if there is not enough data in buffer, 1 otherwise.
 */
int ssh_buffer_get_u8(struct ssh_buffer_struct *buffer, uint8_t *data){
    return ssh_buffer_get_data(buffer,data,sizeof(uint8_t));
}

/**
 * @internal
 *
 * @brief gets a 32 bits unsigned int out of the buffer. Adjusts the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     A pointer to a uint32_t where to store the data.
 *
 * @returns             0 if there is not enough data in buffer, 4 otherwise.
 */
int ssh_buffer_get_u32(struct ssh_buffer_struct *buffer, uint32_t *data){
    return ssh_buffer_get_data(buffer,data,sizeof(uint32_t));
}
/**
 * @internal
 *
 * @brief Get a 64 bits unsigned int out of the buffer and adjusts the read
 * pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     A pointer to a uint64_t where to store the data.
 *
 * @returns             0 if there is not enough data in buffer, 8 otherwise.
 */
int ssh_buffer_get_u64(struct ssh_buffer_struct *buffer, uint64_t *data){
    return ssh_buffer_get_data(buffer,data,sizeof(uint64_t));
}

/**
 * @brief Valdiates that the given length can be obtained from the buffer.
 *
 * @param[in]  buffer  The buffer to read from.
 *
 * @param[in]  len     The length to be checked.
 *
 * @return             SSH_OK if the length is valid, SSH_ERROR otherwise.
 */
int ssh_buffer_validate_length(struct ssh_buffer_struct *buffer, size_t len)
{
    if (buffer->pos + len < len || buffer->pos + len > buffer->used) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Get a SSH String out of the buffer and adjusts the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @returns             The SSH String, NULL on error.
 */
struct ssh_string_struct *
ssh_buffer_get_ssh_string(struct ssh_buffer_struct *buffer)
{
    uint32_t stringlen;
    uint32_t hostlen;
    struct ssh_string_struct *str = NULL;
    int rc;

    rc = ssh_buffer_get_u32(buffer, &stringlen);
    if (rc == 0) {
        return NULL;
    }
    hostlen = ntohl(stringlen);
    /* verify if there is enough space in buffer to get it */
    rc = ssh_buffer_validate_length(buffer, hostlen);
    if (rc != SSH_OK) {
      return NULL; /* it is indeed */
    }
    str = ssh_string_new(hostlen);
    if (str == NULL) {
        return NULL;
    }

    stringlen = ssh_buffer_get_data(buffer, ssh_string_data(str), hostlen);
    if (stringlen != hostlen) {
        /* should never happen */
        SAFE_FREE(str);
        return NULL;
    }

    return str;
}

/**
 * @brief Pre-calculate the size we need for packing the buffer.
 *
 * This makes sure that enough memory is allocated for packing the buffer and
 * we only have to do one memory allocation.
 *
 * @param[in]  buffer    The buffer to allocate
 *
 * @param[in]  format    A format string of arguments.
 *
 * @param[in]  argc      The number of arguments.
 *
 * @param[in]  ap        The va_list of arguments.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
static int ssh_buffer_pack_allocate_va(struct ssh_buffer_struct *buffer,
                                       const char *format,
                                       size_t argc,
                                       va_list ap)
{
    const char *p = NULL;
    ssh_string string = NULL;
    char *cstring = NULL;
    size_t needed_size = 0;
    size_t len;
    size_t count;
    int rc = SSH_OK;

    for (p = format, count = 0; *p != '\0'; p++, count++) {
        /* Invalid number of arguments passed */
        if (count > argc) {
            return SSH_ERROR;
        }

        switch(*p) {
        case 'b':
            va_arg(ap, unsigned int);
            needed_size += sizeof(uint8_t);
            break;
        case 'w':
            va_arg(ap, unsigned int);
            needed_size += sizeof(uint16_t);
            break;
        case 'd':
            va_arg(ap, uint32_t);
            needed_size += sizeof(uint32_t);
            break;
        case 'q':
            va_arg(ap, uint64_t);
            needed_size += sizeof(uint64_t);
            break;
        case 'S':
            string = va_arg(ap, ssh_string);
            needed_size += 4 + ssh_string_len(string);
            string = NULL;
            break;
        case 's':
            cstring = va_arg(ap, char *);
            needed_size += sizeof(uint32_t) + strlen(cstring);
            cstring = NULL;
            break;
        case 'P':
            len = va_arg(ap, size_t);
            needed_size += len;
            va_arg(ap, void *);
            count++; /* increase argument count */
            break;
        case 'B':
            va_arg(ap, bignum);
            /*
             * Use a fixed size for a bignum
             * (they should normaly be around 32)
             */
            needed_size += 64;
            break;
        case 't':
            cstring = va_arg(ap, char *);
            needed_size += strlen(cstring);
            cstring = NULL;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid buffer format %c", *p);
            rc = SSH_ERROR;
        }
        if (rc != SSH_OK){
            break;
        }
    }

    if (argc != count) {
        return SSH_ERROR;
    }

    if (rc != SSH_ERROR){
        /*
         * Check if our canary is intact, if not, something really bad happened.
         */
        uint32_t canary = va_arg(ap, uint32_t);
        if (canary != SSH_BUFFER_PACK_END) {
            abort();
        }
    }

    rc = ssh_buffer_allocate_size(buffer, needed_size);
    if (rc != 0) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/** @internal
 * @brief Add multiple values in a buffer on a single function call
 * @param[in] buffer    The buffer to add to
 * @param[in] format    A format string of arguments.
 * @param[in] ap        A va_list of arguments.
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @see ssh_buffer_add_format() for format list values.
 */
int ssh_buffer_pack_va(struct ssh_buffer_struct *buffer,
                       const char *format,
                       size_t argc,
                       va_list ap)
{
    int rc = SSH_ERROR;
    const char *p;
    union {
        uint8_t byte;
        uint16_t word;
        uint32_t dword;
        uint64_t qword;
        ssh_string string;
        void *data;
    } o;
    char *cstring;
    bignum b;
    size_t len;
    size_t count;

    if (argc > 256) {
        return SSH_ERROR;
    }

    for (p = format, count = 0; *p != '\0'; p++, count++) {
        /* Invalid number of arguments passed */
        if (count > argc) {
            return SSH_ERROR;
        }

        switch(*p) {
        case 'b':
            o.byte = (uint8_t)va_arg(ap, unsigned int);
            rc = ssh_buffer_add_u8(buffer, o.byte);
            break;
        case 'w':
            o.word = (uint16_t)va_arg(ap, unsigned int);
            o.word = htons(o.word);
            rc = ssh_buffer_add_u16(buffer, o.word);
            break;
        case 'd':
            o.dword = va_arg(ap, uint32_t);
            o.dword = htonl(o.dword);
            rc = ssh_buffer_add_u32(buffer, o.dword);
            break;
        case 'q':
            o.qword = va_arg(ap, uint64_t);
            o.qword = htonll(o.qword);
            rc = ssh_buffer_add_u64(buffer, o.qword);
            break;
        case 'S':
            o.string = va_arg(ap, ssh_string);
            rc = ssh_buffer_add_ssh_string(buffer, o.string);
            o.string = NULL;
            break;
        case 's':
            cstring = va_arg(ap, char *);
            len = strlen(cstring);
            rc = ssh_buffer_add_u32(buffer, htonl(len));
            if (rc == SSH_OK){
                rc = ssh_buffer_add_data(buffer, cstring, len);
            }
            cstring = NULL;
            break;
        case 'P':
            len = va_arg(ap, size_t);

            o.data = va_arg(ap, void *);
            count++; /* increase argument count */

            rc = ssh_buffer_add_data(buffer, o.data, len);
            o.data = NULL;
            break;
        case 'B':
            b = va_arg(ap, bignum);
            o.string = ssh_make_bignum_string(b);
            if(o.string == NULL){
                rc = SSH_ERROR;
                break;
            }
            rc = ssh_buffer_add_ssh_string(buffer, o.string);
            SAFE_FREE(o.string);
            break;
        case 't':
            cstring = va_arg(ap, char *);
            len = strlen(cstring);
            rc = ssh_buffer_add_data(buffer, cstring, len);
            cstring = NULL;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid buffer format %c", *p);
            rc = SSH_ERROR;
        }
        if (rc != SSH_OK){
            break;
        }
    }

    if (argc != count) {
        return SSH_ERROR;
    }

    if (rc != SSH_ERROR){
        /* Check if our canary is intact, if not something really bad happened */
        uint32_t canary = va_arg(ap, uint32_t);
        if (canary != SSH_BUFFER_PACK_END) {
            abort();
        }
    }
    return rc;
}

/** @internal
 * @brief Add multiple values in a buffer on a single function call
 * @param[in] buffer    The buffer to add to
 * @param[in] format    A format string of arguments. This string contains single
 *                      letters describing the order and type of arguments:
 *                         'b': uint8_t  (pushed in network byte order)
 *                         'w': uint16_t (pushed in network byte order)
 *                         'd': uint32_t (pushed in network byte order)
 *                         'q': uint64_t (pushed in network byte order)
 *                         'S': ssh_string
 *                         's': char * (C string, pushed as SSH string)
 *                         't': char * (C string, pushed as free text)
 *                         'P': size_t, void * (len of data, pointer to data)
 *                              only pushes data.
 *                         'B': bignum (pushed as SSH string)
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @warning             when using 'P' with a constant size (e.g. 8), do not
 *                      forget to cast to (size_t).
 */
int _ssh_buffer_pack(struct ssh_buffer_struct *buffer,
                     const char *format,
                     size_t argc,
                     ...)
{
    va_list ap;
    int rc;

    if (argc > 256) {
        return SSH_ERROR;
    }

    va_start(ap, argc);
    rc = ssh_buffer_pack_allocate_va(buffer, format, argc, ap);
    va_end(ap);

    if (rc != SSH_OK) {
        return rc;
    }

    va_start(ap, argc);
    rc = ssh_buffer_pack_va(buffer, format, argc, ap);
    va_end(ap);

    return rc;
}

/** @internal
 * @brief Get multiple values from a buffer on a single function call
 * @param[in] buffer    The buffer to get from
 * @param[in] format    A format string of arguments.
 * @param[in] ap        A va_list of arguments.
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @see ssh_buffer_get_format() for format list values.
 */
int ssh_buffer_unpack_va(struct ssh_buffer_struct *buffer,
                         const char *format,
                         size_t argc,
                         va_list ap)
{
    int rc = SSH_ERROR;
    const char *p = format, *last;
    union {
        uint8_t *byte;
        uint16_t *word;
        uint32_t *dword;
        uint64_t *qword;
        ssh_string *string;
        char **cstring;
        bignum *bignum;
        void **data;
    } o;
    size_t len, rlen, max_len;
    ssh_string tmp_string = NULL;
    va_list ap_copy;
    size_t count;

    max_len = ssh_buffer_get_len(buffer);

    /* copy the argument list in case a rollback is needed */
    va_copy(ap_copy, ap);

    if (argc > 256) {
        rc = SSH_ERROR;
        goto cleanup;
    }

    for (count = 0; *p != '\0'; p++, count++) {
        /* Invalid number of arguments passed */
        if (count > argc) {
            rc = SSH_ERROR;
            goto cleanup;
        }

        rc = SSH_ERROR;
        switch (*p) {
        case 'b':
            o.byte = va_arg(ap, uint8_t *);
            rlen = ssh_buffer_get_u8(buffer, o.byte);
            rc = rlen==1 ? SSH_OK : SSH_ERROR;
            break;
        case 'w':
            o.word = va_arg(ap,  uint16_t *);
            rlen = ssh_buffer_get_data(buffer, o.word, sizeof(uint16_t));
            if (rlen == 2) {
                *o.word = ntohs(*o.word);
                rc = SSH_OK;
            }
            break;
        case 'd':
            o.dword = va_arg(ap, uint32_t *);
            rlen = ssh_buffer_get_u32(buffer, o.dword);
            if (rlen == 4) {
                *o.dword = ntohl(*o.dword);
                rc = SSH_OK;
            }
            break;
        case 'q':
            o.qword = va_arg(ap, uint64_t*);
            rlen = ssh_buffer_get_u64(buffer, o.qword);
            if (rlen == 8) {
                *o.qword = ntohll(*o.qword);
                rc = SSH_OK;
            }
            break;
        case 'B':
            o.bignum = va_arg(ap, bignum *);
            *o.bignum = NULL;
            tmp_string = ssh_buffer_get_ssh_string(buffer);
            if (tmp_string == NULL) {
                break;
            }
            *o.bignum = ssh_make_string_bn(tmp_string);
            ssh_string_burn(tmp_string);
            SSH_STRING_FREE(tmp_string);
            rc = (*o.bignum != NULL) ? SSH_OK : SSH_ERROR;
            break;
        case 'S':
            o.string = va_arg(ap, ssh_string *);
            *o.string = ssh_buffer_get_ssh_string(buffer);
            rc = *o.string != NULL ? SSH_OK : SSH_ERROR;
            o.string = NULL;
            break;
        case 's': {
            uint32_t u32len = 0;

            o.cstring = va_arg(ap, char **);
            *o.cstring = NULL;
            rlen = ssh_buffer_get_u32(buffer, &u32len);
            if (rlen != 4){
                break;
            }
            len = ntohl(u32len);
            if (len > max_len - 1) {
                break;
            }

            rc = ssh_buffer_validate_length(buffer, len);
            if (rc != SSH_OK) {
                break;
            }

            *o.cstring = malloc(len + 1);
            if (*o.cstring == NULL){
                rc = SSH_ERROR;
                break;
            }
            rlen = ssh_buffer_get_data(buffer, *o.cstring, len);
            if (rlen != len){
                SAFE_FREE(*o.cstring);
                rc = SSH_ERROR;
                break;
            }
            (*o.cstring)[len] = '\0';
            o.cstring = NULL;
            rc = SSH_OK;
            break;
        }
        case 'P':
            len = va_arg(ap, size_t);
            if (len > max_len - 1) {
                rc = SSH_ERROR;
                break;
            }

            rc = ssh_buffer_validate_length(buffer, len);
            if (rc != SSH_OK) {
                break;
            }

            o.data = va_arg(ap, void **);
            count++;

            *o.data = malloc(len);
            if(*o.data == NULL){
                rc = SSH_ERROR;
                break;
            }
            rlen = ssh_buffer_get_data(buffer, *o.data, len);
            if (rlen != len){
                SAFE_FREE(*o.data);
                rc = SSH_ERROR;
                break;
            }
            o.data = NULL;
            rc = SSH_OK;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid buffer format %c", *p);
        }
        if (rc != SSH_OK) {
            break;
        }
    }

    if (argc != count) {
        rc = SSH_ERROR;
    }

cleanup:
    if (rc != SSH_ERROR){
        /* Check if our canary is intact, if not something really bad happened */
        uint32_t canary = va_arg(ap, uint32_t);
        if (canary != SSH_BUFFER_PACK_END){
            abort();
        }
    }

    if (rc != SSH_OK){
        /* Reset the format string and erase everything that was allocated */
        last = p;
        for(p=format;p<last;++p){
            switch(*p){
            case 'b':
                o.byte = va_arg(ap_copy, uint8_t *);
                if (buffer->secure) {
                    explicit_bzero(o.byte, sizeof(uint8_t));
                    break;
                }
                break;
            case 'w':
                o.word = va_arg(ap_copy, uint16_t *);
                if (buffer->secure) {
                    explicit_bzero(o.word, sizeof(uint16_t));
                    break;
                }
                break;
            case 'd':
                o.dword = va_arg(ap_copy, uint32_t *);
                if (buffer->secure) {
                    explicit_bzero(o.dword, sizeof(uint32_t));
                    break;
                }
                break;
            case 'q':
                o.qword = va_arg(ap_copy, uint64_t *);
                if (buffer->secure) {
                    explicit_bzero(o.qword, sizeof(uint64_t));
                    break;
                }
                break;
            case 'B':
                o.bignum = va_arg(ap_copy, bignum *);
                bignum_safe_free(*o.bignum);
                break;
            case 'S':
                o.string = va_arg(ap_copy, ssh_string *);
                if (buffer->secure) {
                    ssh_string_burn(*o.string);
                }
                SAFE_FREE(*o.string);
                break;
            case 's':
                o.cstring = va_arg(ap_copy, char **);
                if (buffer->secure) {
                    explicit_bzero(*o.cstring, strlen(*o.cstring));
                }
                SAFE_FREE(*o.cstring);
                break;
            case 'P':
                len = va_arg(ap_copy, size_t);
                o.data = va_arg(ap_copy, void **);
                if (buffer->secure) {
                    explicit_bzero(*o.data, len);
                }
                SAFE_FREE(*o.data);
                break;
            default:
                (void)va_arg(ap_copy, void *);
                break;
            }
        }
    }
    va_end(ap_copy);

    return rc;
}

/** @internal
 * @brief Get multiple values from a buffer on a single function call
 * @param[in] buffer    The buffer to get from
 * @param[in] format    A format string of arguments. This string contains single
 *                      letters describing the order and type of arguments:
 *                         'b': uint8_t *  (pulled in network byte order)
 *                         'w': uint16_t * (pulled in network byte order)
 *                         'd': uint32_t * (pulled in network byte order)
 *                         'q': uint64_t * (pulled in network byte order)
 *                         'S': ssh_string *
 *                         's': char ** (C string, pulled as SSH string)
 *                         'P': size_t, void ** (len of data, pointer to data)
 *                              only pulls data.
 *                         'B': bignum * (pulled as SSH string)
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @warning             when using 'P' with a constant size (e.g. 8), do not
 *                      forget to cast to (size_t).
 */
int _ssh_buffer_unpack(struct ssh_buffer_struct *buffer,
                       const char *format,
                       size_t argc,
                       ...)
{
    va_list ap;
    int rc;

    va_start(ap, argc);
    rc = ssh_buffer_unpack_va(buffer, format, argc, ap);
    va_end(ap);
    return rc;
}

/** @} */
