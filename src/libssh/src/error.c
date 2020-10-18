/*
 * error.c - functions for ssh error handling
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

#include <stdio.h>
#include <stdarg.h>
#include "libssh/priv.h"
#include "libssh/session.h"

/**
 * @defgroup libssh_error The SSH error functions.
 * @ingroup libssh
 *
 * Functions for error handling.
 *
 * @{
 */

/**
 * @internal
 *
 * @brief Registers an error with a description.
 *
 * @param  error       The place to store the error.
 *
 * @param  code        The class of error.
 *
 * @param  descr       The description, which can be a format string.
 *
 * @param  ...         The arguments for the format string.
 */
void _ssh_set_error(void *error,
                    int code,
                    const char *function,
                    const char *descr, ...)
{
    struct ssh_common_struct *err = error;
    va_list va;

    va_start(va, descr);
    vsnprintf(err->error.error_buffer, ERROR_BUFFERLEN, descr, va);
    va_end(va);

    err->error.error_code = code;
    if (ssh_get_log_level() >= SSH_LOG_WARN) {
        ssh_log_function(SSH_LOG_WARN,
                         function,
                         err->error.error_buffer);
    }
}

/**
 * @internal
 *
 * @brief Registers an out of memory error
 *
 * @param  error       The place to store the error.
 *
 */
void _ssh_set_error_oom(void *error, const char *function)
{
    struct error_struct *err = error;

    snprintf(err->error_buffer, sizeof(err->error_buffer),
            "%s: Out of memory", function);
    err->error_code = SSH_FATAL;
}

/**
 * @internal
 *
 * @brief Registers an invalid argument error
 *
 * @param  error       The place to store the error.
 *
 * @param  function    The function the error happened in.
 *
 */
void _ssh_set_error_invalid(void *error, const char *function)
{
    _ssh_set_error(error, SSH_FATAL, function,
                   "Invalid argument in %s", function);
}

/**
 * @internal
 *
 * @brief Reset the error code and message
 *
 * @param  error       The place to reset the error.
 */
void ssh_reset_error(void *error)
{
    struct ssh_common_struct *err = error;

    ZERO_STRUCT(err->error.error_buffer);
    err->error.error_code = 0;
}

/**
 * @brief Retrieve the error text message from the last error.
 *
 * @param  error        An ssh_session or ssh_bind.
 *
 * @return A static string describing the error.
 */
const char *ssh_get_error(void *error) {
  struct error_struct *err = error;

  return err->error_buffer;
}

/**
 * @brief Retrieve the error code from the last error.
 *
 * @param  error        An ssh_session or ssh_bind.
 *
 * \return SSH_NO_ERROR       No error occurred\n
 *         SSH_REQUEST_DENIED The last request was denied but situation is
 *                            recoverable\n
 *         SSH_FATAL          A fatal error occurred. This could be an unexpected
 *                            disconnection\n
 *
 *         Other error codes are internal but can be considered same than
 *         SSH_FATAL.
 */
int ssh_get_error_code(void *error) {
  struct error_struct *err = error;

  return err->error_code;
}

/** @} */
