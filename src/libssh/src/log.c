/*
 * log.c - logging and debugging functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2013   by Aris Adamantiadis
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
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif /* HAVE_SYS_UTIME_H */
#include <time.h>

#include "libssh/priv.h"
#include "libssh/misc.h"
#include "libssh/session.h"

static LIBSSH_THREAD int ssh_log_level;
static LIBSSH_THREAD ssh_logging_callback ssh_log_cb;
static LIBSSH_THREAD void *ssh_log_userdata;

/**
 * @defgroup libssh_log The SSH logging functions.
 * @ingroup libssh
 *
 * Logging functions for debugging and problem resolving.
 *
 * @{
 */

static int current_timestring(int hires, char *buf, size_t len)
{
    char tbuf[64];
    struct timeval tv;
    struct tm *tm;
    time_t t;

    gettimeofday(&tv, NULL);
    t = (time_t) tv.tv_sec;

    tm = localtime(&t);
    if (tm == NULL) {
        return -1;
    }

    if (hires) {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s.%06ld", tbuf, (long)tv.tv_usec);
    } else {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s", tbuf);
    }

    return 0;
}

static void ssh_log_stderr(int verbosity,
                           const char *function,
                           const char *buffer)
{
    char date[128] = {0};
    int rc;

    rc = current_timestring(1, date, sizeof(date));
    if (rc == 0) {
        fprintf(stderr, "[%s, %d] %s:", date, verbosity, function);
    } else {
        fprintf(stderr, "[%d] %s", verbosity, function);
    }

    fprintf(stderr, "  %s\n", buffer);
}

void ssh_log_function(int verbosity,
                      const char *function,
                      const char *buffer)
{
    ssh_logging_callback log_fn = ssh_get_log_callback();
    if (log_fn) {
        char buf[1024];

        snprintf(buf, sizeof(buf), "%s: %s", function, buffer);

        log_fn(verbosity,
               function,
               buf,
               ssh_get_log_userdata());
        return;
    }

    ssh_log_stderr(verbosity, function, buffer);
}

void _ssh_log(int verbosity,
              const char *function,
              const char *format, ...)
{
    char buffer[1024];
    va_list va;

    if (verbosity <= ssh_get_log_level()) {
        va_start(va, format);
        vsnprintf(buffer, sizeof(buffer), format, va);
        va_end(va);
        ssh_log_function(verbosity, function, buffer);
    }
}

/* LEGACY */

void ssh_log(ssh_session session,
             int verbosity,
             const char *format, ...)
{
  char buffer[1024];
  va_list va;

  if (verbosity <= session->common.log_verbosity) {
    va_start(va, format);
    vsnprintf(buffer, sizeof(buffer), format, va);
    va_end(va);
    ssh_log_function(verbosity, "", buffer);
  }
}

/** @internal
 * @brief log a SSH event with a common pointer
 * @param common       The SSH/bind session.
 * @param verbosity     The verbosity of the event.
 * @param format        The format string of the log entry.
 */
void ssh_log_common(struct ssh_common_struct *common,
                    int verbosity,
                    const char *function,
                    const char *format, ...)
{
    char buffer[1024];
    va_list va;

    if (verbosity <= common->log_verbosity) {
        va_start(va, format);
        vsnprintf(buffer, sizeof(buffer), format, va);
        va_end(va);
        ssh_log_function(verbosity, function, buffer);
    }
}


/* PUBLIC */

/**
 * @brief Set the log level of the library.
 *
 * @param[in]  level    The level to set.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 */
int ssh_set_log_level(int level) {
  if (level < 0) {
    return SSH_ERROR;
  }

  ssh_log_level = level;

  return SSH_OK;
}

/**
 * @brief Get the log level of the library.
 *
 * @return    The value of the log level.
 */
int ssh_get_log_level(void) {
  return ssh_log_level;
}

int ssh_set_log_callback(ssh_logging_callback cb) {
  if (cb == NULL) {
    return SSH_ERROR;
  }

  ssh_log_cb = cb;

  return SSH_OK;
}

ssh_logging_callback ssh_get_log_callback(void) {
  return ssh_log_cb;
}

/**
 * @brief Get the userdata of the logging function.
 *
 * @return    The userdata if set or NULL.
 */
void *ssh_get_log_userdata(void)
{
    if (ssh_log_userdata == NULL) {
        return NULL;
    }

    return ssh_log_userdata;
}

/**
 * @brief Set the userdata for the logging function.
 *
 * @param[in]  data     The userdata to set.
 *
 * @return              SSH_OK on success.
 */
int ssh_set_log_userdata(void *data)
{
    ssh_log_userdata = data;

    return 0;
}

/** @} */
