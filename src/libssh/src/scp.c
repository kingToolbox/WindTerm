/*
 * scp - SSH scp wrapper functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis <aris@0xbadc0de.be>
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
#include <string.h>
#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/scp.h"
#include "libssh/misc.h"

/**
 * @defgroup libssh_scp The SSH scp functions
 * @ingroup libssh
 *
 * SCP protocol over SSH functions
 *
 * @{
 */

/**
 * @brief Create a new scp session.
 *
 * @param[in]  session  The SSH session to use.
 *
 * @param[in]  mode     One of SSH_SCP_WRITE or SSH_SCP_READ, depending if you
 *                      need to drop files remotely or read them.
 *                      It is not possible to combine read and write.
 *                      SSH_SCP_RECURSIVE Flag can be or'ed to this to indicate
 *                      that you're going to use recursion. Browsing through
 *                      directories is not possible without this.
 *
 * @param[in]  location The directory in which write or read will be done. Any
 *                      push or pull will be relative to this place.
 *                      This can also be a pattern of files to download (read).
 *
 * @returns             A ssh_scp handle, NULL if the creation was impossible.
 */
ssh_scp ssh_scp_new(ssh_session session, int mode, const char *location)
{
    ssh_scp scp = NULL;

    if (session == NULL) {
        goto error;
    }

    scp = (ssh_scp)calloc(1, sizeof(struct ssh_scp_struct));
    if (scp == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Error allocating memory for ssh_scp");
        goto error;
    }

    if ((mode & ~SSH_SCP_RECURSIVE) != SSH_SCP_WRITE &&
        (mode & ~SSH_SCP_RECURSIVE) != SSH_SCP_READ)
    {
        ssh_set_error(session, SSH_FATAL,
                      "Invalid mode %d for ssh_scp_new()", mode);
        goto error;
    }

    if (strlen(location) > 32 * 1024) {
        ssh_set_error(session, SSH_FATAL,
                      "Location path is too long");
        goto error;
    }

    scp->location = strdup(location);
    if (scp->location == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Error allocating memory for ssh_scp");
        goto error;
    }

    scp->session = session;
    scp->mode = mode & ~SSH_SCP_RECURSIVE;
    scp->recursive = (mode & SSH_SCP_RECURSIVE) != 0;
    scp->channel = NULL;
    scp->state = SSH_SCP_NEW;

    return scp;

error:
    ssh_scp_free(scp);
    return NULL;
}

/**
 * @brief Initialize the scp channel.
 *
 * @param[in]  scp      The scp context to initialize.
 *
 * @return SSH_OK on success or an SSH error code.
 *
 * @see ssh_scp_new()
 */
int ssh_scp_init(ssh_scp scp)
{
    int rc;
    char execbuffer[1024] = {0};
    char *quoted_location = NULL;
    size_t quoted_location_len = 0;
    size_t scp_location_len;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_NEW) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_init called under invalid state");
        return SSH_ERROR;
    }

    if (scp->location == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Invalid scp context: location is NULL");
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "Initializing scp session %s %son location '%s'",
            scp->mode == SSH_SCP_WRITE?"write":"read",
            scp->recursive ? "recursive " : "",
            scp->location);

    scp->channel = ssh_channel_new(scp->session);
    if (scp->channel == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Channel creation failed for scp");
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_channel_open_session(scp->channel);
    if (rc == SSH_ERROR) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to open channel for scp");
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    /* In the worst case, each character would be replaced by 3 plus the string
     * terminator '\0' */
    scp_location_len = strlen(scp->location);
    quoted_location_len = ((size_t)3 * scp_location_len) + 1;
    /* Paranoia check */
    if (quoted_location_len < scp_location_len) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Buffer overflow detected");
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    quoted_location = (char *)calloc(1, quoted_location_len);
    if (quoted_location == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to allocate memory for quoted location");
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_quote_file_name(scp->location, quoted_location,
                             quoted_location_len);
    if (rc <= 0) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to single quote command location");
        SAFE_FREE(quoted_location);
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    if (scp->mode == SSH_SCP_WRITE) {
        snprintf(execbuffer, sizeof(execbuffer), "scp -t %s %s",
                scp->recursive ? "-r" : "", quoted_location);
    } else {
        snprintf(execbuffer, sizeof(execbuffer), "scp -f %s %s",
                scp->recursive ? "-r" : "", quoted_location);
    }

    SAFE_FREE(quoted_location);

    SSH_LOG(SSH_LOG_DEBUG, "Executing command: %s", execbuffer);

    rc = ssh_channel_request_exec(scp->channel, execbuffer);
    if (rc == SSH_ERROR){
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed executing command: %s", execbuffer);
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    if (scp->mode == SSH_SCP_WRITE) {
        rc = ssh_scp_response(scp, NULL);
        if (rc != 0) {
            return SSH_ERROR;
        }
    } else {
        ssh_channel_write(scp->channel, "", 1);
    }

    if (scp->mode == SSH_SCP_WRITE) {
        scp->state = SSH_SCP_WRITE_INITED;
    } else {
        scp->state = SSH_SCP_READ_INITED;
    }

    return SSH_OK;
}

/**
 * @brief Close the scp channel.
 *
 * @param[in]  scp      The scp context to close.
 *
 * @return SSH_OK on success or an SSH error code.
 *
 * @see ssh_scp_init()
 */
int ssh_scp_close(ssh_scp scp)
{
    char buffer[128] = {0};
    int rc;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->channel != NULL) {
        if (ssh_channel_send_eof(scp->channel) == SSH_ERROR) {
            scp->state = SSH_SCP_ERROR;
            return SSH_ERROR;
        }
        /* avoid situations where data are buffered and
         * not yet stored on disk. This can happen if the close is sent
         * before we got the EOF back
         */
        while (!ssh_channel_is_eof(scp->channel)) {
            rc = ssh_channel_read(scp->channel, buffer, sizeof(buffer), 0);
            if (rc == SSH_ERROR || rc == 0) {
                break;
            }
        }

        if (ssh_channel_close(scp->channel) == SSH_ERROR) {
            scp->state = SSH_SCP_ERROR;
            return SSH_ERROR;
        }

        ssh_channel_free(scp->channel);
        scp->channel = NULL;
    }

    scp->state = SSH_SCP_NEW;
    return SSH_OK;
}

/**
 * @brief Free a scp context.
 *
 * @param[in]  scp      The context to free.
 *
 * @see ssh_scp_new()
 */
void ssh_scp_free(ssh_scp scp)
{
    if (scp == NULL) {
        return;
    }

    if (scp->state != SSH_SCP_NEW) {
        ssh_scp_close(scp);
    }

    if (scp->channel) {
        ssh_channel_free(scp->channel);
    }

    SAFE_FREE(scp->location);
    SAFE_FREE(scp->request_name);
    SAFE_FREE(scp->warning);
    SAFE_FREE(scp);
}

/**
 * @brief Create a directory in a scp in sink mode.
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[in]  dirname  The name of the directory being created.
 *
 * @param[in]  mode     The UNIX permissions for the new directory, e.g. 0755.
 *
 * @returns             SSH_OK if the directory has been created, SSH_ERROR if
 *                      an error occured.
 *
 * @see ssh_scp_leave_directory()
 */
int ssh_scp_push_directory(ssh_scp scp, const char *dirname, int mode)
{
    char buffer[1024] = {0};
    int rc;
    char *dir = NULL;
    char *perms = NULL;
    char *vis_encoded = NULL;
    size_t vis_encoded_len;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_WRITE_INITED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_push_directory called under invalid state");
        return SSH_ERROR;
    }

    dir = ssh_basename(dirname);
    if (dir == NULL) {
        ssh_set_error_oom(scp->session);
        return SSH_ERROR;
    }

    vis_encoded_len = (2 * strlen(dir)) + 1;
    vis_encoded = (char *)calloc(1, vis_encoded_len);
    if (vis_encoded == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to allocate buffer to vis encode directory name");
        goto error;
    }

    rc = ssh_newline_vis(dir, vis_encoded, vis_encoded_len);
    if (rc <= 0) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to vis encode directory name");
        goto error;
    }

    perms = ssh_scp_string_mode(mode);
    if (perms == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to get directory permission string");
        goto error;
    }

    SSH_LOG(SSH_LOG_PROTOCOL,
            "SCP pushing directory %s with permissions '%s'",
            vis_encoded, perms);

    /* Use vis encoded directory name */
    snprintf(buffer, sizeof(buffer),
             "D%s 0 %s\n",
             perms, vis_encoded);

    SAFE_FREE(dir);
    SAFE_FREE(perms);
    SAFE_FREE(vis_encoded);

    rc = ssh_channel_write(scp->channel, buffer, strlen(buffer));
    if (rc == SSH_ERROR) {
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_scp_response(scp, NULL);
    if (rc != 0) {
        return SSH_ERROR;
    }

    return SSH_OK;

error:
    SAFE_FREE(dir);
    SAFE_FREE(perms);
    SAFE_FREE(vis_encoded);

    return SSH_ERROR;
}

/**
 * @brief Leave a directory.
 *
 * @returns             SSH_OK if the directory has been left, SSH_ERROR if an
 *                      error occured.
 *
 * @see ssh_scp_push_directory()
 */
int ssh_scp_leave_directory(ssh_scp scp)
{
    char buffer[] = "E\n";
    int rc;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_WRITE_INITED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_leave_directory called under invalid state");
        return SSH_ERROR;
    }

    rc = ssh_channel_write(scp->channel, buffer, strlen(buffer));
    if (rc == SSH_ERROR) {
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_scp_response(scp, NULL);
    if (rc != 0) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Initialize the sending of a file to a scp in sink mode, using a 64-bit
 * size.
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[in]  filename The name of the file being sent. It should not contain
 *                      any path indicator
 *
 * @param[in]  size     Exact size in bytes of the file being sent.
 *
 * @param[in]  mode     The UNIX permissions for the new file, e.g. 0644.
 *
 * @returns             SSH_OK if the file is ready to be sent, SSH_ERROR if an
 *                      error occured.
 *
 * @see ssh_scp_push_file()
 */
int ssh_scp_push_file64(ssh_scp scp, const char *filename, uint64_t size,
                        int mode)
{
    char buffer[1024] = {0};
    int rc;
    char *file = NULL;
    char *perms = NULL;
    char *vis_encoded = NULL;
    size_t vis_encoded_len;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_WRITE_INITED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_push_file called under invalid state");
        return SSH_ERROR;
    }

    file = ssh_basename(filename);
    if (file == NULL) {
        ssh_set_error_oom(scp->session);
        return SSH_ERROR;
    }

    vis_encoded_len = (2 * strlen(file)) + 1;
    vis_encoded = (char *)calloc(1, vis_encoded_len);
    if (vis_encoded == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to allocate buffer to vis encode file name");
        goto error;
    }

    rc = ssh_newline_vis(file, vis_encoded, vis_encoded_len);
    if (rc <= 0) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to vis encode file name");
        goto error;
    }

    perms = ssh_scp_string_mode(mode);
    if (perms == NULL) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "Failed to get file permission string");
        goto error;
    }

    SSH_LOG(SSH_LOG_PROTOCOL,
            "SCP pushing file %s, size %" PRIu64 " with permissions '%s'",
            vis_encoded, size, perms);

    /* Use vis encoded file name */
    snprintf(buffer, sizeof(buffer),
             "C%s %" PRIu64 " %s\n",
             perms, size, vis_encoded);

    SAFE_FREE(file);
    SAFE_FREE(perms);
    SAFE_FREE(vis_encoded);

    rc = ssh_channel_write(scp->channel, buffer, strlen(buffer));
    if (rc == SSH_ERROR) {
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_scp_response(scp, NULL);
    if (rc != 0) {
        return SSH_ERROR;
    }

    scp->filelen = size;
    scp->processed = 0;
    scp->state = SSH_SCP_WRITE_WRITING;

    return SSH_OK;

error:
    SAFE_FREE(file);
    SAFE_FREE(perms);
    SAFE_FREE(vis_encoded);

    return SSH_ERROR;
}

/**
 * @brief Initialize the sending of a file to a scp in sink mode.
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[in]  filename The name of the file being sent. It should not contain
 *                      any path indicator
 *
 * @param[in]  size     Exact size in bytes of the file being sent.
 *
 * @param[in]  mode     The UNIX permissions for the new file, e.g. 0644.
 *
 * @returns             SSH_OK if the file is ready to be sent, SSH_ERROR if an
 *                      error occured.
 */
int ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, int mode)
{
    return ssh_scp_push_file64(scp, filename, (uint64_t) size, mode);
}

/**
 * @internal
 *
 * @brief Wait for a response of the scp server.
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[out] response A pointer where the response message must be copied if
 *                      any. This pointer must then be free'd.
 *
 * @returns             The return code, SSH_ERROR a error occured.
 */
int ssh_scp_response(ssh_scp scp, char **response)
{
    unsigned char code;
    int rc;
    char msg[128] = {0};

    if (scp == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_channel_read(scp->channel, &code, 1, 0);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    if (code == 0) {
        return 0;
    }

    if (code > 2) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "SCP: invalid status code %u received", code);
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    rc = ssh_scp_read_string(scp, msg, sizeof(msg));
    if (rc == SSH_ERROR) {
        return rc;
    }

    /* Warning */
    if (code == 1) {
        ssh_set_error(scp->session, SSH_REQUEST_DENIED,
                      "SCP: Warning: status code 1 received: %s", msg);
        SSH_LOG(SSH_LOG_RARE,
                "SCP: Warning: status code 1 received: %s", msg);
        if (response) {
            *response = strdup(msg);
        }
        return 1;
    }

    if (code == 2) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "SCP: Error: status code 2 received: %s", msg);
        if (response) {
            *response = strdup(msg);
        }
        return 2;
    }

    /* Not reached */
    return SSH_ERROR;
}

/**
 * @brief Write into a remote scp file.
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[in]  buffer   The buffer to write.
 *
 * @param[in]  len      The number of bytes to write.
 *
 * @returns             SSH_OK if the write was successful, SSH_ERROR an error
 *                      occured while writing.
 */
int ssh_scp_write(ssh_scp scp, const void *buffer, size_t len)
{
    int w;
    int rc;
    uint8_t code;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_WRITE_WRITING) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_write called under invalid state");
        return SSH_ERROR;
    }

    if (scp->processed + len > scp->filelen) {
        len = (size_t) (scp->filelen - scp->processed);
    }

    /* hack to avoid waiting for window change */
    rc = ssh_channel_poll(scp->channel, 0);
    if (rc == SSH_ERROR) {
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    w = ssh_channel_write(scp->channel, buffer, len);
    if (w != SSH_ERROR) {
        scp->processed += w;
    } else {
        scp->state = SSH_SCP_ERROR;
        //return = channel_get_exit_status(scp->channel);
        return SSH_ERROR;
    }

    /* Far end sometimes send a status message, which we need to read
     * and handle */
    rc = ssh_channel_poll(scp->channel, 0);
    if (rc > 0) {
        rc = ssh_scp_response(scp, NULL);
        if (rc != 0) {
            return SSH_ERROR;
        }
    }

    /* Check if we arrived at end of file */
    if (scp->processed == scp->filelen) {
        code = 0;
        w = ssh_channel_write(scp->channel, &code, 1);
        if (w == SSH_ERROR) {
            scp->state = SSH_SCP_ERROR;
            return SSH_ERROR;
        }

        scp->processed = scp->filelen = 0;
        scp->state = SSH_SCP_WRITE_INITED;
    }

    return SSH_OK;
}

/**
 * @brief Read a string on a channel, terminated by '\n'
 *
 * @param[in]  scp      The scp handle.
 *
 * @param[out] buffer   A pointer to a buffer to place the string.
 *
 * @param[in]  len      The size of the buffer in bytes. If the string is bigger
 *                      than len-1, only len-1 bytes are read and the string is
 *                      null-terminated.
 *
 * @returns             SSH_OK if the string was read, SSH_ERROR if an error
 *                      occured while reading.
 */
int ssh_scp_read_string(ssh_scp scp, char *buffer, size_t len)
{
    size_t read = 0;
    int err = SSH_OK;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    while (read < len - 1) {
        err = ssh_channel_read(scp->channel, &buffer[read], 1, 0);
        if (err == SSH_ERROR) {
            break;
        }

        if (err == 0) {
            ssh_set_error(scp->session, SSH_FATAL,
                          "End of file while reading string");
            err = SSH_ERROR;
            break;
        }

        read++;
        if (buffer[read - 1] == '\n') {
            break;
        }
    }

    buffer[read] = 0;
    return err;
}

/**
 * @brief Wait for a scp request (file, directory).
 *
 * @returns             SSH_SCP_REQUEST_NEWFILE:       The other side is sending
 *                                                     a file
 *                      SSH_SCP_REQUEST_NEWDIR:  The other side is sending
 *                                                     a directory
 *                      SSH_SCP_REQUEST_ENDDIR: The other side has
 *                                                     finished with the current
 *                                                     directory
 *                      SSH_SCP_REQUEST_WARNING: The other side sent us a warning
 *                      SSH_SCP_REQUEST_EOF: The other side finished sending us
 *                                           files and data.
 *                      SSH_ERROR:                     Some error happened
 *
 * @see ssh_scp_read()
 * @see ssh_scp_deny_request()
 * @see ssh_scp_accept_request()
 * @see ssh_scp_request_get_warning()
 */
int ssh_scp_pull_request(ssh_scp scp)
{
    char buffer[MAX_BUF_SIZE] = {0};
    char *mode = NULL;
    char *p, *tmp;
    uint64_t size;
    char *name = NULL;
    int rc;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_READ_INITED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_pull_request called under invalid state");
        return SSH_ERROR;
    }

    rc = ssh_scp_read_string(scp, buffer, sizeof(buffer));
    if (rc == SSH_ERROR) {
        if (ssh_channel_is_eof(scp->channel)) {
            scp->state = SSH_SCP_TERMINATED;
            return SSH_SCP_REQUEST_EOF;
        }
        return rc;
    }

    p = strchr(buffer, '\n');
    if (p != NULL) {
        *p = '\0';
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "Received SCP request: '%s'", buffer);
    switch(buffer[0]) {
    case 'C':
        /* File */
    case 'D':
        /* Directory */
        p = strchr(buffer, ' ');
        if (p == NULL) {
            goto error;
        }
        *p = '\0';
        p++;
        //mode = strdup(&buffer[1]);
        scp->request_mode = ssh_scp_integer_mode(&buffer[1]);
        tmp = p;
        p = strchr(p, ' ');
        if (p == NULL) {
            goto error;
        }
        *p = 0;
        size = strtoull(tmp, NULL, 10);
        p++;
        name = strdup(p);
        SAFE_FREE(scp->request_name);
        scp->request_name = name;
        if (buffer[0] == 'C') {
            scp->filelen = size;
            scp->request_type = SSH_SCP_REQUEST_NEWFILE;
        } else {
            scp->filelen = '0';
            scp->request_type = SSH_SCP_REQUEST_NEWDIR;
        }
        scp->state = SSH_SCP_READ_REQUESTED;
        scp->processed = 0;
        return scp->request_type;
        break;
    case 'E':
        scp->request_type = SSH_SCP_REQUEST_ENDDIR;
        ssh_channel_write(scp->channel, "", 1);
        return scp->request_type;
    case 0x1:
        ssh_set_error(scp->session, SSH_REQUEST_DENIED,
                      "SCP: Warning: %s", &buffer[1]);
        scp->request_type = SSH_SCP_REQUEST_WARNING;
        SAFE_FREE(scp->warning);
        scp->warning = strdup(&buffer[1]);
        return scp->request_type;
    case 0x2:
        ssh_set_error(scp->session, SSH_FATAL,
                      "SCP: Error: %s", &buffer[1]);
        return SSH_ERROR;
    case 'T':
        /* Timestamp */
    default:
        ssh_set_error(scp->session, SSH_FATAL,
                      "Unhandled message: (%d)%s", buffer[0], buffer);
        return SSH_ERROR;
    }

    /* a parsing error occured */
error:
    SAFE_FREE(name);
    SAFE_FREE(mode);
    ssh_set_error(scp->session, SSH_FATAL,
                  "Parsing error while parsing message: %s", buffer);
    return SSH_ERROR;
}

/**
 * @brief Deny the transfer of a file or creation of a directory coming from the
 * remote party.
 *
 * @param[in]  scp      The scp handle.
 * @param[in]  reason   A nul-terminated string with a human-readable
 *                      explanation of the deny.
 *
 * @returns             SSH_OK if the message was sent, SSH_ERROR if the sending
 *                      the message failed, or sending it in a bad state.
 */
int ssh_scp_deny_request(ssh_scp scp, const char *reason)
{
    char buffer[MAX_BUF_SIZE] = {0};
    int rc;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_READ_REQUESTED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_deny_request called under invalid state");
        return SSH_ERROR;
    }

    snprintf(buffer, sizeof(buffer), "%c%s\n", 2, reason);
    rc = ssh_channel_write(scp->channel, buffer, strlen(buffer));
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    else {
        scp->state = SSH_SCP_READ_INITED;
        return SSH_OK;
    }
}

/**
 * @brief Accepts transfer of a file or creation of a directory coming from the
 * remote party.
 *
 * @param[in]  scp      The scp handle.
 *
 * @returns             SSH_OK if the message was sent, SSH_ERROR if sending the
 *                      message failed, or sending it in a bad state.
 */
int ssh_scp_accept_request(ssh_scp scp)
{
    char buffer[] = {0x00};
    int rc;
    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state != SSH_SCP_READ_REQUESTED) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_deny_request called under invalid state");
        return SSH_ERROR;
    }

    rc = ssh_channel_write(scp->channel, buffer, 1);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    if (scp->request_type == SSH_SCP_REQUEST_NEWFILE) {
        scp->state = SSH_SCP_READ_READING;
    } else {
        scp->state = SSH_SCP_READ_INITED;
    }

    return SSH_OK;
}

/** @brief Read from a remote scp file
 * @param[in]  scp      The scp handle.
 *
 * @param[in]  buffer   The destination buffer.
 *
 * @param[in]  size     The size of the buffer.
 *
 * @returns             The nNumber of bytes read, SSH_ERROR if an error occured
 *                      while reading.
 */
int ssh_scp_read(ssh_scp scp, void *buffer, size_t size)
{
    int rc;
    int code;

    if (scp == NULL) {
        return SSH_ERROR;
    }

    if (scp->state == SSH_SCP_READ_REQUESTED &&
        scp->request_type == SSH_SCP_REQUEST_NEWFILE)
    {
        rc = ssh_scp_accept_request(scp);
        if (rc == SSH_ERROR) {
            return rc;
        }
    }

    if (scp->state != SSH_SCP_READ_READING) {
        ssh_set_error(scp->session, SSH_FATAL,
                      "ssh_scp_read called under invalid state");
        return SSH_ERROR;
    }

    if (scp->processed + size > scp->filelen) {
        size = (size_t) (scp->filelen - scp->processed);
    }

    if (size > 65536) {
        size = 65536; /* avoid too large reads */
    }

    rc = ssh_channel_read(scp->channel, buffer, size, 0);
    if (rc != SSH_ERROR) {
        scp->processed += rc;
    } else {
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    /* Check if we arrived at end of file */
    if (scp->processed == scp->filelen) {
        scp->processed = scp->filelen = 0;
        ssh_channel_write(scp->channel, "", 1);
        code = ssh_scp_response(scp, NULL);
        if (code == 0) {
            scp->state = SSH_SCP_READ_INITED;
            return rc;
        }
        if (code == 1) {
            scp->state = SSH_SCP_READ_INITED;
            return SSH_ERROR;
        }
        scp->state = SSH_SCP_ERROR;
        return SSH_ERROR;
    }

    return rc;
}

/**
 * @brief Get the name of the directory or file being pushed from the other
 * party.
 *
 * @returns             The file name, NULL on error. The string should not be
 *                      freed.
 */
const char *ssh_scp_request_get_filename(ssh_scp scp)
{
    if (scp == NULL) {
        return NULL;
    }

    return scp->request_name;
}

/**
 * @brief Get the permissions of the directory or file being pushed from the
 * other party.
 *
 * @returns             The UNIX permission, e.g 0644, -1 on error.
 */
int ssh_scp_request_get_permissions(ssh_scp scp)
{
    if (scp == NULL) {
        return -1;
    }

    return scp->request_mode;
}

/** @brief Get the size of the file being pushed from the other party.
 *
 * @returns             The numeric size of the file being read.
 * @warning             The real size may not fit in a 32 bits field and may
 *                      be truncated.
 * @see ssh_scp_request_get_size64()
 */
size_t ssh_scp_request_get_size(ssh_scp scp)
{
    if (scp == NULL) {
        return 0;
    }
    return (size_t)scp->filelen;
}

/** @brief Get the size of the file being pushed from the other party.
 *
 * @returns             The numeric size of the file being read.
 */
uint64_t ssh_scp_request_get_size64(ssh_scp scp)
{
    if (scp == NULL) {
        return 0;
    }
    return scp->filelen;
}

/**
 * @brief Convert a scp text mode to an integer.
 *
 * @param[in]  mode     The mode to convert, e.g. "0644".
 *
 * @returns             An integer value, e.g. 420 for "0644".
 */
int ssh_scp_integer_mode(const char *mode)
{
    int value = strtoul(mode, NULL, 8) & 0xffff;
    return value;
}

/**
 * @brief Convert a unix mode into a scp string.
 *
 * @param[in]  mode     The mode to convert, e.g. 420 or 0644.
 *
 * @returns             A pointer to a malloc'ed string containing the scp mode,
 *                      e.g. "0644".
 */
char *ssh_scp_string_mode(int mode)
{
    char buffer[16] = {0};
    snprintf(buffer, sizeof(buffer), "%.4o", mode);
    return strdup(buffer);
}

/**
 * @brief Get the warning string from a scp handle.
 *
 * @param[in]  scp      The scp handle.
 *
 * @returns             A warning string, or NULL on error. The string should
 *                      not be freed.
 */
const char *ssh_scp_request_get_warning(ssh_scp scp)
{
    if (scp == NULL) {
        return NULL;
    }

    return scp->warning;
}

/** @} */
