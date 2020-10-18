/*
 * keyfiles.c - private and public key handling for authentication.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <asn@cryptomilk.org>
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/options.h"
#include "libssh/knownhosts.h"
/*todo: remove this include */
#include "libssh/string.h"
#include "libssh/token.h"

#ifndef _WIN32
# include <netinet/in.h>
# include <arpa/inet.h>
#endif

/**
 * @addtogroup libssh_session
 *
 * @{
 */

/**
 * @internal
 *
 * @brief Return one line of known host file.
 *
 * This will return a token array containing (host|ip), keytype and key.
 *
 * @param[out] file     A pointer to the known host file. Could be pointing to
 *                      NULL at start.
 *
 * @param[in]  filename The file name of the known host file.
 *
 * @param[out] found_type A pointer to a string to be set with the found key
 *                        type.
 *
 * @returns             The found_type type of key (ie "dsa","ssh-rsa"). Don't
 *                      free that value. NULL if no match was found or the file
 *                      was not found.
 */
static struct ssh_tokens_st *ssh_get_knownhost_line(FILE **file,
                                                    const char *filename,
                                                    const char **found_type)
{
    char buffer[4096] = {0};
    char *ptr;
    struct ssh_tokens_st *tokens;

    if (*file == NULL) {
        *file = fopen(filename,"r");
        if (*file == NULL) {
            return NULL;
        }
    }

    while (fgets(buffer, sizeof(buffer), *file)) {
        ptr = strchr(buffer, '\n');
        if (ptr) {
            *ptr =  '\0';
        }

        ptr = strchr(buffer,'\r');
        if (ptr) {
            *ptr = '\0';
        }

        if (buffer[0] == '\0' || buffer[0] == '#') {
            continue; /* skip empty lines */
        }

        tokens = ssh_tokenize(buffer, ' ');
        if (tokens == NULL) {
            fclose(*file);
            *file = NULL;

            return NULL;
        }

        if (tokens->tokens[0] == NULL ||
            tokens->tokens[1] == NULL ||
            tokens->tokens[2] == NULL)
        {
            /* it should have at least 3 tokens */
            ssh_tokens_free(tokens);
            continue;
        }

        *found_type = tokens->tokens[1];

        return tokens;
    }

    fclose(*file);
    *file = NULL;

    /* we did not find anything, end of file*/
    return NULL;
}

/**
 * @internal
 *
 * @brief Check the public key in the known host line matches the public key of
 * the currently connected server.
 *
 * @param[in] session   The SSH session to use.
 *
 * @param[in] tokens    A list of tokens in the known_hosts line.
 *
 * @returns             1 if the key matches, 0 if the key doesn't match and -1
 *                      on error.
 */
static int check_public_key(ssh_session session, char **tokens) {
  ssh_string pubkey_blob = NULL;
  ssh_buffer pubkey_buffer;
  char *pubkey_64;
  int rc;

    /* ssh-dss or ssh-rsa */
    pubkey_64 = tokens[2];
    pubkey_buffer = base64_to_bin(pubkey_64);

  if (pubkey_buffer == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "Verifying that server is a known host: base64 error");
    return -1;
  }

  rc = ssh_dh_get_current_server_publickey_blob(session, &pubkey_blob);
  if (rc != 0) {
      ssh_buffer_free(pubkey_buffer);
      return -1;
  }

  if (ssh_buffer_get_len(pubkey_buffer) != ssh_string_len(pubkey_blob)) {
    ssh_string_free(pubkey_blob);
    ssh_buffer_free(pubkey_buffer);
    return 0;
  }

  /* now test that they are identical */
  if (memcmp(ssh_buffer_get(pubkey_buffer), ssh_string_data(pubkey_blob),
        ssh_buffer_get_len(pubkey_buffer)) != 0) {
    ssh_string_free(pubkey_blob);
    ssh_buffer_free(pubkey_buffer);
    return 0;
  }

  ssh_string_free(pubkey_blob);
  ssh_buffer_free(pubkey_buffer);
  return 1;
}

/**
 * @internal
 * @brief Check if a hostname matches a openssh-style hashed known host.
 *
 * @param[in]  host     The host to check.
 *
 * @param[in]  hashed   The hashed value.
 *
 * @returns             1 if it matches, 0 otherwise.
 */
static int match_hashed_host(const char *host, const char *sourcehash)
{
  /* Openssh hash structure :
   * |1|base64 encoded salt|base64 encoded hash
   * hash is produced that way :
   * hash := HMAC_SHA1(key=salt,data=host)
   */
  unsigned char buffer[256] = {0};
  ssh_buffer salt;
  ssh_buffer hash;
  HMACCTX mac;
  char *source;
  char *b64hash;
  int match;
  unsigned int size;

  if (strncmp(sourcehash, "|1|", 3) != 0) {
    return 0;
  }

  source = strdup(sourcehash + 3);
  if (source == NULL) {
    return 0;
  }

  b64hash = strchr(source, '|');
  if (b64hash == NULL) {
    /* Invalid hash */
    SAFE_FREE(source);

    return 0;
  }

  *b64hash = '\0';
  b64hash++;

  salt = base64_to_bin(source);
  if (salt == NULL) {
    SAFE_FREE(source);

    return 0;
  }

  hash = base64_to_bin(b64hash);
  SAFE_FREE(source);
  if (hash == NULL) {
    ssh_buffer_free(salt);

    return 0;
  }

  mac = hmac_init(ssh_buffer_get(salt), ssh_buffer_get_len(salt), SSH_HMAC_SHA1);
  if (mac == NULL) {
    ssh_buffer_free(salt);
    ssh_buffer_free(hash);

    return 0;
  }
  size = sizeof(buffer);
  hmac_update(mac, host, strlen(host));
  hmac_final(mac, buffer, &size);

  if (size == ssh_buffer_get_len(hash) &&
      memcmp(buffer, ssh_buffer_get(hash), size) == 0) {
    match = 1;
  } else {
    match = 0;
  }

  ssh_buffer_free(salt);
  ssh_buffer_free(hash);

  SSH_LOG(SSH_LOG_PACKET,
      "Matching a hashed host: %s match=%d", host, match);

  return match;
}

/* How it's working :
 * 1- we open the known host file and bitch if it doesn't exist
 * 2- we need to examine each line of the file, until going on state SSH_SERVER_KNOWN_OK:
 *  - there's a match. if the key is good, state is SSH_SERVER_KNOWN_OK,
 *    else it's SSH_SERVER_KNOWN_CHANGED (or SSH_SERVER_FOUND_OTHER)
 *  - there's no match : no change
 */

/**
 * @brief This function is deprecated
 *
 * @deprecated          Please use ssh_session_is_known_server()
 * @see ssh_session_is_known_server()
 */
int ssh_is_server_known(ssh_session session)
{
    FILE *file = NULL;
    char *host;
    char *hostport;
    const char *type;
    int match;
    int i = 0;
    char *files[3];

    struct ssh_tokens_st *tokens;

    int ret = SSH_SERVER_NOT_KNOWN;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session, SSH_REQUEST_DENIED,
                    "Can't find a known_hosts file");

            return SSH_SERVER_FILE_NOT_FOUND;
        }
    }

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "Can't verify host in known hosts if the hostname isn't known");

        return SSH_SERVER_ERROR;
    }

    if (session->current_crypto == NULL){
        ssh_set_error(session, SSH_FATAL,
                "ssh_is_host_known called without cryptographic context");

        return SSH_SERVER_ERROR;
    }

    host = ssh_lowercase(session->opts.host);
    hostport = ssh_hostport(host, session->opts.port > 0 ? session->opts.port : 22);
    if (host == NULL || hostport == NULL) {
        ssh_set_error_oom(session);
        SAFE_FREE(host);
        SAFE_FREE(hostport);

        return SSH_SERVER_ERROR;
    }

    /* Set the list of known hosts files */
    i = 0;
    if (session->opts.global_knownhosts != NULL){
        files[i++] = session->opts.global_knownhosts;
    }
    files[i++] = session->opts.knownhosts;
    files[i] = NULL;
    i = 0;

    do {
        tokens = ssh_get_knownhost_line(&file,
                                        files[i],
                                        &type);

        /* End of file, return the current state or use next file */
        if (tokens == NULL) {
            ++i;
            if(files[i] == NULL)
                break;
            else
                continue;
        }
        match = match_hashed_host(host, tokens->tokens[0]);
        if (match == 0){
            match = match_hostname(hostport, tokens->tokens[0],
                                   strlen(tokens->tokens[0]));
        }
        if (match == 0) {
            match = match_hostname(host, tokens->tokens[0],
                                   strlen(tokens->tokens[0]));
        }
        if (match == 0) {
            match = match_hashed_host(hostport, tokens->tokens[0]);
        }
        if (match) {
            ssh_key pubkey = ssh_dh_get_current_server_publickey(session);
            const char *pubkey_type = ssh_key_type_to_char(ssh_key_type(pubkey));

            /* We got a match. Now check the key type */
            if (strcmp(pubkey_type, type) != 0) {
                SSH_LOG(SSH_LOG_PACKET,
                        "ssh_is_server_known: server type [%s] doesn't match the "
                        "type [%s] in known_hosts file",
                        pubkey_type,
                        type);
                /* Different type. We don't override the known_changed error which is
                 * more important */
                if (ret != SSH_SERVER_KNOWN_CHANGED)
                    ret = SSH_SERVER_FOUND_OTHER;
                ssh_tokens_free(tokens);
                continue;
            }
            /* so we know the key type is good. We may get a good key or a bad key. */
            match = check_public_key(session, tokens->tokens);
            ssh_tokens_free(tokens);

            if (match < 0) {
                ret = SSH_SERVER_ERROR;
                break;
            } else if (match == 1) {
                ret = SSH_SERVER_KNOWN_OK;
                break;
            } else if(match == 0) {
                /* We override the status with the wrong key state */
                ret = SSH_SERVER_KNOWN_CHANGED;
            }
        } else {
            ssh_tokens_free(tokens);
        }
    } while (1);

    if ((ret == SSH_SERVER_NOT_KNOWN) &&
            (session->opts.StrictHostKeyChecking == 0)) {
        int rv = ssh_session_update_known_hosts(session);
        if (rv != SSH_OK) {
            ret = SSH_SERVER_ERROR;
        } else {
            ret = SSH_SERVER_KNOWN_OK;
        }
    }

    SAFE_FREE(host);
    SAFE_FREE(hostport);
    if (file != NULL) {
        fclose(file);
    }

    /* Return the current state at end of file */
    return ret;
}

/**
 * @deprecated Please use ssh_session_export_known_hosts_entry()
 * @brief This function is deprecated.
 */
char * ssh_dump_knownhost(ssh_session session) {
    ssh_key server_pubkey = NULL;
    char *host;
    char *hostport;
    size_t len = 4096;
    char *buffer;
    char *b64_key;
    int rc;

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                "Can't write host in known hosts if the hostname isn't known");
        return NULL;
    }

    host = ssh_lowercase(session->opts.host);
    /* If using a nonstandard port, save the host in the [host]:port format */
    if (session->opts.port > 0 && session->opts.port != 22) {
        hostport = ssh_hostport(host, session->opts.port);
        SAFE_FREE(host);
        if (hostport == NULL) {
            return NULL;
        }
        host = hostport;
        hostport = NULL;
    }

    if (session->current_crypto==NULL) {
        ssh_set_error(session, SSH_FATAL, "No current crypto context");
        SAFE_FREE(host);
        return NULL;
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL){
        ssh_set_error(session, SSH_FATAL, "No public key present");
        SAFE_FREE(host);
        return NULL;
    }

    buffer = calloc (1, 4096);
    if (!buffer) {
        SAFE_FREE(host);
        return NULL;
    }

    rc = ssh_pki_export_pubkey_base64(server_pubkey, &b64_key);
    if (rc < 0) {
        SAFE_FREE(buffer);
        SAFE_FREE(host);
        return NULL;
    }

    snprintf(buffer, len,
            "%s %s %s\n",
            host,
            server_pubkey->type_c,
            b64_key);

    SAFE_FREE(host);
    SAFE_FREE(b64_key);

    return buffer;
}

/**
 * @deprecated Please use ssh_session_update_known_hosts()
 * @brief This function is deprecated
 */
int ssh_write_knownhost(ssh_session session)
{
    FILE *file;
    char *buffer = NULL;
    char *dir;
    int rc;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session, SSH_FATAL, "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    errno = 0;
    file = fopen(session->opts.knownhosts, "a");
    if (file == NULL) {
        if (errno == ENOENT) {
            dir = ssh_dirname(session->opts.knownhosts);
            if (dir == NULL) {
                ssh_set_error(session, SSH_FATAL, "%s", strerror(errno));
                return SSH_ERROR;
            }

            rc = ssh_mkdirs(dir, 0700);
            if (rc < 0) {
                ssh_set_error(session, SSH_FATAL,
                              "Cannot create %s directory: %s",
                              dir, strerror(errno));
                SAFE_FREE(dir);
                return SSH_ERROR;
            }
            SAFE_FREE(dir);

            errno = 0;
            file = fopen(session->opts.knownhosts, "a");
            if (file == NULL) {
                ssh_set_error(session, SSH_FATAL,
                              "Couldn't open known_hosts file %s"
                              " for appending: %s",
                              session->opts.knownhosts, strerror(errno));
                return SSH_ERROR;
            }
        } else {
            ssh_set_error(session, SSH_FATAL,
                          "Couldn't open known_hosts file %s for appending: %s",
                          session->opts.knownhosts, strerror(errno));
            return SSH_ERROR;
        }
    }

    rc = ssh_session_export_known_hosts_entry(session, &buffer);
    if (rc != SSH_OK) {
        fclose(file);
        return SSH_ERROR;
    }

    if (fwrite(buffer, strlen(buffer), 1, file) != 1 || ferror(file)) {
        SAFE_FREE(buffer);
        fclose(file);
        return -1;
    }

    SAFE_FREE(buffer);
    fclose(file);
    return 0;
}

#define KNOWNHOSTS_MAXTYPES 10

/** @} */
