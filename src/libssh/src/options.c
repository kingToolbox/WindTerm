/*
 * options.c - handle pre-connection options
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
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
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#else
#include <winsock2.h>
#endif
#include <sys/types.h>
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/options.h"
#ifdef WITH_SERVER
#include "libssh/server.h"
#include "libssh/bind.h"
#include "libssh/bind_config.h"
#endif

/**
 * @addtogroup libssh_session
 * @{
 */

/**
 * @brief Duplicate the options of a session structure.
 *
 * If you make several sessions with the same options this is useful. You
 * cannot use twice the same option structure in ssh_session_connect.
 *
 * @param src           The session to use to copy the options.
 *
 * @param dest          A pointer to store the allocated session with duplicated
 *                      options. You have to free the memory.
 *
 * @returns             0 on sucess, -1 on error with errno set.
 *
 * @see ssh_session_connect()
 */
int ssh_options_copy(ssh_session src, ssh_session *dest)
{
    ssh_session new;
    struct ssh_iterator *it = NULL;
    char *id = NULL;
    int i;

    if (src == NULL || dest == NULL) {
        return -1;
    }

    new = ssh_new();
    if (new == NULL) {
        return -1;
    }

    if (src->opts.username != NULL) {
        new->opts.username = strdup(src->opts.username);
        if (new->opts.username == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.host != NULL) {
        new->opts.host = strdup(src->opts.host);
        if (new->opts.host == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.bindaddr != NULL) {
        new->opts.bindaddr = strdup(src->opts.bindaddr);
        if (new->opts.bindaddr == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    /* Remove the default identities */
    for (id = ssh_list_pop_head(char *, new->opts.identity);
         id != NULL;
         id = ssh_list_pop_head(char *, new->opts.identity)) {
        SAFE_FREE(id);
    }
    /* Copy the new identities from the source list */
    if (src->opts.identity != NULL) {
        it = ssh_list_get_iterator(src->opts.identity);
        while (it) {
            int rc;

            id = strdup((char *) it->data);
            if (id == NULL) {
                ssh_free(new);
                return -1;
            }

            rc = ssh_list_append(new->opts.identity, id);
            if (rc < 0) {
                free(id);
                ssh_free(new);
                return -1;
            }
            it = it->next;
        }
    }

    if (src->opts.sshdir != NULL) {
        new->opts.sshdir = strdup(src->opts.sshdir);
        if (new->opts.sshdir == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.knownhosts != NULL) {
        new->opts.knownhosts = strdup(src->opts.knownhosts);
        if (new->opts.knownhosts == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.global_knownhosts != NULL) {
        new->opts.global_knownhosts = strdup(src->opts.global_knownhosts);
        if (new->opts.global_knownhosts == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (src->opts.wanted_methods[i] != NULL) {
            new->opts.wanted_methods[i] = strdup(src->opts.wanted_methods[i]);
            if (new->opts.wanted_methods[i] == NULL) {
                ssh_free(new);
                return -1;
            }
        }
    }

    if (src->opts.ProxyCommand != NULL) {
        new->opts.ProxyCommand = strdup(src->opts.ProxyCommand);
        if (new->opts.ProxyCommand == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.pubkey_accepted_types != NULL) {
        new->opts.pubkey_accepted_types = strdup(src->opts.pubkey_accepted_types);
        if (new->opts.pubkey_accepted_types == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.gss_server_identity != NULL) {
        new->opts.gss_server_identity = strdup(src->opts.gss_server_identity);
        if (new->opts.gss_server_identity == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.gss_client_identity != NULL) {
        new->opts.gss_client_identity = strdup(src->opts.gss_client_identity);
        if (new->opts.gss_client_identity == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    memcpy(new->opts.options_seen, src->opts.options_seen,
           sizeof(new->opts.options_seen));

    new->opts.fd                    = src->opts.fd;
    new->opts.port                  = src->opts.port;
    new->opts.timeout               = src->opts.timeout;
    new->opts.timeout_usec          = src->opts.timeout_usec;
    new->opts.compressionlevel      = src->opts.compressionlevel;
    new->opts.StrictHostKeyChecking = src->opts.StrictHostKeyChecking;
    new->opts.gss_delegate_creds    = src->opts.gss_delegate_creds;
    new->opts.flags                 = src->opts.flags;
    new->opts.nodelay               = src->opts.nodelay;
    new->opts.config_processed      = src->opts.config_processed;
    new->common.log_verbosity       = src->common.log_verbosity;
    new->common.callbacks           = src->common.callbacks;

    *dest = new;

    return 0;
}

int ssh_options_set_algo(ssh_session session,
                         enum ssh_kex_types_e algo,
                         const char *list)
{
    char *p = NULL;

    if (ssh_fips_mode()) {
        p = ssh_keep_fips_algos(algo, list);
    } else {
        p = ssh_keep_known_algos(algo, list);
    }

    if (p == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                "Setting method: no allowed algorithm for method \"%s\" (%s)",
                ssh_kex_get_description(algo), list);
        return -1;
    }

    SAFE_FREE(session->opts.wanted_methods[algo]);
    session->opts.wanted_methods[algo] = p;

    return 0;
}

/**
 * @brief This function can set all possible ssh options.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to set. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to (const char *).
 *
 *              - SSH_OPTIONS_PORT:
 *                The port to connect to (unsigned int *).
 *
 *              - SSH_OPTIONS_PORT_STR:
 *                The port to connect to (const char *).
 *
 *              - SSH_OPTIONS_FD:
 *                The file descriptor to use (socket_t).\n
 *                \n
 *                If you wish to open the socket yourself for a reason
 *                or another, set the file descriptor. Don't forget to
 *                set the hostname as the hostname is used as a key in
 *                the known_host mechanism.
 *
 *              - SSH_OPTIONS_BINDADDR:
 *                The address to bind the client to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n
 *                If the value is NULL, the username is set to the
 *                default username.
 *
 *              - SSH_OPTIONS_SSH_DIR:
 *                Set the ssh directory (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default ssh directory.\n
 *                \n
 *                The ssh directory is used for files like known_hosts
 *                and identity (private and public key). It may include
 *                "%s" which will be replaced by the user home
 *                directory.
 *
 *              - SSH_OPTIONS_KNOWNHOSTS:
 *                Set the known hosts file name (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default known hosts file, normally
 *                ~/.ssh/known_hosts.\n
 *                \n
 *                The known hosts file is used to certify remote hosts
 *                are genuine. It may include "%d" which will be
 *                replaced by the user home directory.
 *
 *              - SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
 *                Set the global known hosts file name (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default global known hosts file, normally
 *                /etc/ssh/ssh_known_hosts.\n
 *                \n
 *                The known hosts file is used to certify remote hosts
 *                are genuine.
 *
 *              - SSH_OPTIONS_ADD_IDENTITY (or SSH_OPTIONS_IDENTITY):
 *                Add a new identity file (const char *, format string) to
 *                the identity list.\n
 *                \n
 *                By default identity, id_dsa and id_rsa are checked.\n
 *                \n
 *                The identity used to authenticate with public key will be
 *                prepended to the list.
 *                It may include "%s" which will be replaced by the
 *                user home directory.
 *
 *              - SSH_OPTIONS_TIMEOUT:
 *                Set a timeout for the connection in seconds (long).
 *
 *              - SSH_OPTIONS_TIMEOUT_USEC:
 *                Set a timeout for the connection in micro seconds
 *                        (long).
 *
 *              - SSH_OPTIONS_SSH1:
 *                Deprecated
 *
 *              - SSH_OPTIONS_SSH2:
 *                Unused
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY:
 *                Set the session logging verbosity (int).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_WARNING: Only warnings
 *                - SSH_LOG_PROTOCOL: High level protocol information
 *                - SSH_LOG_PACKET: Lower level protocol infomations, packet level
 *                - SSH_LOG_FUNCTIONS: Every function path
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY_STR:
 *                Set the session logging verbosity via a
 *                string that will be converted to a numerical
 *                value (e.g. "3") and interpreted according
 *                to the values of
 *                SSH_OPTIONS_LOG_VERBOSITY above (const
 *                char *).
 *
 *              - SSH_OPTIONS_CIPHERS_C_S:
 *                Set the symmetric cipher client to server (const char *,
 *                comma-separated list).
 *
 *              - SSH_OPTIONS_CIPHERS_S_C:
 *                Set the symmetric cipher server to client (const char *,
 *                comma-separated list).
 *
 *              - SSH_OPTIONS_KEY_EXCHANGE:
 *                Set the key exchange method to be used (const char *,
 *                comma-separated list). ex:
 *                "ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
 *
 *              - SSH_OPTIONS_HMAC_C_S:
 *                Set the Message Authentication Code algorithm client to server
 *                (const char *, comma-separated list).
 *
 *              - SSH_OPTIONS_HMAC_S_C:
 *                Set the Message Authentication Code algorithm server to client
 *                (const char *, comma-separated list).
 *
 *              - SSH_OPTIONS_HOSTKEYS:
 *                Set the preferred server host key types (const char *,
 *                comma-separated list). ex:
 *                "ssh-rsa,ssh-dss,ecdh-sha2-nistp256"
 *
 *              - SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
 *                Set the preferred public key algorithms to be used for
 *                authentication (const char *, comma-separated list). ex:
 *                "ssh-rsa,rsa-sha2-256,ssh-dss,ecdh-sha2-nistp256"
 *
 *              - SSH_OPTIONS_COMPRESSION_C_S:
 *                Set the compression to use for client to server
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_S_C:
 *                Set the compression to use for server to client
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION:
 *                Set the compression to use for both directions
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_LEVEL:
 *                Set the compression level to use for zlib functions. (int,
 *                value from 1 to 9, 9 being the most efficient but slower).
 *
 *              - SSH_OPTIONS_STRICTHOSTKEYCHECK:
 *                Set the parameter StrictHostKeyChecking to avoid
 *                asking about a fingerprint (int, 0 = false).
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Set the command to be executed in order to connect to
 *                server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_SERVER_IDENTITY
 *                Set it to specify the GSSAPI server identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY
 *                Set it to specify the GSSAPI client identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS
 *                Set it to specify that GSSAPI should delegate credentials
 *                to the server (int, 0 = false).
 *
 *              - SSH_OPTIONS_PASSWORD_AUTH
 *                Set it if password authentication should be used
 *                in ssh_userauth_auto_pubkey(). (int, 0=false).
 *                Currently without effect (ssh_userauth_auto_pubkey doesn't use
 *                password authentication).
 *
 *              - SSH_OPTIONS_PUBKEY_AUTH
 *                Set it if pubkey authentication should be used
 *                in ssh_userauth_auto_pubkey(). (int, 0=false).
 *
 *              - SSH_OPTIONS_KBDINT_AUTH
 *                Set it if keyboard-interactive authentication should be used
 *                in ssh_userauth_auto_pubkey(). (int, 0=false).
 *                Currently without effect (ssh_userauth_auto_pubkey doesn't use
 *                keyboard-interactive authentication).
 *
 *              - SSH_OPTIONS_GSSAPI_AUTH
 *                Set it if gssapi authentication should be used
 *                in ssh_userauth_auto_pubkey(). (int, 0=false).
 *                Currently without effect (ssh_userauth_auto_pubkey doesn't use
 *                gssapi authentication).
 *
 *              - SSH_OPTIONS_NODELAY
 *                Set it to disable Nagle's Algorithm (TCP_NODELAY) on the
 *                session socket. (int, 0=false)
 *
 *              - SSH_OPTIONS_PROCESS_CONFIG
 *                Set it to false to disable automatic processing of per-user
 *                and system-wide OpenSSH configuration files. LibSSH
 *                automatically uses these configuration files unless
 *                you provide it with this option or with different file (bool).
 *
 *              - SSH_OPTIONS_REKEY_DATA
 *                Set the data limit that can be transferred with a single
 *                key in bytes. RFC 4253 Section 9 recommends 1GB of data, while
 *                RFC 4344 provides more specific restrictions, that are applied
 *                automatically. When specified, the lower value will be used.
 *                (uint64_t, 0=default)
 *
 *              - SSH_OPTIONS_REKEY_TIME
 *                Set the time limit for a session before intializing a rekey
 *                in seconds. RFC 4253 Section 9 recommends one hour.
 *                (uint32_t, 0=off)
 *
 * @param  value The value to set. This is a generic pointer and the
 *               datatype which is used should be set according to the
 *               type set.
 *
 * @return       0 on success, < 0 on error.
 */
int ssh_options_set(ssh_session session, enum ssh_options_e type,
    const void *value) {
    const char *v;
    char *p, *q;
    long int i;
    unsigned int u;
    int rc;

    if (session == NULL) {
        return -1;
    }

    switch (type) {
        case SSH_OPTIONS_HOST:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(value);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                p = strchr(q, '@');

                SAFE_FREE(session->opts.host);

                if (p) {
                    *p = '\0';
                    session->opts.host = strdup(p + 1);
                    if (session->opts.host == NULL) {
                        SAFE_FREE(q);
                        ssh_set_error_oom(session);
                        return -1;
                    }

                    SAFE_FREE(session->opts.username);
                    session->opts.username = strdup(q);
                    SAFE_FREE(q);
                    if (session->opts.username == NULL) {
                        ssh_set_error_oom(session);
                        return -1;
                    }
                } else {
                    session->opts.host = q;
                }
            }
            break;
        case SSH_OPTIONS_PORT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x <= 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = *x & 0xffffU;
            }
            break;
        case SSH_OPTIONS_PORT_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p) {
                    SAFE_FREE(q);
                }
                SAFE_FREE(q);
                if (i <= 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = i & 0xffffU;
            }
            break;
        case SSH_OPTIONS_FD:
            if (value == NULL) {
                session->opts.fd = SSH_INVALID_SOCKET;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                socket_t *x = (socket_t *) value;
                if (*x < 0) {
                    session->opts.fd = SSH_INVALID_SOCKET;
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.fd = *x & 0xffff;
            }
            break;
        case SSH_OPTIONS_BINDADDR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }

            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            SAFE_FREE(session->opts.bindaddr);
            session->opts.bindaddr = q;
            break;
        case SSH_OPTIONS_USER:
            v = value;
            SAFE_FREE(session->opts.username);
            if (v == NULL) {
                q = ssh_get_local_username();
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                session->opts.username = q;
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else { /* username provided */
                session->opts.username = strdup(value);
                if (session->opts.username == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_SSH_DIR:
            v = value;
            SAFE_FREE(session->opts.sshdir);
            if (v == NULL) {
                session->opts.sshdir = ssh_path_expand_tilde("~/.ssh");
                if (session->opts.sshdir == NULL) {
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.sshdir = ssh_path_expand_tilde(v);
                if (session->opts.sshdir == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_IDENTITY:
        case SSH_OPTIONS_ADD_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            rc = ssh_list_prepend(session->opts.identity, q);
            if (rc < 0) {
                free(q);
                return -1;
            }
            break;
        case SSH_OPTIONS_KNOWNHOSTS:
            v = value;
            SAFE_FREE(session->opts.knownhosts);
            if (v == NULL) {
                /* The default value will be set by the ssh_options_apply() */
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.knownhosts = strdup(v);
                if (session->opts.knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
            v = value;
            SAFE_FREE(session->opts.global_knownhosts);
            if (v == NULL) {
                session->opts.global_knownhosts =
                    strdup("/etc/ssh/ssh_known_hosts");
                if (session->opts.global_knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.global_knownhosts = strdup(v);
                if (session->opts.global_knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_TIMEOUT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout = *x & 0xffffffffU;
            }
            break;
        case SSH_OPTIONS_TIMEOUT_USEC:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout_usec = *x & 0xffffffffU;
            }
            break;
        case SSH_OPTIONS_SSH1:
            break;
        case SSH_OPTIONS_SSH2:
            break;
        case SSH_OPTIONS_LOG_VERBOSITY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = *x & 0xffffU;
                ssh_set_log_level(*x & 0xffffU);
            }
            break;
        case SSH_OPTIONS_LOG_VERBOSITY_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                session->common.log_verbosity = 0;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p) {
                    SAFE_FREE(q);
                }
                SAFE_FREE(q);
                if (i < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = i & 0xffffU;
                ssh_set_log_level(i & 0xffffU);
            }
            break;
        case SSH_OPTIONS_CIPHERS_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_CRYPT_C_S, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_CIPHERS_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_CRYPT_S_C, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_KEY_EXCHANGE:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_KEX, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_HOSTKEYS:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_HOSTKEYS, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_fips_mode()) {
                    p = ssh_keep_fips_algos(SSH_HOSTKEYS, v);
                } else {
                    p = ssh_keep_known_algos(SSH_HOSTKEYS, v);
                }
                if (p == NULL) {
                    ssh_set_error(session, SSH_REQUEST_DENIED,
                        "Setting method: no known public key algorithm (%s)",
                         v);
                    return -1;
                }

                SAFE_FREE(session->opts.pubkey_accepted_types);
                session->opts.pubkey_accepted_types = p;
            }
            break;
        case SSH_OPTIONS_HMAC_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_MAC_C_S, v) < 0)
                    return -1;
            }
            break;
         case SSH_OPTIONS_HMAC_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_MAC_S_C, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_COMPRESSION_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (strcasecmp(value,"yes")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_C_S,"zlib@openssh.com,zlib") < 0)
                        return -1;
                } else if (strcasecmp(value,"no")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_C_S,"none") < 0)
                        return -1;
                } else {
                    if (ssh_options_set_algo(session, SSH_COMP_C_S, v) < 0)
                        return -1;
                }
            }
            break;
        case SSH_OPTIONS_COMPRESSION_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (strcasecmp(value,"yes")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_S_C,"zlib@openssh.com,zlib") < 0)
                        return -1;
                } else if (strcasecmp(value,"no")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_S_C,"none") < 0)
                        return -1;
                } else {
                    if (ssh_options_set_algo(session, SSH_COMP_S_C, v) < 0)
                        return -1;
                }
            }
            break;
        case SSH_OPTIONS_COMPRESSION:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_C_S, v) < 0)
                return -1;
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_S_C, v) < 0)
                return -1;
            break;
        case SSH_OPTIONS_COMPRESSION_LEVEL:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < 1 || *x > 9) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.compressionlevel = *x & 0xff;
            }
            break;
        case SSH_OPTIONS_STRICTHOSTKEYCHECK:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;

                session->opts.StrictHostKeyChecking = (*x & 0xff) > 0 ? 1 : 0;
            }
            session->opts.StrictHostKeyChecking = *(int*)value;
            break;
        case SSH_OPTIONS_PROXYCOMMAND:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.ProxyCommand);
                /* Setting the command to 'none' disables this option. */
                rc = strcasecmp(v, "none");
                if (rc != 0) {
                    q = strdup(v);
                    if (q == NULL) {
                        return -1;
                    }
                    session->opts.ProxyCommand = q;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_SERVER_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_server_identity);
                session->opts.gss_server_identity = strdup(v);
                if (session->opts.gss_server_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_client_identity);
                session->opts.gss_client_identity = strdup(v);
                if (session->opts.gss_client_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int x = *(int *)value;

                session->opts.gss_delegate_creds = (x & 0xff);
            }
            break;
        case SSH_OPTIONS_PASSWORD_AUTH:
        case SSH_OPTIONS_PUBKEY_AUTH:
        case SSH_OPTIONS_KBDINT_AUTH:
        case SSH_OPTIONS_GSSAPI_AUTH:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int x = *(int *)value;
                u = type == SSH_OPTIONS_PASSWORD_AUTH ?
                    SSH_OPT_FLAG_PASSWORD_AUTH:
                    type == SSH_OPTIONS_PUBKEY_AUTH ?
                        SSH_OPT_FLAG_PUBKEY_AUTH:
                        type == SSH_OPTIONS_KBDINT_AUTH ?
                            SSH_OPT_FLAG_KBDINT_AUTH:
                            SSH_OPT_FLAG_GSSAPI_AUTH;
                if (x != 0){
                    session->opts.flags |= u;
                } else {
                    session->opts.flags &= ~u;
                }
            }
            break;
        case SSH_OPTIONS_NODELAY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                session->opts.nodelay = (*x & 0xff) > 0 ? 1 : 0;
            }
            break;
        case SSH_OPTIONS_PROCESS_CONFIG:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                bool *x = (bool *)value;
                session->opts.config_processed = !(*x);
            }
            break;
        case SSH_OPTIONS_REKEY_DATA:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                uint64_t *x = (uint64_t *)value;
                session->opts.rekey_data = *x;
            }
            break;
        case SSH_OPTIONS_REKEY_TIME:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                uint32_t *x = (uint32_t *)value;
                if ((*x * 1000) < *x) {
                    ssh_set_error(session, SSH_REQUEST_DENIED,
                                  "The provided value (%" PRIu32 ") for rekey"
                                  " time is too large", *x);
                    return -1;
                }
                session->opts.rekey_time = (*x) * 1000;
            }
            break;
        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return -1;
            break;
    }

    return 0;
}

/**
 * @brief This function can get ssh the ssh port. It must only be used on
 *        a valid ssh session. This function is useful when the session
 *        options have been automatically inferred from the environment
 *        or configuration files and one
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  port_target An unsigned integer into which the
 *         port will be set from the ssh session.
 *
 * @return       0 on success, < 0 on error.
 *
 */
int ssh_options_get_port(ssh_session session, unsigned int* port_target) {
    if (session == NULL) {
        return -1;
    }

    if (session->opts.port == 0) {
        *port_target = 22;
        return 0;
    }

    *port_target = session->opts.port;

    return 0;
}

/**
 * @brief This function can get ssh options, it does not support all options provided for
 *        ssh options set, but mostly those which a user-space program may care about having
 *        trusted the ssh driver to infer these values from underlaying configuration files.
 *        It operates only on those SSH_OPTIONS_* which return char*. If you wish to receive
 *        the port then please use ssh_options_get_port() which returns an unsigned int.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to get. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n when not explicitly set this will be inferred from the
 *                ~/.ssh/config file.
 *
 *              - SSH_OPTIONS_IDENTITY:
 *                Get the first identity file name (const char *).\n
 *                \n
 *                By default identity, id_dsa and id_rsa are checked.
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Get the proxycommand necessary to log into the
 *                remote host. When not explicitly set, it will be read
 *                from the ~/.ssh/config file.
 *
 *              - SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
 *                Get the path to the global known_hosts file being used.
 *
 *              - SSH_OPTIONS_KNOWNHOSTS:
 *                Get the path to the known_hosts file being used.
 *
 * @param  value The value to get into. As a char**, space will be
 *               allocated by the function for the value, it is
 *               your responsibility to free the memory using
 *               ssh_string_free_char().
 *
 * @return       SSH_OK on success, SSH_ERROR on error.
 */
int ssh_options_get(ssh_session session, enum ssh_options_e type, char** value)
{
    char* src = NULL;

    if (session == NULL) {
        return SSH_ERROR;
    }

    if (value == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    switch(type)
    {
        case SSH_OPTIONS_HOST: {
            src = session->opts.host;
            break;
        }
        case SSH_OPTIONS_USER: {
            src = session->opts.username;
            break;
        }
        case SSH_OPTIONS_IDENTITY: {
            struct ssh_iterator *it = ssh_list_get_iterator(session->opts.identity);
            if (it == NULL) {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, it);
            break;
        }
        case SSH_OPTIONS_PROXYCOMMAND: {
            src = session->opts.ProxyCommand;
            break;
        }
        case SSH_OPTIONS_KNOWNHOSTS: {
            src = session->opts.knownhosts;
            break;
        }
        case SSH_OPTIONS_GLOBAL_KNOWNHOSTS: {
            src = session->opts.global_knownhosts;
            break;
        }
        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return SSH_ERROR;
        break;
    }
    if (src == NULL) {
        return SSH_ERROR;
    }
    *value = strdup(src);
    if (*value == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Parse command line arguments.
 *
 * This is a helper for your application to generate the appropriate
 * options from the command line arguments.\n
 * The argv array and argc value are changed so that the parsed
 * arguments wont appear anymore in them.\n
 * The single arguments (without switches) are not parsed. thus,
 * myssh -l user localhost\n
 * The command wont set the hostname value of options to localhost.
 *
 * @param session       The session to configure.
 *
 * @param argcptr       The pointer to the argument count.
 *
 * @param argv          The arguments list pointer.
 *
 * @returns 0 on success, < 0 on error.
 *
 * @see ssh_session_new()
 */
int ssh_options_getopt(ssh_session session, int *argcptr, char **argv)
{
#ifdef _MSC_VER
    (void)session;
    (void)argcptr;
    (void)argv;
    /* Not supported with a Microsoft compiler */
    return -1;
#else
    char *user = NULL;
    char *cipher = NULL;
    char *identity = NULL;
    char *port = NULL;
    char **save = NULL;
    char **tmp = NULL;
    size_t i = 0;
    int argc = *argcptr;
    int debuglevel = 0;
    int usersa = 0;
    int usedss = 0;
    int compress = 0;
    int cont = 1;
    size_t current = 0;
    int saveoptind = optind; /* need to save 'em */
    int saveopterr = opterr;
    int opt;

    opterr = 0; /* shut up getopt */
    while((opt = getopt(argc, argv, "c:i:Cl:p:vb:rd12")) != -1) {
        switch(opt) {
        case 'l':
            user = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'v':
            debuglevel++;
            break;
        case 'r':
            usersa++;
            break;
        case 'd':
            usedss++;
            break;
        case 'c':
            cipher = optarg;
            break;
        case 'i':
            identity = optarg;
            break;
        case 'C':
            compress++;
            break;
        case '2':
            break;
        case '1':
            break;
        default:
            {
                char optv[3] = "- ";
                optv[1] = optopt;
                tmp = realloc(save, (current + 1) * sizeof(char*));
                if (tmp == NULL) {
                    SAFE_FREE(save);
                    ssh_set_error_oom(session);
                    return -1;
                }
                save = tmp;
                save[current] = strdup(optv);
                if (save[current] == NULL) {
                    SAFE_FREE(save);
                    ssh_set_error_oom(session);
                    return -1;
                }
                current++;
                if (optarg) {
                    save[current++] = argv[optind + 1];
                }
            }
        } /* switch */
    } /* while */
    opterr = saveopterr;
    tmp = realloc(save, (current + (argc - optind)) * sizeof(char*));
    if (tmp == NULL) {
        SAFE_FREE(save);
        ssh_set_error_oom(session);
        return -1;
    }
    save = tmp;
    while (optind < argc) {
        tmp = realloc(save, (current + 1) * sizeof(char*));
        if (tmp == NULL) {
            SAFE_FREE(save);
            ssh_set_error_oom(session);
            return -1;
        }
        save = tmp;
        save[current] = argv[optind];
        current++;
        optind++;
    }

    if (usersa && usedss) {
        ssh_set_error(session, SSH_FATAL, "Either RSA or DSS must be chosen");
        cont = 0;
    }

    ssh_set_log_level(debuglevel);

    optind = saveoptind;

    if(!cont) {
        SAFE_FREE(save);
        return -1;
    }

    /* first recopy the save vector into the original's */
    for (i = 0; i < current; i++) {
        /* don't erase argv[0] */
        argv[ i + 1] = save[i];
    }
    argv[current + 1] = NULL;
    *argcptr = current + 1;
    SAFE_FREE(save);

    /* set a new option struct */
    if (compress) {
        if (ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes") < 0) {
            cont = 0;
        }
    }

    if (cont && cipher) {
        if (ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher) < 0) {
            cont = 0;
        }
        if (cont && ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher) < 0) {
            cont = 0;
        }
    }

    if (cont && user) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            cont = 0;
        }
    }

    if (cont && identity) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity) < 0) {
            cont = 0;
        }
    }

    if (port != NULL) {
        ssh_options_set(session, SSH_OPTIONS_PORT_STR, port);
    }

    if (!cont) {
        return SSH_ERROR;
    }

    return SSH_OK;
#endif
}

/**
 * @brief Parse the ssh config file.
 *
 * This should be the last call of all options, it may overwrite options which
 * are already set. It requires that the host name is already set with
 * ssh_options_set_host().
 *
 * @param  session      SSH session handle
 *
 * @param  filename     The options file to use, if NULL the default
 *                      ~/.ssh/config will be used.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_host()
 */
int ssh_options_parse_config(ssh_session session, const char *filename) {
  char *expanded_filename;
  int r;

  if (session == NULL) {
    return -1;
  }
  if (session->opts.host == NULL) {
    ssh_set_error_invalid(session);
    return -1;
  }

  if (session->opts.sshdir == NULL) {
      r = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
      if (r < 0) {
          ssh_set_error_oom(session);
          return -1;
      }
  }

  /* set default filename */
  if (filename == NULL) {
    expanded_filename = ssh_path_expand_escape(session, "%d/config");
  } else {
    expanded_filename = ssh_path_expand_escape(session, filename);
  }
  if (expanded_filename == NULL) {
    return -1;
  }

  r = ssh_config_parse_file(session, expanded_filename);
  if (r < 0) {
      goto out;
  }
  if (filename == NULL) {
      r = ssh_config_parse_file(session, GLOBAL_CLIENT_CONFIG);
  }

  /* Do not process the default configuration as part of connection again */
  session->opts.config_processed = true;
out:
  free(expanded_filename);
  return r;
}

int ssh_options_apply(ssh_session session) {
    struct ssh_iterator *it;
    char *tmp;
    int rc;

    if (session->opts.sshdir == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.username == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.knownhosts == NULL) {
        tmp = ssh_path_expand_escape(session, "%d/known_hosts");
    } else {
        tmp = ssh_path_expand_escape(session, session->opts.knownhosts);
    }
    if (tmp == NULL) {
        return -1;
    }
    free(session->opts.knownhosts);
    session->opts.knownhosts = tmp;

    if (session->opts.global_knownhosts == NULL) {
        tmp = strdup("/etc/ssh/ssh_known_hosts");
    } else {
        tmp = ssh_path_expand_escape(session, session->opts.global_knownhosts);
    }
    if (tmp == NULL) {
        return -1;
    }
    free(session->opts.global_knownhosts);
    session->opts.global_knownhosts = tmp;

    if (session->opts.ProxyCommand != NULL) {
        tmp = ssh_path_expand_escape(session, session->opts.ProxyCommand);
        if (tmp == NULL) {
            return -1;
        }
        free(session->opts.ProxyCommand);
        session->opts.ProxyCommand = tmp;
    }

    for (it = ssh_list_get_iterator(session->opts.identity);
         it != NULL;
         it = it->next) {
        char *id = (char *) it->data;
        if (strncmp(id, "pkcs11:", 6) == 0) {
            /* PKCS#11 URIs are using percent-encoding so we can not mix
             * it with ssh expansion of ssh escape characters.
             * Skip these identities now, before we will have PKCS#11 support
             */
             continue;
        }
        tmp = ssh_path_expand_escape(session, id);
        if (tmp == NULL) {
            return -1;
        }
        free(id);
        it->data = tmp;
    }

    return 0;
}

/** @} */

#ifdef WITH_SERVER
/**
 * @addtogroup libssh_server
 * @{
 */
static int ssh_bind_set_key(ssh_bind sshbind, char **key_loc,
                            const void *value) {
    if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
    } else {
        SAFE_FREE(*key_loc);
        *key_loc = strdup(value);
        if (*key_loc == NULL) {
            ssh_set_error_oom(sshbind);
            return -1;
        }
    }
    return 0;
}

static int ssh_bind_set_algo(ssh_bind sshbind,
                             enum ssh_kex_types_e algo,
                             const char *list)
{
    char *p = NULL;

    if (ssh_fips_mode()) {
        p = ssh_keep_fips_algos(algo, list);
    } else {
        p = ssh_keep_known_algos(algo, list);
    }
    if (p == NULL) {
        ssh_set_error(sshbind, SSH_REQUEST_DENIED,
                      "Setting method: no algorithm for method \"%s\" (%s)",
                      ssh_kex_get_description(algo), list);
        return -1;
    }

    SAFE_FREE(sshbind->wanted_methods[algo]);
    sshbind->wanted_methods[algo] = p;

    return 0;
}

/**
 * @brief Set options for an SSH server bind.
 *
 * @param  sshbind      The ssh server bind to configure.
 *
 * @param  type         The option type to set. This should be one of the
 *                      following:
 *
 *                      - SSH_BIND_OPTIONS_HOSTKEY:
 *                        Set the path to an ssh host key, regardless
 *                        of type.  Only one key from per key type
 *                        (RSA, DSA, ECDSA) is allowed in an ssh_bind
 *                        at a time, and later calls to this function
 *                        with this option for the same key type will
 *                        override prior calls (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDADDR:
 *                        Set the IP address to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT:
 *                        Set the port to bind (unsigned int *).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT_STR:
 *                        Set the port to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY:
 *                        Set the session logging verbosity (int *).
 *                        The logging verbosity should have one of the
 *                        following values, which are listed in order
 *                        of increasing verbosity.  Every log message
 *                        with verbosity less than or equal to the
 *                        logging verbosity will be shown.
 *                        - SSH_LOG_NOLOG: No logging
 *                        - SSH_LOG_WARNING: Only warnings
 *                        - SSH_LOG_PROTOCOL: High level protocol information
 *                        - SSH_LOG_PACKET: Lower level protocol infomations, packet level
 *                        - SSH_LOG_FUNCTIONS: Every function path
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
 *                        Set the session logging verbosity via a
 *                        string that will be converted to a numerical
 *                        value (e.g. "3") and interpreted according
 *                        to the values of
 *                        SSH_BIND_OPTIONS_LOG_VERBOSITY above (const
 *                        char *).
 *
 *                      - SSH_BIND_OPTIONS_DSAKEY:
 *                        Set the path to the ssh host dsa key, SSHv2
 *                        only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_RSAKEY:
 *                        Set the path to the ssh host rsa key, SSHv2
 *                        only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_ECDSAKEY:
 *                        Set the path to the ssh host ecdsa key,
 *                        SSHv2 only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BANNER:
 *                        Set the server banner sent to clients (const char *).
 *
 *                      - SSH_BIND_OPTIONS_IMPORT_KEY:
 *                        Set the Private Key for the server directly (ssh_key)
 *
 *                      - SSH_BIND_OPTIONS_CIPHERS_C_S:
 *                        Set the symmetric cipher client to server (const char *,
 *                        comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_CIPHERS_S_C:
 *                        Set the symmetric cipher server to client (const char *,
 *                        comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_KEY_EXCHANGE:
 *                        Set the key exchange method to be used (const char *,
 *                        comma-separated list). ex:
 *                        "ecdh-sha2-nistp256,diffie-hellman-group14-sha1"
 *
 *                      - SSH_BIND_OPTIONS_HMAC_C_S:
 *                        Set the Message Authentication Code algorithm client
 *                        to server (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_HMAC_S_C:
 *                        Set the Message Authentication Code algorithm server
 *                        to client (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_CONFIG_DIR:
 *                        Set the directory (const char *, format string)
 *                        to be used when the "%d" scape is used when providing
 *                        paths of configuration files to
 *                        ssh_bind_options_parse_config().
 *
 *                      - SSH_BIND_OPTIONS_PROCESS_CONFIG
 *                        Set it to false to disable automatic processing of
 *                        system-wide configuration files. LibSSH automatically
 *                        uses these configuration files otherwise. This
 *                        option will only have effect if set before any call
 *                        to ssh_bind_options_parse_config() (bool).
 *
 *                      - SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES:
 *                        Set the public key algorithm accepted by the server
 *                        (const char *, comma-separated list).
 *
 *                      - SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS:
 *                        Set the list of allowed hostkey signatures algorithms
 *                        to offer to the client, ordered by preference. This
 *                        list is used as a filter when creating the list of
 *                        algorithms to offer to the client: first the list of
 *                        possible algorithms is created from the list of keys
 *                        set and then filtered against this list.
 *                        (const char *, comma-separated list).
 *
 * @param  value        The value to set. This is a generic pointer and the
 *                      datatype which should be used is described at the
 *                      corresponding value of type above.
 *
 * @return              0 on success, < 0 on error, invalid option, or parameter.
 */
int ssh_bind_options_set(ssh_bind sshbind, enum ssh_bind_options_e type,
    const void *value)
{
  char *p, *q;
  const char *v;
  int i, rc;

  if (sshbind == NULL) {
    return -1;
  }

  switch (type) {
    case SSH_BIND_OPTIONS_HOSTKEY:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
          int key_type;
          ssh_key key;
          ssh_key *bind_key_loc = NULL;
          char **bind_key_path_loc;

          rc = ssh_pki_import_privkey_file(value, NULL, NULL, NULL, &key);
          if (rc != SSH_OK) {
              return -1;
          }
          key_type = ssh_key_type(key);
          switch (key_type) {
          case SSH_KEYTYPE_DSS:
#ifdef HAVE_DSA
              bind_key_loc = &sshbind->dsa;
              bind_key_path_loc = &sshbind->dsakey;
#else
              ssh_set_error(sshbind,
                      SSH_FATAL,
                      "DSS key used and libssh compiled "
                      "without DSA support");
#endif
              break;
          case SSH_KEYTYPE_ECDSA_P256:
          case SSH_KEYTYPE_ECDSA_P384:
          case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_ECC
              bind_key_loc = &sshbind->ecdsa;
              bind_key_path_loc = &sshbind->ecdsakey;
#else
              ssh_set_error(sshbind,
                            SSH_FATAL,
                            "ECDSA key used and libssh compiled "
                            "without ECDSA support");
#endif
              break;
          case SSH_KEYTYPE_RSA:
              bind_key_loc = &sshbind->rsa;
              bind_key_path_loc = &sshbind->rsakey;
              break;
          case SSH_KEYTYPE_ED25519:
		  bind_key_loc = &sshbind->ed25519;
		  bind_key_path_loc = &sshbind->ed25519key;
		  break;
          default:
              ssh_set_error(sshbind,
                            SSH_FATAL,
                            "Unsupported key type %d", key_type);
          }

          if (bind_key_loc == NULL) {
              ssh_key_free(key);
              return -1;
          }

          /* Set the location of the key on disk even though we don't
             need it in case some other function wants it */
          rc = ssh_bind_set_key(sshbind, bind_key_path_loc, value);
          if (rc < 0) {
              ssh_key_free(key);
              return -1;
          }
          ssh_key_free(*bind_key_loc);
          *bind_key_loc = key;
      }
      break;
    case SSH_BIND_OPTIONS_IMPORT_KEY:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            int key_type;
            ssh_key *bind_key_loc = NULL;
            ssh_key key = (ssh_key)value;

            key_type = ssh_key_type(key);
            switch (key_type) {
                case SSH_KEYTYPE_DSS:
#ifdef HAVE_DSA
                    bind_key_loc = &sshbind->dsa;
#else
                    ssh_set_error(sshbind,
                                  SSH_FATAL,
                                  "DSA key used and libssh compiled "
                                  "without DSA support");
#endif
                    break;
                case SSH_KEYTYPE_ECDSA_P256:
                case SSH_KEYTYPE_ECDSA_P384:
                case SSH_KEYTYPE_ECDSA_P521:
#ifdef HAVE_ECC
                    bind_key_loc = &sshbind->ecdsa;
#else
                    ssh_set_error(sshbind,
                                  SSH_FATAL,
                                  "ECDSA key used and libssh compiled "
                                  "without ECDSA support");
#endif
                    break;
                case SSH_KEYTYPE_RSA:
                    bind_key_loc = &sshbind->rsa;
                    break;
                case SSH_KEYTYPE_ED25519:
                    bind_key_loc = &sshbind->ed25519;
                    break;
                default:
                    ssh_set_error(sshbind,
                                  SSH_FATAL,
                                  "Unsupported key type %d", key_type);
            }
            if (bind_key_loc == NULL)
                return -1;
            ssh_key_free(*bind_key_loc);
            *bind_key_loc = key;
        }
        break;
    case SSH_BIND_OPTIONS_BINDADDR:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->bindaddr);
        sshbind->bindaddr = strdup(value);
        if (sshbind->bindaddr == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        int *x = (int *) value;
        sshbind->bindport = *x & 0xffffU;
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT_STR:
      if (value == NULL) {
        sshbind->bindport = 22 & 0xffffU;
      } else {
        q = strdup(value);
        if (q == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        sshbind->bindport = i & 0xffffU;
      }
      break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        int *x = (int *) value;
        ssh_set_log_level(*x & 0xffffU);
      }
      break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
      if (value == NULL) {
      	ssh_set_log_level(0);
      } else {
        q = strdup(value);
        if (q == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        ssh_set_log_level(i & 0xffffU);
      }
      break;
    case SSH_BIND_OPTIONS_DSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->dsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_RSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->rsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_ECDSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->ecdsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_BANNER:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->banner);
        sshbind->banner = strdup(value);
        if (sshbind->banner == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_CIPHERS_C_S:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            if (ssh_bind_set_algo(sshbind, SSH_CRYPT_C_S, v) < 0)
                return -1;
        }
        break;
    case SSH_BIND_OPTIONS_CIPHERS_S_C:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            if (ssh_bind_set_algo(sshbind, SSH_CRYPT_S_C, v) < 0)
                return -1;
        }
        break;
    case SSH_BIND_OPTIONS_KEY_EXCHANGE:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind, SSH_KEX, v);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_HMAC_C_S:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            if (ssh_bind_set_algo(sshbind, SSH_MAC_C_S, v) < 0)
                return -1;
        }
        break;
     case SSH_BIND_OPTIONS_HMAC_S_C:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            if (ssh_bind_set_algo(sshbind, SSH_MAC_S_C, v) < 0)
                return -1;
        }
        break;
    case SSH_BIND_OPTIONS_CONFIG_DIR:
        v = value;
        SAFE_FREE(sshbind->config_dir);
        if (v == NULL) {
            break;
        } else if (v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            sshbind->config_dir = ssh_path_expand_tilde(v);
            if (sshbind->config_dir == NULL) {
                ssh_set_error_oom(sshbind);
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            if (ssh_fips_mode()) {
                p = ssh_keep_fips_algos(SSH_HOSTKEYS, v);
            } else {
                p = ssh_keep_known_algos(SSH_HOSTKEYS, v);
            }
            if (p == NULL) {
                ssh_set_error(sshbind, SSH_REQUEST_DENIED,
                    "Setting method: no known public key algorithm (%s)",
                     v);
                return -1;
            }

            SAFE_FREE(sshbind->pubkey_accepted_key_types);
            sshbind->pubkey_accepted_key_types = p;
        }
        break;
    case SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS:
        v = value;
        if (v == NULL || v[0] == '\0') {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            rc = ssh_bind_set_algo(sshbind, SSH_HOSTKEYS, v);
            if (rc < 0) {
                return -1;
            }
        }
        break;
    case SSH_BIND_OPTIONS_PROCESS_CONFIG:
        if (value == NULL) {
            ssh_set_error_invalid(sshbind);
            return -1;
        } else {
            bool *x = (bool *)value;
            sshbind->config_processed = !(*x);
        }
        break;
    default:
      ssh_set_error(sshbind, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
      return -1;
    break;
  }

  return 0;
}

static char *ssh_bind_options_expand_escape(ssh_bind sshbind, const char *s)
{
    char buf[MAX_BUF_SIZE];
    char *r, *x = NULL;
    const char *p;
    size_t i, l;

    r = ssh_path_expand_tilde(s);
    if (r == NULL) {
        ssh_set_error_oom(sshbind);
        return NULL;
    }

    if (strlen(r) > MAX_BUF_SIZE) {
        ssh_set_error(sshbind, SSH_FATAL, "string to expand too long");
        free(r);
        return NULL;
    }

    p = r;
    buf[0] = '\0';

    for (i = 0; *p != '\0'; p++) {
        if (*p != '%') {
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
            case 'd':
                x = strdup(sshbind->config_dir);
                break;
            default:
                ssh_set_error(sshbind, SSH_FATAL,
                        "Wrong escape sequence detected");
                free(r);
                return NULL;
        }

        if (x == NULL) {
            ssh_set_error_oom(sshbind);
            free(r);
            return NULL;
        }

        i += strlen(x);
        if (i >= MAX_BUF_SIZE) {
            ssh_set_error(sshbind, SSH_FATAL,
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
}

/**
 * @brief Parse a ssh bind options configuration file.
 *
 * This parses the options file and set them to the ssh_bind handle provided. If
 * an option was previously set, it is overridden. If the global configuration
 * hasn't been processed yet, it is processed prior to the provided file.
 *
 * @param  sshbind      SSH bind handle
 *
 * @param  filename     The options file to use; if NULL only the global
 *                      configuration is parsed and applied (if it haven't been
 *                      processed before).
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_bind_options_parse_config(ssh_bind sshbind, const char *filename)
{
    int rc = 0;
    char *expanded_filename;

    if (sshbind == NULL) {
        return -1;
    }

    /* If the global default configuration hasn't been processed yet, process it
     * before the provided configuration. */
    if (!(sshbind->config_processed)) {
        rc = ssh_bind_config_parse_file(sshbind, GLOBAL_BIND_CONFIG);
        if (rc != 0) {
            return rc;
        }
        sshbind->config_processed = true;
    }

    if (filename != NULL) {
        expanded_filename = ssh_bind_options_expand_escape(sshbind, filename);
        if (expanded_filename == NULL) {
            return -1;
        }

        /* Apply the user provided configuration */
        rc = ssh_bind_config_parse_file(sshbind, expanded_filename);
        free(expanded_filename);
    }

    return rc;
}

#endif

/** @} */
