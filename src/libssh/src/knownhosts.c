/*
 * known_hosts: Host and public key verification.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2017 by Andreas Schneider <asn@cryptomilk.org>
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
#include <stdlib.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "libssh/priv.h"
#include "libssh/dh.h"
#include "libssh/session.h"
#include "libssh/options.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/dh.h"
#include "libssh/knownhosts.h"
#include "libssh/token.h"

/**
 * @addtogroup libssh_session
 *
 * @{
 */

static int hash_hostname(const char *name,
                         unsigned char *salt,
                         unsigned int salt_size,
                         unsigned char **hash,
                         unsigned int *hash_size)
{
    HMACCTX mac_ctx;

    mac_ctx = hmac_init(salt, salt_size, SSH_HMAC_SHA1);
    if (mac_ctx == NULL) {
        return SSH_ERROR;
    }

    hmac_update(mac_ctx, name, strlen(name));
    hmac_final(mac_ctx, *hash, hash_size);

    return SSH_OK;
}

static int match_hashed_hostname(const char *host, const char *hashed_host)
{
    char *hashed;
    char *b64_hash;
    ssh_buffer salt = NULL;
    ssh_buffer hash = NULL;
    unsigned char hashed_buf[256] = {0};
    unsigned char *hashed_buf_ptr = hashed_buf;
    unsigned int hashed_buf_size = sizeof(hashed_buf);
    int cmp;
    int rc;
    int match = 0;

    cmp = strncmp(hashed_host, "|1|", 3);
    if (cmp != 0) {
        return 0;
    }

    hashed = strdup(hashed_host + 3);
    if (hashed == NULL) {
        return 0;
    }

    b64_hash = strchr(hashed, '|');
    if (b64_hash == NULL) {
        goto error;
    }
    *b64_hash = '\0';
    b64_hash++;

    salt = base64_to_bin(hashed);
    if (salt == NULL) {
        goto error;
    }

    hash = base64_to_bin(b64_hash);
    if (hash == NULL) {
        goto error;
    }

    rc = hash_hostname(host,
                       ssh_buffer_get(salt),
                       ssh_buffer_get_len(salt),
                       &hashed_buf_ptr,
                       &hashed_buf_size);
    if (rc != SSH_OK) {
        goto error;
    }

    if (hashed_buf_size != ssh_buffer_get_len(hash)) {
        goto error;
    }

    cmp = memcmp(hashed_buf, ssh_buffer_get(hash), hashed_buf_size);
    if (cmp == 0) {
        match = 1;
    }

error:
    free(hashed);
    SSH_BUFFER_FREE(salt);
    SSH_BUFFER_FREE(hash);

    return match;
}

/**
 * @brief Free an allocated ssh_knownhosts_entry.
 *
 * Use SSH_KNOWNHOSTS_ENTRY_FREE() to set the pointer to NULL.
 *
 * @param[in]  entry     The entry to free.
 */
void ssh_knownhosts_entry_free(struct ssh_knownhosts_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    SAFE_FREE(entry->hostname);
    SAFE_FREE(entry->unparsed);
    ssh_key_free(entry->publickey);
    SAFE_FREE(entry->comment);
    SAFE_FREE(entry);
}

static int known_hosts_read_line(FILE *fp,
                                 char *buf,
                                 size_t buf_size,
                                 size_t *buf_len,
                                 size_t *lineno)
{
    while (fgets(buf, buf_size, fp) != NULL) {
        size_t len;
        if (buf[0] == '\0') {
            continue;
        }

        *lineno += 1;
        len = strlen(buf);
        if (buf_len != NULL) {
            *buf_len = len;
        }
        if (buf[len - 1] == '\n' || feof(fp)) {
            return 0;
        } else {
            errno = E2BIG;
            return -1;
        }
    }

    return -1;
}

static int
ssh_known_hosts_entries_compare(struct ssh_knownhosts_entry *k1,
                                struct ssh_knownhosts_entry *k2)
{
    int cmp;

    if (k1 == NULL || k2 == NULL) {
        return 1;
    }

    cmp = strcmp(k1->hostname, k2->hostname);
    if (cmp != 0) {
        return cmp;
    }

    cmp = ssh_key_cmp(k1->publickey, k2->publickey, SSH_KEY_CMP_PUBLIC);
    if (cmp != 0) {
        return cmp;
    }

    return 0;
}

/* This method reads the known_hosts file referenced by the path
 * in  filename  argument, and entries matching the  match  argument
 * will be added to the list in  entries  argument.
 * If the  entries  list is NULL, it will allocate a new list. Caller
 * is responsible to free it even if an error occurs.
 */
static int ssh_known_hosts_read_entries(const char *match,
                                        const char *filename,
                                        struct ssh_list **entries)
{
    char line[8192];
    size_t lineno = 0;
    size_t len = 0;
    FILE *fp;
    int rc;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Failed to open the known_hosts file '%s': %s",
                filename, strerror(errno));
        /* The missing file is not an error here */
        return SSH_OK;
    }

    if (*entries == NULL) {
        *entries = ssh_list_new();
        if (*entries == NULL) {
            fclose(fp);
            return SSH_ERROR;
        }
    }

    for (rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno);
         rc == 0;
         rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno)) {
        struct ssh_knownhosts_entry *entry = NULL;
        struct ssh_iterator *it = NULL;
        char *p = NULL;

        if (line[len] != '\n') {
            len = strcspn(line, "\n");
        }
        line[len] = '\0';

        /* Skip leading spaces */
        for (p = line; isspace((int)p[0]); p++);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#') {
            continue;
        }

        /* Skip lines starting with markers (@cert-authority, @revoked):
         * we do not completely support them anyway */
        if (p[0] == '@') {
            continue;
        }

        rc = ssh_known_hosts_parse_line(match,
                                        line,
                                        &entry);
        if (rc == SSH_AGAIN) {
            continue;
        } else if (rc != SSH_OK) {
            goto error;
        }

        /* Check for duplicates */
        for (it = ssh_list_get_iterator(*entries);
             it != NULL;
             it = it->next) {
            struct ssh_knownhosts_entry *entry2;
            int cmp;
            entry2 = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
            cmp = ssh_known_hosts_entries_compare(entry, entry2);
            if (cmp == 0) {
                ssh_knownhosts_entry_free(entry);
                entry = NULL;
                break;
            }
        }
        if (entry != NULL) {
            ssh_list_append(*entries, entry);
        }
    }

    fclose(fp);
    return SSH_OK;
error:
    fclose(fp);
    return SSH_ERROR;
}

static char *ssh_session_get_host_port(ssh_session session)
{
    char *host_port;
    char *host;

    if (session->opts.host == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Can't verify server in known hosts if the host we "
                      "should connect to has not been set");

        return NULL;
    }

    host = ssh_lowercase(session->opts.host);
    if (host == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (session->opts.port == 0 || session->opts.port == 22) {
        host_port = host;
    } else {
        host_port = ssh_hostport(host, session->opts.port);
        SAFE_FREE(host);
        if (host_port == NULL) {
            ssh_set_error_oom(session);
            return NULL;
        }
    }

    return host_port;
}

/**
 * @internal
 * @brief Check which host keys should be preferred for the session.
 *
 * This checks the known_hosts file to find out which algorithms should be
 * preferred for the connection we are going to establish.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A list of supported key types, NULL on error.
 */
struct ssh_list *ssh_known_hosts_get_algorithms(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    struct ssh_list *list = NULL;
    int list_error = 0;
    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return NULL;
    }

    list = ssh_list_new();
    if (list == NULL) {
        SAFE_FREE(host_port);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        ssh_list_free(entry_list);
        ssh_list_free(list);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        ssh_list_free(entry_list);
        ssh_list_free(list);
        return NULL;
    }

    if (entry_list == NULL) {
        ssh_list_free(list);
        return NULL;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_list_free(list);
        ssh_list_free(entry_list);
        return NULL;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_iterator *it2 = NULL;
        struct ssh_knownhosts_entry *entry = NULL;
        const char *algo = NULL;
        bool present = false;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        algo = entry->publickey->type_c;

        /* Check for duplicates */
        for (it2 = ssh_list_get_iterator(list);
             it2 != NULL;
             it2 = it2->next) {
            char *alg2 = ssh_iterator_value(char *, it2);
            int cmp = strcmp(alg2, algo);
            if (cmp == 0) {
                present = true;
                break;
            }
        }

        /* Add to the new list only if it is unique */
        if (!present) {
            rc = ssh_list_append(list, algo);
            if (rc != SSH_OK) {
               list_error = 1;
            }
        }

        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);
    if (list_error) {
        goto error;
    }

    return list;
error:
    ssh_list_free(list);
    return NULL;
}

/**
 * @internal
 *
 * @brief   Returns a static string containing a list of the signature types the
 * given key type can generate.
 *
 * @returns A static cstring containing the signature types the key is able to
 * generate separated by commas; NULL in case of error
 */
static const char *ssh_known_host_sigs_from_hostkey_type(enum ssh_keytypes_e type)
{
    switch (type) {
    case SSH_KEYTYPE_RSA:
        return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    case SSH_KEYTYPE_ED25519:
        return "ssh-ed25519";
#ifdef HAVE_DSA
    case SSH_KEYTYPE_DSS:
        return "ssh-dss";
#endif
#ifdef HAVE_ECDH
    case SSH_KEYTYPE_ECDSA_P256:
        return "ecdsa-sha2-nistp256";
    case SSH_KEYTYPE_ECDSA_P384:
        return "ecdsa-sha2-nistp384";
    case SSH_KEYTYPE_ECDSA_P521:
        return "ecdsa-sha2-nistp521";
#endif
    case SSH_KEYTYPE_UNKNOWN:
    default:
        SSH_LOG(SSH_LOG_WARN, "The given type %d is not a base private key type "
                "or is unsupported", type);
        return NULL;
    }
}

/**
 * @internal
 * @brief Get the host keys algorithms identifiers from the known_hosts files
 *
 * This expands the signatures types that can be generated from the keys types
 * present in the known_hosts files
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A newly allocated cstring containing a list of signature algorithms
 * that can be generated by the host using the keys listed in the known_hosts
 * files, NULL on error.
 */
char *ssh_known_hosts_get_algorithms_names(ssh_session session)
{
    char methods_buffer[256 + 1] = {0};
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    bool needcomma = false;
    char *names;

    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        SAFE_FREE(host_port);
        ssh_list_free(entry_list);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        ssh_list_free(entry_list);
        return NULL;
    }

    if (entry_list == NULL) {
        return NULL;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_list_free(entry_list);
        return NULL;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list))
    {
        struct ssh_knownhosts_entry *entry = NULL;
        const char *algo = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        algo = ssh_known_host_sigs_from_hostkey_type(entry->publickey->type);
        if (algo == NULL) {
            continue;
        }

        if (needcomma) {
            strncat(methods_buffer,
                    ",",
                    sizeof(methods_buffer) - strlen(methods_buffer) - 1);
        }

        strncat(methods_buffer,
                algo,
                sizeof(methods_buffer) - strlen(methods_buffer) - 1);
        needcomma = true;

        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }

    ssh_list_free(entry_list);

    names = ssh_remove_duplicates(methods_buffer);

    return names;
}

/**
 * @brief Parse a line from a known_hosts entry into a structure
 *
 * This parses an known_hosts entry into a structure with the key in a libssh
 * consumeable form. You can use the PKI key function to further work with it.
 *
 * @param[in]  hostname     The hostname to match the line to
 *
 * @param[in]  line         The line to compare and parse if we have a hostname
 *                          match.
 *
 * @param[in]  entry        A pointer to store the the allocated known_hosts
 *                          entry structure. The user needs to free the memory
 *                          using SSH_KNOWNHOSTS_ENTRY_FREE().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_known_hosts_parse_line(const char *hostname,
                               const char *line,
                               struct ssh_knownhosts_entry **entry)
{
    struct ssh_knownhosts_entry *e = NULL;
    char *known_host = NULL;
    char *p;
    enum ssh_keytypes_e key_type;
    int match = 0;
    int rc = SSH_OK;

    known_host = strdup(line);
    if (known_host == NULL) {
        return SSH_ERROR;
    }

    /* match pattern for hostname or hashed hostname */
    p = strtok(known_host, " ");
    if (p == NULL ) {
        free(known_host);
        return SSH_ERROR;
    }

    e = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (e == NULL) {
        free(known_host);
        return SSH_ERROR;
    }

    if (hostname != NULL) {
        char *host_port = NULL;
        char *q = NULL;

        /* Hashed */
        if (p[0] == '|') {
            match = match_hashed_hostname(hostname, p);
        }

        for (q = strtok(p, ",");
             q != NULL;
             q = strtok(NULL, ",")) {
            int cmp;

            if (q[0] == '[' && hostname[0] != '[') {
                /* Corner case: We have standard port so we do not have
                 * hostname in square braces. But the patern is enclosed
                 * in braces with, possibly standard or wildcard, port.
                 * We need to test against [host]:port pair here.
                 */
                if (host_port == NULL) {
                    host_port = ssh_hostport(hostname, 22);
                    if (host_port == NULL) {
                        rc = SSH_ERROR;
                        goto out;
                    }
                }

                cmp = match_hostname(host_port, q, strlen(q));
            } else {
                cmp = match_hostname(hostname, q, strlen(q));
            }
            if (cmp == 1) {
                match = 1;
                break;
            }
        }
        free(host_port);

        if (match == 0) {
            rc = SSH_AGAIN;
            goto out;
        }

        e->hostname = strdup(hostname);
        if (e->hostname == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    /* Restart parsing */
    SAFE_FREE(known_host);
    known_host = strdup(line);
    if (known_host == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    p = strtok(known_host, " ");
    if (p == NULL ) {
        rc = SSH_ERROR;
        goto out;
    }

    e->unparsed = strdup(p);
    if (e->unparsed == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    /* pubkey type */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    key_type = ssh_key_type_from_name(p);
    if (key_type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "key type '%s' unknown!", p);
        rc = SSH_ERROR;
        goto out;
    }

    /* public key */
    p = strtok(NULL, " ");
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_pki_import_pubkey_base64(p,
                                      key_type,
                                      &e->publickey);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to parse %s key for entry: %s!",
                ssh_key_type_to_char(key_type),
                e->unparsed);
        goto out;
    }

    /* comment */
    p = strtok(NULL, " ");
    if (p != NULL) {
        p = strstr(line, p);
        if (p != NULL) {
            e->comment = strdup(p);
            if (e->comment == NULL) {
                rc = SSH_ERROR;
                goto out;
            }
        }
    }

    *entry = e;
    SAFE_FREE(known_host);

    return SSH_OK;
out:
    SAFE_FREE(known_host);
    ssh_knownhosts_entry_free(e);
    return rc;
}

/**
 * @brief Check if the set hostname and port matches an entry in known_hosts.
 *
 * This check if the set hostname and port has an entry in the known_hosts file.
 * You need to set at least the hostname using ssh_options_set().
 *
 * @param[in]  session  The session with with the values set to check.
 *
 * @return A ssh_known_hosts_e return value.
 */
enum ssh_known_hosts_e ssh_session_has_known_hosts_entry(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    bool global_known_hosts_found = false;
    bool known_hosts_found = false;
    int rc;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Cannot find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    if (session->opts.knownhosts == NULL &&
        session->opts.global_knownhosts == NULL) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "No path set for a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    if (session->opts.knownhosts != NULL) {
        known_hosts_found = ssh_file_readaccess_ok(session->opts.knownhosts);
        if (!known_hosts_found) {
            SSH_LOG(SSH_LOG_WARN, "Cannot access file %s",
                    session->opts.knownhosts);
        }
    }

    if (session->opts.global_knownhosts != NULL) {
        global_known_hosts_found =
                ssh_file_readaccess_ok(session->opts.global_knownhosts);
        if (!global_known_hosts_found) {
            SSH_LOG(SSH_LOG_WARN, "Cannot access file %s",
                    session->opts.global_knownhosts);
        }
    }

    if ((!known_hosts_found) && (!global_known_hosts_found)) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Cannot find a known_hosts file");

        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    if (known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_list_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    if (global_known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.global_knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_list_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    SAFE_FREE(host_port);

    if (ssh_list_count(entry_list) == 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return SSH_KNOWN_HOSTS_OK;
}

/**
 * @brief Export the current session information to a known_hosts string.
 *
 * This exports the current information of a session which is connected so a
 * ssh server into an entry line which can be added to a known_hosts file.
 *
 * @param[in]  session  The session with information to export.
 *
 * @param[in]  pentry_string A pointer to a string to store the alloocated
 *                           line of the entry. The user must free it using
 *                           ssh_string_free_char().
 *
 * @return SSH_OK on succcess, SSH_ERROR otherwise.
 */
int ssh_session_export_known_hosts_entry(ssh_session session,
                                         char **pentry_string)
{
    ssh_key server_pubkey = NULL;
    char *host = NULL;
    char entry_buf[4096] = {0};
    char *b64_key = NULL;
    int rc;

    if (pentry_string == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Can't create known_hosts entry - hostname unknown");
        return SSH_ERROR;
    }

    host = ssh_session_get_host_port(session);
    if (host == NULL) {
        return SSH_ERROR;
    }

    if (session->current_crypto == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "No current crypto context, please connect first");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL){
        ssh_set_error(session, SSH_FATAL, "No public key present");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    rc = ssh_pki_export_pubkey_base64(server_pubkey, &b64_key);
    if (rc < 0) {
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    snprintf(entry_buf, sizeof(entry_buf),
                "%s %s %s\n",
                host,
                server_pubkey->type_c,
                b64_key);

    SAFE_FREE(host);
    SAFE_FREE(b64_key);

    *pentry_string = strdup(entry_buf);
    if (*pentry_string == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Add the current connected server to the user known_hosts file.
 *
 * This adds the currently connected server to the known_hosts file by
 * appending a new line at the end. The global known_hosts file is considered
 * read-only so it is not touched by this function.
 *
 * @param[in]  session  The session to use to write the entry.
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_update_known_hosts(ssh_session session)
{
    FILE *fp = NULL;
    char *entry = NULL;
    char *dir = NULL;
    size_t nwritten;
    size_t len;
    int rc;

    if (session->opts.knownhosts == NULL) {
        rc = ssh_options_apply(session);
        if (rc != SSH_OK) {
            ssh_set_error(session, SSH_FATAL, "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    errno = 0;
    fp = fopen(session->opts.knownhosts, "a");
    if (fp == NULL) {
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
            fp = fopen(session->opts.knownhosts, "a");
            if (fp == NULL) {
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

    rc = ssh_session_export_known_hosts_entry(session, &entry);
    if (rc != SSH_OK) {
        fclose(fp);
        return rc;
    }

    len = strlen(entry);
    nwritten = fwrite(entry, sizeof(char), len, fp);
    SAFE_FREE(entry);
    if (nwritten != len || ferror(fp)) {
        ssh_set_error(session, SSH_FATAL,
                      "Couldn't append to known_hosts file %s: %s",
                      session->opts.knownhosts, strerror(errno));
        fclose(fp);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

static enum ssh_known_hosts_e
ssh_known_hosts_check_server_key(const char *hosts_entry,
                                 const char *filename,
                                 ssh_key server_key,
                                 struct ssh_knownhosts_entry **pentry)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;
    int rc;

    rc = ssh_known_hosts_read_entries(hosts_entry,
                                      filename,
                                      &entry_list);
    if (rc != 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    it = ssh_list_get_iterator(entry_list);
    if (it == NULL) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    for (;it != NULL; it = it->next) {
        struct ssh_knownhosts_entry *entry = NULL;
        int cmp;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);

        cmp = ssh_key_cmp(server_key, entry->publickey, SSH_KEY_CMP_PUBLIC);
        if (cmp == 0) {
            found = SSH_KNOWN_HOSTS_OK;
            if (pentry != NULL) {
                *pentry = entry;
                ssh_list_remove(entry_list, it);
            }
            break;
        }

        if (ssh_key_type(server_key) == ssh_key_type(entry->publickey)) {
            found = SSH_KNOWN_HOSTS_CHANGED;
            continue;
        }

        if (found != SSH_KNOWN_HOSTS_CHANGED) {
            found = SSH_KNOWN_HOSTS_OTHER;
        }
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return found;
}

/**
 * @brief Get the known_hosts entry for the current connected session.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an eror checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry(ssh_session session,
                                  struct ssh_knownhosts_entry **pentry)
{
    enum ssh_known_hosts_e old_rv, rv = SSH_KNOWN_HOSTS_UNKNOWN;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.knownhosts,
                                                pentry);
    if (rv == SSH_KNOWN_HOSTS_OK) {
        /* We already found a match in the first file: return */
        return rv;
    }

    old_rv = rv;
    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.global_knownhosts,
                                                pentry);

    /* If we did not find any match at all:  we report the previous result */
    if (rv == SSH_KNOWN_HOSTS_UNKNOWN) {
        if (session->opts.StrictHostKeyChecking == 0) {
            return SSH_KNOWN_HOSTS_OK;
        }
        return old_rv;
    }

    /* We found some match: return it */
    return rv;

}

/**
 * @brief Get the known_hosts entry for the current connected session
 *        from the given known_hosts file.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  filename The filename to parse.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an eror checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry_file(ssh_session session,
                                       const char *filename,
                                       struct ssh_knownhosts_entry **pentry)
{
    ssh_key server_pubkey = NULL;
    char *host_port = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_session_is_known_host called without a "
                      "server_key!");

        return SSH_KNOWN_HOSTS_ERROR;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    found = ssh_known_hosts_check_server_key(host_port,
                                             filename,
                                             server_pubkey,
                                             pentry);
    SAFE_FREE(host_port);

    return found;
}

/**
 * @brief Check if the servers public key for the connected session is known.
 *
 * This checks if we already know the public key of the server we want to
 * connect to. This allows to detect if there is a MITM attach going on
 * of if there have been changes on the server we don't know about.
 *
 * @param[in]  session  The SSH to validate.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 */
enum ssh_known_hosts_e ssh_session_is_known_server(ssh_session session)
{
    return ssh_session_get_known_hosts_entry(session, NULL);
}

/** @} */
