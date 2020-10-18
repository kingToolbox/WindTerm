/*
 * kex.c - key exchange
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/dh.h"
#ifdef WITH_GEX
#include "libssh/dh-gex.h"
#endif /* WITH_GEX */
#include "libssh/kex.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"
#include "libssh/string.h"
#include "libssh/curve25519.h"
#include "libssh/knownhosts.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"
#include "libssh/token.h"

#ifdef WITH_BLOWFISH_CIPHER
# if defined(HAVE_OPENSSL_BLOWFISH_H) || defined(HAVE_LIBGCRYPT) || defined(HAVE_LIBMBEDCRYPTO)
#  define BLOWFISH "blowfish-cbc,"
# else
#  define BLOWFISH ""
# endif
#else
# define BLOWFISH ""
#endif

#ifdef HAVE_LIBGCRYPT
# define AES "aes256-gcm@openssh.com,aes128-gcm@openssh.com," \
             "aes256-ctr,aes192-ctr,aes128-ctr," \
             "aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"

#elif defined(HAVE_LIBMBEDCRYPTO)
# ifdef MBEDTLS_GCM_C
#  define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
# else
#  define GCM ""
# endif /* MBEDTLS_GCM_C */
# define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr," \
             "aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"

#elif defined(HAVE_LIBCRYPTO)
# ifdef HAVE_OPENSSL_AES_H
#  ifdef HAVE_OPENSSL_EVP_AES_GCM
#   define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
#  else
#   define GCM ""
#  endif /* HAVE_OPENSSL_EVP_AES_GCM */
#  ifdef BROKEN_AES_CTR
#   define AES GCM "aes256-cbc,aes192-cbc,aes128-cbc,"
#  else /* BROKEN_AES_CTR */
#   define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
#  endif /* BROKEN_AES_CTR */
# else /* HAVE_OPENSSL_AES_H */
#  define AES ""
# endif /* HAVE_OPENSSL_AES_H */

# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc"
#endif /* HAVE_LIBCRYPTO */

#ifdef WITH_ZLIB
#define ZLIB "none,zlib,zlib@openssh.com"
#else
#define ZLIB "none"
#endif

#ifdef HAVE_CURVE25519
#define CURVE25519 "curve25519-sha256,curve25519-sha256@libssh.org,"
#else
#define CURVE25519 ""
#endif

#ifdef HAVE_ECDH
#define ECDH "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
#define EC_HOSTKEYS "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,"
#define EC_PUBLIC_KEY_ALGORITHMS "ecdsa-sha2-nistp521-cert-v01@openssh.com," \
                                 "ecdsa-sha2-nistp384-cert-v01@openssh.com," \
                                 "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
#else
#define EC_HOSTKEYS ""
#define EC_PUBLIC_KEY_ALGORITHMS ""
#define ECDH ""
#endif

#ifdef HAVE_DSA
#define DSA_HOSTKEYS ",ssh-dss"
#define DSA_PUBLIC_KEY_ALGORITHMS ",ssh-dss-cert-v01@openssh.com"
#else
#define DSA_HOSTKEYS ""
#define DSA_PUBLIC_KEY_ALGORITHMS ""
#endif

#define HOSTKEYS "ssh-ed25519," \
                 EC_HOSTKEYS \
                 "rsa-sha2-512," \
                 "rsa-sha2-256," \
                 "ssh-rsa" \
                 DSA_HOSTKEYS
#define PUBLIC_KEY_ALGORITHMS "ssh-ed25519-cert-v01@openssh.com," \
                              EC_PUBLIC_KEY_ALGORITHMS \
                              "rsa-sha2-512-cert-v01@openssh.com," \
                              "rsa-sha2-256-cert-v01@openssh.com," \
                              "ssh-rsa-cert-v01@openssh.com" \
                              DSA_PUBLIC_KEY_ALGORITHMS "," \
                              HOSTKEYS

#ifdef WITH_GEX
#define GEX_SHA256 "diffie-hellman-group-exchange-sha256,"
#define GEX_SHA1 "diffie-hellman-group-exchange-sha1,"
#else
#define GEX_SHA256
#define GEX_SHA1
#endif /* WITH_GEX */

#define CHACHA20 "chacha20-poly1305@openssh.com,"

#define KEY_EXCHANGE \
    CURVE25519 \
    ECDH \
    "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512," \
    GEX_SHA256 \
    "diffie-hellman-group14-sha256," \
    "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define KEY_EXCHANGE_SUPPORTED \
    GEX_SHA1 \
    KEY_EXCHANGE

/* RFC 8308 */
#define KEX_EXTENSION_CLIENT "ext-info-c"

/* Allowed algorithms in FIPS mode */
#define FIPS_ALLOWED_CIPHERS "aes256-gcm@openssh.com,"\
                             "aes256-ctr,"\
                             "aes256-cbc,"\
                             "aes128-gcm@openssh.com,"\
                             "aes128-ctr,"\
                             "aes128-cbc"

#define FIPS_ALLOWED_HOSTKEYS EC_HOSTKEYS \
                              "rsa-sha2-512," \
                              "rsa-sha2-256"

#define FIPS_ALLOWED_PUBLIC_KEY_ALGORITHMS EC_PUBLIC_KEY_ALGORITHMS \
                                           "rsa-sha2-512-cert-v01@openssh.com," \
                                           "rsa-sha2-256-cert-v01@openssh.com," \
                                           FIPS_ALLOWED_HOSTKEYS

#define FIPS_ALLOWED_KEX "ecdh-sha2-nistp256,"\
                         "ecdh-sha2-nistp384,"\
                         "ecdh-sha2-nistp521,"\
                         "diffie-hellman-group-exchange-sha256,"\
                         "diffie-hellman-group14-sha256,"\
                         "diffie-hellman-group16-sha512,"\
                         "diffie-hellman-group18-sha512"

#define FIPS_ALLOWED_MACS "hmac-sha2-256-etm@openssh.com,"\
                          "hmac-sha1-etm@openssh.com,"\
                          "hmac-sha2-512-etm@openssh.com,"\
                          "hmac-sha2-256,"\
                          "hmac-sha1,"\
                          "hmac-sha2-512"

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *fips_methods[] = {
    FIPS_ALLOWED_KEX,
    FIPS_ALLOWED_PUBLIC_KEY_ALGORITHMS,
    FIPS_ALLOWED_CIPHERS,
    FIPS_ALLOWED_CIPHERS,
    FIPS_ALLOWED_MACS,
    FIPS_ALLOWED_MACS,
    ZLIB,
    ZLIB,
    "",
    "",
    NULL
};

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *default_methods[] = {
  KEY_EXCHANGE,
  PUBLIC_KEY_ALGORITHMS,
  AES BLOWFISH DES,
  AES BLOWFISH DES,
  "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "none",
  "none",
  "",
  "",
  NULL
};

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *supported_methods[] = {
  KEY_EXCHANGE_SUPPORTED,
  PUBLIC_KEY_ALGORITHMS,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  ZLIB,
  ZLIB,
  "",
  "",
  NULL
};

/* descriptions of the key exchange packet */
static const char *ssh_kex_descriptions[] = {
  "kex algos",
  "server host key algo",
  "encryption client->server",
  "encryption server->client",
  "mac algo client->server",
  "mac algo server->client",
  "compression algo client->server",
  "compression algo server->client",
  "languages client->server",
  "languages server->client",
  NULL
};

const char *ssh_kex_get_default_methods(uint32_t algo)
{
    if (algo >= SSH_KEX_METHODS) {
        return NULL;
    }

    return default_methods[algo];
}

const char *ssh_kex_get_supported_method(uint32_t algo)
{
    if (algo >= SSH_KEX_METHODS) {
        return NULL;
    }

    return supported_methods[algo];
}

const char *ssh_kex_get_description(uint32_t algo) {
  if (algo >= SSH_KEX_METHODS) {
    return NULL;
  }

  return ssh_kex_descriptions[algo];
}

const char *ssh_kex_get_fips_methods(uint32_t algo) {
  if (algo >= SSH_KEX_METHODS) {
    return NULL;
  }

  return fips_methods[algo];
}

/**
 * @internal
 * @brief returns whether the first client key exchange algorithm or
 *        hostkey type matches its server counterpart
 * @returns whether the first client key exchange algorithm or hostkey type
 *          matches its server counterpart
 */
static int cmp_first_kex_algo(const char *client_str,
                              const char *server_str) {
    size_t client_kex_len;
    size_t server_kex_len;

    char *colon;

    int is_wrong = 1;

    colon = strchr(client_str, ',');
    if (colon == NULL) {
        client_kex_len = strlen(client_str);
    } else {
        client_kex_len = colon - client_str;
    }

    colon = strchr(server_str, ',');
    if (colon == NULL) {
        server_kex_len = strlen(server_str);
    } else {
        server_kex_len = colon - server_str;
    }

    if (client_kex_len != server_kex_len) {
        return is_wrong;
    }

    is_wrong = (strncmp(client_str, server_str, client_kex_len) != 0);

    return is_wrong;
}

SSH_PACKET_CALLBACK(ssh_packet_kexinit)
{
    int i, ok;
    int server_kex = session->server;
    ssh_string str = NULL;
    char *strings[SSH_KEX_METHODS] = {0};
    char *rsa_sig_ext = NULL;
    int rc = SSH_ERROR;
    size_t len;

    uint8_t first_kex_packet_follows = 0;
    uint32_t kexinit_reserved = 0;

    (void)type;
    (void)user;

    if (session->session_state == SSH_SESSION_STATE_AUTHENTICATED) {
        SSH_LOG(SSH_LOG_INFO, "Initiating key re-exchange");
    } else if (session->session_state != SSH_SESSION_STATE_INITIAL_KEX) {
        ssh_set_error(session,SSH_FATAL,"SSH_KEXINIT received in wrong state");
        goto error;
    }

    if (server_kex) {
        len = ssh_buffer_get_data(packet,session->next_crypto->client_kex.cookie, 16);
        if (len != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        ok = ssh_hashbufin_add_cookie(session, session->next_crypto->client_kex.cookie);
        if (ok < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    } else {
        len = ssh_buffer_get_data(packet,session->next_crypto->server_kex.cookie, 16);
        if (len != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        ok = ssh_hashbufin_add_cookie(session, session->next_crypto->server_kex.cookie);
        if (ok < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    }

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        str = ssh_buffer_get_ssh_string(packet);
        if (str == NULL) {
          goto error;
        }

        rc = ssh_buffer_add_ssh_string(session->in_hashbuf, str);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "Error adding string in hash buffer");
            goto error;
        }

        strings[i] = ssh_string_to_char(str);
        if (strings[i] == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        SSH_STRING_FREE(str);
        str = NULL;
    }

    /* copy the server kex info into an array of strings */
    if (server_kex) {
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->client_kex.methods[i] = strings[i];
        }
    } else { /* client */
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->server_kex.methods[i] = strings[i];
        }
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     *
     * Notably if clients set 'first_kex_packet_follows', it is expected
     * that its value is included when computing the session ID (see
     * 'make_sessionid').
     */
    if (server_kex) {
        rc = ssh_buffer_get_u8(packet, &first_kex_packet_follows);
        if (rc != 1) {
            goto error;
        }

        rc = ssh_buffer_add_u8(session->in_hashbuf, first_kex_packet_follows);
        if (rc < 0) {
            goto error;
        }

        rc = ssh_buffer_add_u32(session->in_hashbuf, kexinit_reserved);
        if (rc < 0) {
            goto error;
        }

        /*
         * If client sent a ext-info-c message in the kex list, it supports
         * RFC 8308 extension negotiation.
         */
        ok = ssh_match_group(session->next_crypto->client_kex.methods[SSH_KEX],
                             KEX_EXTENSION_CLIENT);
        if (ok) {
            const char *hostkeys = NULL;

            /* The client supports extension negotiation */
            session->extensions |= SSH_EXT_NEGOTIATION;
            /*
             * RFC 8332 Section 3.1: Use for Server Authentication
             * Check what algorithms were provided in the SSH_HOSTKEYS list
             * by the client and enable the respective extensions to provide
             * correct signature in the next packet if RSA is negotiated
             */
            hostkeys = session->next_crypto->client_kex.methods[SSH_HOSTKEYS];
            ok = ssh_match_group(hostkeys, "rsa-sha2-512");
            if (ok) {
                /* Check if rsa-sha2-512 is allowed by config */
                if (session->opts.wanted_methods[SSH_HOSTKEYS] != NULL) {
                    char *is_allowed =
                        ssh_find_matching(session->opts.wanted_methods[SSH_HOSTKEYS],
                                          "rsa-sha2-512");
                    if (is_allowed != NULL) {
                        session->extensions |= SSH_EXT_SIG_RSA_SHA512;
                    }
                    SAFE_FREE(is_allowed);
                }
            }
            ok = ssh_match_group(hostkeys, "rsa-sha2-256");
            if (ok) {
                /* Check if rsa-sha2-256 is allowed by config */
                if (session->opts.wanted_methods[SSH_HOSTKEYS] != NULL) {
                    char *is_allowed =
                        ssh_find_matching(session->opts.wanted_methods[SSH_HOSTKEYS],
                                          "rsa-sha2-256");
                    if (is_allowed != NULL) {
                        session->extensions |= SSH_EXT_SIG_RSA_SHA256;
                    }
                    SAFE_FREE(is_allowed);
                }
            }

            /*
             * Ensure that the client preference is honored for the case
             * both signature types are enabled.
             */
            if ((session->extensions & SSH_EXT_SIG_RSA_SHA256) &&
                (session->extensions & SSH_EXT_SIG_RSA_SHA512)) {
                session->extensions &= ~(SSH_EXT_SIG_RSA_SHA256 | SSH_EXT_SIG_RSA_SHA512);
                rsa_sig_ext = ssh_find_matching("rsa-sha2-512,rsa-sha2-256",
                                                session->next_crypto->client_kex.methods[SSH_HOSTKEYS]);
                if (rsa_sig_ext == NULL) {
                    goto error; /* should never happen */
                } else if (strcmp(rsa_sig_ext, "rsa-sha2-512") == 0) {
                    session->extensions |= SSH_EXT_SIG_RSA_SHA512;
                } else if (strcmp(rsa_sig_ext, "rsa-sha2-256") == 0) {
                    session->extensions |= SSH_EXT_SIG_RSA_SHA256;
                } else {
                    SAFE_FREE(rsa_sig_ext);
                    goto error; /* should never happen */
                }
                SAFE_FREE(rsa_sig_ext);
            }

            SSH_LOG(SSH_LOG_DEBUG, "The client supports extension "
                    "negotiation. Enabled signature algorithms: %s%s",
                    session->extensions & SSH_EXT_SIG_RSA_SHA256 ? "SHA256" : "",
                    session->extensions & SSH_EXT_SIG_RSA_SHA512 ? " SHA512" : "");
        }

        /*
         * Remember whether 'first_kex_packet_follows' was set and the client
         * guess was wrong: in this case the next SSH_MSG_KEXDH_INIT message
         * must be ignored.
         */
        if (first_kex_packet_follows) {
          session->first_kex_follows_guess_wrong =
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_KEX],
                               session->next_crypto->server_kex.methods[SSH_KEX]) ||
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_HOSTKEYS],
                               session->next_crypto->server_kex.methods[SSH_HOSTKEYS]);
        }
    }

    /* Note, that his overwrites authenticated state in case of rekeying */
    session->session_state = SSH_SESSION_STATE_KEXINIT_RECEIVED;
    session->dh_handshake_state = DH_STATE_INIT;
    session->ssh_connection_callback(session);
    return SSH_PACKET_USED;

error:
    SSH_STRING_FREE(str);
    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (server_kex) {
            session->next_crypto->client_kex.methods[i] = NULL;
        } else { /* client */
            session->next_crypto->server_kex.methods[i] = NULL;
        }
        SAFE_FREE(strings[i]);
    }

    session->session_state = SSH_SESSION_STATE_ERROR;

    return SSH_PACKET_USED;
}

void ssh_list_kex(struct ssh_kex_struct *kex) {
  int i = 0;

#ifdef DEBUG_CRYPTO
  ssh_log_hexdump("session cookie", kex->cookie, 16);
#endif

  for(i = 0; i < SSH_KEX_METHODS; i++) {
    if (kex->methods[i] == NULL) {
      continue;
    }
    SSH_LOG(SSH_LOG_FUNCTIONS, "%s: %s",
        ssh_kex_descriptions[i], kex->methods[i]);
  }
}

/**
 * @internal
 *
 * @brief selects the hostkey mechanisms to be chosen for the key exchange,
 * as some hostkey mechanisms may be present in known_hosts files.
 *
 * @returns a cstring containing a comma-separated list of hostkey methods.
 *          NULL if no method matches
 */
char *ssh_client_select_hostkeys(ssh_session session)
{
    const char *wanted = NULL;
    char *wanted_without_certs = NULL;
    char *known_hosts_algorithms = NULL;
    char *known_hosts_ordered = NULL;
    char *new_hostkeys = NULL;
    char *fips_hostkeys = NULL;

    wanted = session->opts.wanted_methods[SSH_HOSTKEYS];
    if (wanted == NULL) {
        if (ssh_fips_mode()) {
            wanted = ssh_kex_get_fips_methods(SSH_HOSTKEYS);
        } else {
            wanted = ssh_kex_get_default_methods(SSH_HOSTKEYS);
        }
    }

    /* This removes the certificate types, unsupported for now */
    wanted_without_certs = ssh_find_all_matching(HOSTKEYS, wanted);
    if (wanted_without_certs == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "List of allowed host key algorithms is empty or contains only "
                "unsupported algorithms");
        return NULL;
    }

    SSH_LOG(SSH_LOG_DEBUG,
            "Order of wanted host keys: \"%s\"",
            wanted_without_certs);

    known_hosts_algorithms = ssh_known_hosts_get_algorithms_names(session);
    if (known_hosts_algorithms == NULL) {
        SSH_LOG(SSH_LOG_DEBUG,
                "No key found in known_hosts; "
                "changing host key method to \"%s\"",
                wanted_without_certs);

        return wanted_without_certs;
    }

    SSH_LOG(SSH_LOG_DEBUG,
            "Algorithms found in known_hosts files: \"%s\"",
            known_hosts_algorithms);

    /* Filter and order the keys from known_hosts according to wanted list */
    known_hosts_ordered = ssh_find_all_matching(known_hosts_algorithms,
                                                wanted_without_certs);
    SAFE_FREE(known_hosts_algorithms);
    if (known_hosts_ordered == NULL) {
        SSH_LOG(SSH_LOG_DEBUG,
                "No key found in known_hosts is allowed; "
                "changing host key method to \"%s\"",
                wanted_without_certs);

        return wanted_without_certs;
    }

    /* Append the other supported keys after the preferred ones
     * This function tolerates NULL pointers in parameters */
    new_hostkeys = ssh_append_without_duplicates(known_hosts_ordered,
                                                 wanted_without_certs);
    SAFE_FREE(known_hosts_ordered);
    SAFE_FREE(wanted_without_certs);
    if (new_hostkeys == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (ssh_fips_mode()) {
        /* Filter out algorithms not allowed in FIPS mode */
        fips_hostkeys = ssh_keep_fips_algos(SSH_HOSTKEYS, new_hostkeys);
        SAFE_FREE(new_hostkeys);
        if (fips_hostkeys == NULL) {
            SSH_LOG(SSH_LOG_WARNING,
                    "None of the wanted host keys or keys in known_hosts files "
                    "is allowed in FIPS mode.");
            return NULL;
        }
        new_hostkeys = fips_hostkeys;
    }

    SSH_LOG(SSH_LOG_DEBUG,
            "Changing host key method to \"%s\"",
            new_hostkeys);

    return new_hostkeys;
}

/**
 * @brief sets the key exchange parameters to be sent to the server,
 *        in function of the options and available methods.
 */
int ssh_set_client_kex(ssh_session session)
{
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    const char *wanted;
    char *kex = NULL;
    char *kex_tmp = NULL;
    int ok;
    int i;
    size_t kex_len, len;

    ok = ssh_get_random(client->cookie, 16, 0);
    if (!ok) {
        ssh_set_error(session, SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    memset(client->methods, 0, SSH_KEX_METHODS * sizeof(char **));

    /* Set the list of allowed algorithms in order of preference, if it hadn't
     * been set yet. */
    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (i == SSH_HOSTKEYS) {
            /* Set the hostkeys in the following order:
             * - First: keys present in known_hosts files ordered by preference
             * - Next: other wanted algorithms ordered by preference */
            client->methods[i] = ssh_client_select_hostkeys(session);
            if (client->methods[i] == NULL) {
                ssh_set_error_oom(session);
                return SSH_ERROR;
            }
            continue;
        }

        wanted = session->opts.wanted_methods[i];
        if (wanted == NULL) {
            if (ssh_fips_mode()) {
                wanted = fips_methods[i];
            } else {
                wanted = default_methods[i];
            }
        }
        client->methods[i] = strdup(wanted);
        if (client->methods[i] == NULL) {
            ssh_set_error_oom(session);
            return SSH_ERROR;
        }
    }

    /* For rekeying, skip the extension negotiation */
    if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) {
        return SSH_OK;
    }

    /* Here we append  ext-info-c  to the list of kex algorithms */
    kex = client->methods[SSH_KEX];
    len = strlen(kex);
    if (len + strlen(KEX_EXTENSION_CLIENT) + 2 < len) {
        /* Overflow */
        return SSH_ERROR;
    }
    kex_len = len + strlen(KEX_EXTENSION_CLIENT) + 2; /* comma, NULL */
    kex_tmp = realloc(kex, kex_len);
    if (kex_tmp == NULL) {
        free(kex);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    snprintf(kex_tmp + len, kex_len - len, ",%s", KEX_EXTENSION_CLIENT);
    client->methods[SSH_KEX] = kex_tmp;

    return SSH_OK;
}

/** @brief Select the different methods on basis of client's and
 * server's kex messages, and watches out if a match is possible.
 */
int ssh_kex_select_methods (ssh_session session){
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    char *ext_start = NULL;
    int i;

    /* Here we should drop the  ext-info-c  from the list so we avoid matching.
     * it. We added it to the end, so we can just truncate the string here */
    ext_start = strstr(client->methods[SSH_KEX], ","KEX_EXTENSION_CLIENT);
    if (ext_start != NULL) {
        ext_start[0] = '\0';
    }

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        session->next_crypto->kex_methods[i]=ssh_find_matching(server->methods[i],client->methods[i]);
        if(session->next_crypto->kex_methods[i] == NULL && i < SSH_LANG_C_S){
            ssh_set_error(session,SSH_FATAL,"kex error : no match for method %s: server [%s], client [%s]",
                    ssh_kex_descriptions[i],server->methods[i],client->methods[i]);
            return SSH_ERROR;
        } else if ((i >= SSH_LANG_C_S) && (session->next_crypto->kex_methods[i] == NULL)) {
            /* we can safely do that for languages */
            session->next_crypto->kex_methods[i] = strdup("");
        }
    }
    if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group1-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP1_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group14-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP14_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group14-sha256") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP14_SHA256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group16-sha512") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP16_SHA512;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group18-sha512") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP18_SHA512;
#ifdef WITH_GEX
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group-exchange-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GEX_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group-exchange-sha256") == 0){
        session->next_crypto->kex_type=SSH_KEX_DH_GEX_SHA256;
#endif /* WITH_GEX */
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp256") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp384") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP384;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp521") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP521;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256@libssh.org") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256;
    }
    SSH_LOG(SSH_LOG_INFO, "Negotiated %s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
            session->next_crypto->kex_methods[SSH_KEX],
            session->next_crypto->kex_methods[SSH_HOSTKEYS],
            session->next_crypto->kex_methods[SSH_CRYPT_C_S],
            session->next_crypto->kex_methods[SSH_CRYPT_S_C],
            session->next_crypto->kex_methods[SSH_MAC_C_S],
            session->next_crypto->kex_methods[SSH_MAC_S_C],
            session->next_crypto->kex_methods[SSH_COMP_C_S],
            session->next_crypto->kex_methods[SSH_COMP_S_C],
            session->next_crypto->kex_methods[SSH_LANG_C_S],
            session->next_crypto->kex_methods[SSH_LANG_S_C]
    );
    return SSH_OK;
}


/* this function only sends the predefined set of kex methods */
int ssh_send_kex(ssh_session session, int server_kex) {
  struct ssh_kex_struct *kex = (server_kex ? &session->next_crypto->server_kex :
      &session->next_crypto->client_kex);
  ssh_string str = NULL;
  int i;
  int rc;

  rc = ssh_buffer_pack(session->out_buffer,
                       "bP",
                       SSH2_MSG_KEXINIT,
                       16,
                       kex->cookie); /* cookie */
  if (rc != SSH_OK)
    goto error;
  if (ssh_hashbufout_add_cookie(session) < 0) {
    goto error;
  }

  ssh_list_kex(kex);

  for (i = 0; i < SSH_KEX_METHODS; i++) {
    str = ssh_string_from_char(kex->methods[i]);
    if (str == NULL) {
      goto error;
    }

    if (ssh_buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
      goto error;
    }
    if (ssh_buffer_add_ssh_string(session->out_buffer, str) < 0) {
      goto error;
    }
    SSH_STRING_FREE(str);
    str = NULL;
  }

  rc = ssh_buffer_pack(session->out_buffer,
                       "bd",
                       0,
                       0);
  if (rc != SSH_OK) {
    goto error;
  }

  if (ssh_packet_send(session) == SSH_ERROR) {
    return -1;
  }

  SSH_LOG(SSH_LOG_PACKET, "SSH_MSG_KEXINIT sent");
  return 0;
error:
  ssh_buffer_reinit(session->out_buffer);
  ssh_buffer_reinit(session->out_hashbuf);
  SSH_STRING_FREE(str);

  return -1;
}

/*
 * Key re-exchange (rekey) is triggered by this function.
 * It can not be called again after the rekey is initialized!
 */
int ssh_send_rekex(ssh_session session)
{
    int rc;

    if (session->dh_handshake_state != DH_STATE_FINISHED) {
        /* Rekey/Key exchange is already in progress */
        SSH_LOG(SSH_LOG_PACKET, "Attempting rekey in bad state");
        return SSH_ERROR;
    }

    if (session->current_crypto == NULL) {
        /* No current crypto used -- can not exchange it */
        SSH_LOG(SSH_LOG_PACKET, "No crypto to rekey");
        return SSH_ERROR;
    }

    if (session->client) {
        rc = ssh_set_client_kex(session);
        if (rc != SSH_OK) {
            SSH_LOG(SSH_LOG_PACKET, "Failed to set client kex");
            return rc;
        }
    } else {
#ifdef WITH_SERVER
        rc = server_set_kex(session);
        if (rc == SSH_ERROR) {
            SSH_LOG(SSH_LOG_PACKET, "Failed to set server kex");
            return rc;
        }
#else
        SSH_LOG(SSH_LOG_PACKET, "Invalid session state.");
        return SSH_ERROR;
#endif /* WITH_SERVER */
    }

    session->dh_handshake_state = DH_STATE_INIT;
    rc = ssh_send_kex(session, session->server);
    if (rc < 0) {
        SSH_LOG(SSH_LOG_PACKET, "Failed to send kex");
        return rc;
    }

    /* Reset the handshake state */
    session->dh_handshake_state = DH_STATE_INIT_SENT;
    return SSH_OK;
}

/* returns a copy of the provided list if everything is supported,
 * otherwise a new list of the supported algorithms */
char *ssh_keep_known_algos(enum ssh_kex_types_e algo, const char *list)
{
    if (algo > SSH_LANG_S_C) {
        return NULL;
    }

    return ssh_find_all_matching(supported_methods[algo], list);
}

/**
 * @internal
 *
 * @brief Return a new allocated string containing only the FIPS allowed
 * algorithms from the list.
 *
 * @param[in] algo  The type of the methods to filter
 * @param[in] list  The list to be filtered
 *
 * @return A new allocated list containing only the FIPS allowed algorithms from
 * the list; NULL in case of error.
 */
char *ssh_keep_fips_algos(enum ssh_kex_types_e algo, const char *list)
{
    if (algo > SSH_LANG_S_C) {
        return NULL;
    }

    return ssh_find_all_matching(fips_methods[algo], list);
}

int ssh_make_sessionid(ssh_session session)
{
    ssh_string num = NULL;
    ssh_buffer server_hash = NULL;
    ssh_buffer client_hash = NULL;
    ssh_buffer buf = NULL;
    ssh_string server_pubkey_blob = NULL;
    const_bignum client_pubkey, server_pubkey;
#ifdef WITH_GEX
    const_bignum modulus, generator;
#endif
    int rc = SSH_ERROR;

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return rc;
    }

    rc = ssh_buffer_pack(buf,
                         "ss",
                         session->clientbanner,
                         session->serverbanner);
    if (rc == SSH_ERROR) {
        goto error;
    }

    if (session->client) {
        server_hash = session->in_hashbuf;
        client_hash = session->out_hashbuf;
    } else {
        server_hash = session->out_hashbuf;
        client_hash = session->in_hashbuf;
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     */
    rc = ssh_buffer_add_u8(server_hash, 0);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_buffer_add_u32(server_hash, 0);
    if (rc < 0) {
        goto error;
    }

    /* These fields are handled for the server case in ssh_packet_kexinit. */
    if (session->client) {
        rc = ssh_buffer_add_u8(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u32(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
    }

    rc = ssh_dh_get_next_server_publickey_blob(session, &server_pubkey_blob);
    if (rc != SSH_OK) {
        goto error;
    }

    rc = ssh_buffer_pack(buf,
                         "dPdPS",
                         ssh_buffer_get_len(client_hash),
                         ssh_buffer_get_len(client_hash),
                         ssh_buffer_get(client_hash),
                         ssh_buffer_get_len(server_hash),
                         ssh_buffer_get_len(server_hash),
                         ssh_buffer_get(server_hash),
                         server_pubkey_blob);
    SSH_STRING_FREE(server_pubkey_blob);
    if(rc != SSH_OK){
        goto error;
    }

    switch(session->next_crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
    case SSH_KEX_DH_GROUP14_SHA256:
    case SSH_KEX_DH_GROUP16_SHA512:
    case SSH_KEX_DH_GROUP18_SHA512:
        rc = ssh_dh_keypair_get_keys(session->next_crypto->dh_ctx,
                                     DH_CLIENT_KEYPAIR, NULL, &client_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        rc = ssh_dh_keypair_get_keys(session->next_crypto->dh_ctx,
                                     DH_SERVER_KEYPAIR, NULL, &server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        rc = ssh_buffer_pack(buf,
                             "BB",
                             client_pubkey,
                             server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        break;
#ifdef WITH_GEX
    case SSH_KEX_DH_GEX_SHA1:
    case SSH_KEX_DH_GEX_SHA256:
        rc = ssh_dh_keypair_get_keys(session->next_crypto->dh_ctx,
                                     DH_CLIENT_KEYPAIR, NULL, &client_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        rc = ssh_dh_keypair_get_keys(session->next_crypto->dh_ctx,
                                     DH_SERVER_KEYPAIR, NULL, &server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        rc = ssh_dh_get_parameters(session->next_crypto->dh_ctx,
                                   &modulus, &generator);
        if (rc != SSH_OK) {
            goto error;
        }
        rc = ssh_buffer_pack(buf,
                    "dddBBBB",
                    session->next_crypto->dh_pmin,
                    session->next_crypto->dh_pn,
                    session->next_crypto->dh_pmax,
                    modulus,
                    generator,
                    client_pubkey,
                    server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        break;
#endif /* WITH_GEX */
#ifdef HAVE_ECDH
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_ECDH_SHA2_NISTP384:
    case SSH_KEX_ECDH_SHA2_NISTP521:
        if (session->next_crypto->ecdh_client_pubkey == NULL ||
            session->next_crypto->ecdh_server_pubkey == NULL) {
            SSH_LOG(SSH_LOG_WARNING, "ECDH parameted missing");
            goto error;
        }
        rc = ssh_buffer_pack(buf,
                             "SS",
                             session->next_crypto->ecdh_client_pubkey,
                             session->next_crypto->ecdh_server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
        break;
#endif
#ifdef HAVE_CURVE25519
    case SSH_KEX_CURVE25519_SHA256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
        rc = ssh_buffer_pack(buf,
                             "dPdP",
                             CURVE25519_PUBKEY_SIZE,
                             (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_client_pubkey,
                             CURVE25519_PUBKEY_SIZE,
                             (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_server_pubkey);

        if (rc != SSH_OK) {
            goto error;
        }
        break;
#endif
    }
    rc = ssh_buffer_pack(buf, "B", session->next_crypto->shared_secret);
    if (rc != SSH_OK) {
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("hash buffer", ssh_buffer_get(buf), ssh_buffer_get_len(buf));
#endif

    switch (session->next_crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
#ifdef WITH_GEX
    case SSH_KEX_DH_GEX_SHA1:
#endif /* WITH_GEX */
        session->next_crypto->digest_len = SHA_DIGEST_LENGTH;
        session->next_crypto->digest_type = SSH_KDF_SHA1;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha1(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
                                   session->next_crypto->secret_hash);
        break;
    case SSH_KEX_DH_GROUP14_SHA256:
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_CURVE25519_SHA256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
#ifdef WITH_GEX
    case SSH_KEX_DH_GEX_SHA256:
#endif /* WITH_GEX */
        session->next_crypto->digest_len = SHA256_DIGEST_LENGTH;
        session->next_crypto->digest_type = SSH_KDF_SHA256;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha256(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
                                     session->next_crypto->secret_hash);
        break;
    case SSH_KEX_ECDH_SHA2_NISTP384:
        session->next_crypto->digest_len = SHA384_DIGEST_LENGTH;
        session->next_crypto->digest_type = SSH_KDF_SHA384;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha384(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
                                     session->next_crypto->secret_hash);
        break;
    case SSH_KEX_DH_GROUP16_SHA512:
    case SSH_KEX_DH_GROUP18_SHA512:
    case SSH_KEX_ECDH_SHA2_NISTP521:
        session->next_crypto->digest_len = SHA512_DIGEST_LENGTH;
        session->next_crypto->digest_type = SSH_KDF_SHA512;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha512(ssh_buffer_get(buf),
               ssh_buffer_get_len(buf),
               session->next_crypto->secret_hash);
        break;
    }
    /* During the first kex, secret hash and session ID are equal. However, after
     * a key re-exchange, a new secret hash is calculated. This hash will not replace
     * but complement existing session id.
     */
    if (!session->next_crypto->session_id) {
        session->next_crypto->session_id = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->session_id == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        memcpy(session->next_crypto->session_id, session->next_crypto->secret_hash,
                session->next_crypto->digest_len);
    }
#ifdef DEBUG_CRYPTO
    printf("Session hash: \n");
    ssh_log_hexdump("secret hash", session->next_crypto->secret_hash, session->next_crypto->digest_len);
    ssh_log_hexdump("session id", session->next_crypto->session_id, session->next_crypto->digest_len);
#endif

    rc = SSH_OK;
error:
    SSH_BUFFER_FREE(buf);
    SSH_BUFFER_FREE(client_hash);
    SSH_BUFFER_FREE(server_hash);

    session->in_hashbuf = NULL;
    session->out_hashbuf = NULL;

    SSH_STRING_FREE(num);

    return rc;
}

int ssh_hashbufout_add_cookie(ssh_session session)
{
    int rc;

    session->out_hashbuf = ssh_buffer_new();
    if (session->out_hashbuf == NULL) {
        return -1;
    }

    rc = ssh_buffer_allocate_size(session->out_hashbuf,
            sizeof(uint8_t) + 16);
    if (rc < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return -1;
    }

    if (ssh_buffer_add_u8(session->out_hashbuf, 20) < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return -1;
    }

    if (session->server) {
        if (ssh_buffer_add_data(session->out_hashbuf,
                    session->next_crypto->server_kex.cookie, 16) < 0) {
            ssh_buffer_reinit(session->out_hashbuf);
            return -1;
        }
    } else {
        if (ssh_buffer_add_data(session->out_hashbuf,
                    session->next_crypto->client_kex.cookie, 16) < 0) {
            ssh_buffer_reinit(session->out_hashbuf);
            return -1;
        }
    }

    return 0;
}

int ssh_hashbufin_add_cookie(ssh_session session, unsigned char *cookie)
{
    int rc;

    session->in_hashbuf = ssh_buffer_new();
    if (session->in_hashbuf == NULL) {
        return -1;
    }

    rc = ssh_buffer_allocate_size(session->in_hashbuf,
            sizeof(uint8_t) + 20 + 16);
    if (rc < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return -1;
    }

    if (ssh_buffer_add_u8(session->in_hashbuf, 20) < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return -1;
    }
    if (ssh_buffer_add_data(session->in_hashbuf,cookie, 16) < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return -1;
    }

    return 0;
}

int ssh_generate_session_keys(ssh_session session)
{
    ssh_string k_string = NULL;
    struct ssh_crypto_struct *crypto = session->next_crypto;
    unsigned char *key = NULL;
    unsigned char *IV_cli_to_srv = NULL;
    unsigned char *IV_srv_to_cli = NULL;
    unsigned char *enckey_cli_to_srv = NULL;
    unsigned char *enckey_srv_to_cli = NULL;
    unsigned char *intkey_cli_to_srv = NULL;
    unsigned char *intkey_srv_to_cli = NULL;
    size_t key_len = 0;
    size_t IV_len = 0;
    size_t enckey_cli_to_srv_len = 0;
    size_t enckey_srv_to_cli_len = 0;
    size_t intkey_cli_to_srv_len = 0;
    size_t intkey_srv_to_cli_len = 0;
    int rc = -1;

    k_string = ssh_make_bignum_string(crypto->shared_secret);
    if (k_string == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    /* See RFC4251 Section 5 for the definition of mpint which is the
     * encoding we need to use for key in the SSH KDF */
    key = (unsigned char *)k_string;
    key_len = ssh_string_len(k_string) + 4;

    IV_len = crypto->digest_len;
    if (session->client) {
        enckey_cli_to_srv_len = crypto->out_cipher->keysize / 8;
        enckey_srv_to_cli_len = crypto->in_cipher->keysize / 8;
        intkey_cli_to_srv_len = hmac_digest_len(crypto->out_hmac);
        intkey_srv_to_cli_len = hmac_digest_len(crypto->in_hmac);
    } else {
        enckey_cli_to_srv_len = crypto->in_cipher->keysize / 8;
        enckey_srv_to_cli_len = crypto->out_cipher->keysize / 8;
        intkey_cli_to_srv_len = hmac_digest_len(crypto->in_hmac);
        intkey_srv_to_cli_len = hmac_digest_len(crypto->out_hmac);
    }

    IV_cli_to_srv = malloc(IV_len);
    IV_srv_to_cli = malloc(IV_len);
    enckey_cli_to_srv = malloc(enckey_cli_to_srv_len);
    enckey_srv_to_cli = malloc(enckey_srv_to_cli_len);
    intkey_cli_to_srv = malloc(intkey_cli_to_srv_len);
    intkey_srv_to_cli = malloc(intkey_srv_to_cli_len);
    if (IV_cli_to_srv == NULL || IV_srv_to_cli == NULL ||
        enckey_cli_to_srv == NULL || enckey_srv_to_cli == NULL ||
        intkey_cli_to_srv == NULL || intkey_srv_to_cli == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* IV */
    rc = ssh_kdf(crypto, key, key_len, 'A', IV_cli_to_srv, IV_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'B', IV_srv_to_cli, IV_len);
    if (rc < 0) {
        goto error;
    }
    /* Encryption Key */
    rc = ssh_kdf(crypto, key, key_len, 'C', enckey_cli_to_srv,
                 enckey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'D', enckey_srv_to_cli,
                 enckey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }
    /* Integrity Key */
    rc = ssh_kdf(crypto, key, key_len, 'E', intkey_cli_to_srv,
                 intkey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'F', intkey_srv_to_cli,
                 intkey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }

    if (session->client) {
        crypto->encryptIV = IV_cli_to_srv;
        crypto->decryptIV = IV_srv_to_cli;
        crypto->encryptkey = enckey_cli_to_srv;
        crypto->decryptkey = enckey_srv_to_cli;
        crypto->encryptMAC = intkey_cli_to_srv;
        crypto->decryptMAC = intkey_srv_to_cli;
    } else {
        crypto->encryptIV = IV_srv_to_cli;
        crypto->decryptIV = IV_cli_to_srv;
        crypto->encryptkey = enckey_srv_to_cli;
        crypto->decryptkey = enckey_cli_to_srv;
        crypto->encryptMAC = intkey_srv_to_cli;
        crypto->decryptMAC = intkey_cli_to_srv;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("Client to Server IV", IV_cli_to_srv, IV_len);
    ssh_log_hexdump("Server to Client IV", IV_srv_to_cli, IV_len);
    ssh_log_hexdump("Client to Server Encryption Key", enckey_cli_to_srv,
                   enckey_cli_to_srv_len);
    ssh_log_hexdump("Server to Client Encryption Key", enckey_srv_to_cli,
                   enckey_srv_to_cli_len);
    ssh_log_hexdump("Client to Server Integrity Key", intkey_cli_to_srv,
                   intkey_cli_to_srv_len);
    ssh_log_hexdump("Server to Client Integrity Key", intkey_srv_to_cli,
                   intkey_srv_to_cli_len);
#endif

    rc = 0;
error:
    ssh_string_burn(k_string);
    SSH_STRING_FREE(k_string);
    if (rc != 0) {
        free(IV_cli_to_srv);
        free(IV_srv_to_cli);
        free(enckey_cli_to_srv);
        free(enckey_srv_to_cli);
        free(intkey_cli_to_srv);
        free(intkey_srv_to_cli);
    }

    return rc;
}
