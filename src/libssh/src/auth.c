/*
 * auth.c - Authentication with SSH protocols
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013 by Aris Adamantiadis <aris@0xbadc0de.be>
 * Copyright (c) 2008-2013 Andreas Schneider <asn@cryptomilk.org>
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

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/agent.h"
#include "libssh/misc.h"
#include "libssh/packet.h"
#include "libssh/session.h"
#include "libssh/keys.h"
#include "libssh/auth.h"
#include "libssh/pki.h"
#include "libssh/gssapi.h"
#include "libssh/legacy.h"

/**
 * @defgroup libssh_auth The SSH authentication functions.
 * @ingroup libssh
 *
 * Functions to authenticate with a server.
 *
 * @{
 */

/**
 * @internal
 *
 * @brief Ask access to the ssh-userauth service.
 *
 * @param[in] session   The SSH session handle.
 *
 * @returns SSH_OK on success, SSH_ERROR on error.
 * @returns SSH_AGAIN on nonblocking mode, if calling that function
 * again is necessary
 */
static int ssh_userauth_request_service(ssh_session session) {
    int rc;

    rc = ssh_service_request(session, "ssh-userauth");
    if ((rc != SSH_OK) && (rc != SSH_AGAIN)) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to request \"ssh-userauth\" service");
    }

    return rc;
}

static int ssh_auth_response_termination(void *user) {
    ssh_session session = (ssh_session)user;
    switch (session->auth.state) {
        case SSH_AUTH_STATE_NONE:
        case SSH_AUTH_STATE_KBDINT_SENT:
        case SSH_AUTH_STATE_GSSAPI_REQUEST_SENT:
        case SSH_AUTH_STATE_GSSAPI_TOKEN:
        case SSH_AUTH_STATE_GSSAPI_MIC_SENT:
        case SSH_AUTH_STATE_PUBKEY_AUTH_SENT:
        case SSH_AUTH_STATE_PUBKEY_OFFER_SENT:
        case SSH_AUTH_STATE_PASSWORD_AUTH_SENT:
        case SSH_AUTH_STATE_AUTH_NONE_SENT:
            return 0;
        default:
            return 1;
    }
}

static const char *ssh_auth_get_current_method(ssh_session session)
{
    const char *method = "unknown";

    switch (session->auth.current_method) {
    case SSH_AUTH_METHOD_NONE:
        method = "none";
        break;
    case SSH_AUTH_METHOD_PASSWORD:
        method = "password";
        break;
    case SSH_AUTH_METHOD_PUBLICKEY:
        method = "publickey";
        break;
    case SSH_AUTH_METHOD_HOSTBASED:
        method = "hostbased";
        break;
    case SSH_AUTH_METHOD_INTERACTIVE:
        method = "keyboard interactive";
        break;
    case SSH_AUTH_METHOD_GSSAPI_MIC:
        method = "gssapi";
        break;
    default:
        break;
    }

    return method;
}

/**
 * @internal
 * @brief Wait for a response of an authentication function.
 *
 * @param[in] session   The SSH session.
 *
 * @returns SSH_AUTH_SUCCESS Authentication success, or pubkey accepted
 *          SSH_AUTH_PARTIAL Authentication succeeded but another mean
 *                           of authentication is needed.
 *          SSH_AUTH_INFO    Data for keyboard-interactive
 *          SSH_AUTH_AGAIN   In nonblocking mode, call has to be made again
 *          SSH_AUTH_ERROR   Error during the process.
 */
static int ssh_userauth_get_response(ssh_session session) {
    int rc = SSH_AUTH_ERROR;

    rc = ssh_handle_packets_termination(session, SSH_TIMEOUT_USER,
        ssh_auth_response_termination, session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
    if (!ssh_auth_response_termination(session)) {
        return SSH_AUTH_AGAIN;
    }

    switch(session->auth.state) {
        case SSH_AUTH_STATE_ERROR:
            rc = SSH_AUTH_ERROR;
            break;
        case SSH_AUTH_STATE_FAILED:
            rc = SSH_AUTH_DENIED;
            break;
        case SSH_AUTH_STATE_INFO:
            rc = SSH_AUTH_INFO;
            break;
        case SSH_AUTH_STATE_PARTIAL:
            rc = SSH_AUTH_PARTIAL;
            break;
        case SSH_AUTH_STATE_PK_OK:
        case SSH_AUTH_STATE_SUCCESS:
            rc = SSH_AUTH_SUCCESS;
            break;
        case SSH_AUTH_STATE_KBDINT_SENT:
        case SSH_AUTH_STATE_GSSAPI_REQUEST_SENT:
        case SSH_AUTH_STATE_GSSAPI_TOKEN:
        case SSH_AUTH_STATE_GSSAPI_MIC_SENT:
        case SSH_AUTH_STATE_PUBKEY_OFFER_SENT:
        case SSH_AUTH_STATE_PUBKEY_AUTH_SENT:
        case SSH_AUTH_STATE_PASSWORD_AUTH_SENT:
        case SSH_AUTH_STATE_AUTH_NONE_SENT:
        case SSH_AUTH_STATE_NONE:
            /* not reached */
            rc = SSH_AUTH_ERROR;
            break;
    }

    return rc;
}

/**
 * @internal
 *
 * @brief Handles a SSH_USERAUTH_BANNER packet.
 *
 * This banner should be shown to user prior to authentication
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_banner) {
    ssh_string banner;
    (void)type;
    (void)user;

    banner = ssh_buffer_get_ssh_string(packet);
    if (banner == NULL) {
        SSH_LOG(SSH_LOG_WARN,
                "Invalid SSH_USERAUTH_BANNER packet");
    } else {
        SSH_LOG(SSH_LOG_DEBUG,
                "Received SSH_USERAUTH_BANNER packet");
        if (session->banner != NULL)
            SSH_STRING_FREE(session->banner);
        session->banner = banner;
    }

    return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handles a SSH_USERAUTH_FAILURE packet.
 *
 * This handles the complete or partial authentication failure.
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_failure) {
    const char *current_method = ssh_auth_get_current_method(session);
    char *auth_methods = NULL;
    uint8_t partial = 0;
    int rc;
    (void) type;
    (void) user;

    rc = ssh_buffer_unpack(packet, "sb", &auth_methods, &partial);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL,
                      "Invalid SSH_MSG_USERAUTH_FAILURE message");
        session->auth.state = SSH_AUTH_STATE_ERROR;
        goto end;
    }

    if (partial) {
        session->auth.state = SSH_AUTH_STATE_PARTIAL;
        SSH_LOG(SSH_LOG_INFO,
                "Partial success for '%s'. Authentication that can continue: %s",
                current_method,
                auth_methods);
    } else {
        session->auth.state = SSH_AUTH_STATE_FAILED;
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Access denied for '%s'. Authentication that can continue: %s",
                      current_method,
                      auth_methods);
        SSH_LOG(SSH_LOG_INFO,
                "%s",
                ssh_get_error(session));

    }
    session->auth.supported_methods = 0;
    if (strstr(auth_methods, "password") != NULL) {
        session->auth.supported_methods |= SSH_AUTH_METHOD_PASSWORD;
    }
    if (strstr(auth_methods, "keyboard-interactive") != NULL) {
        session->auth.supported_methods |= SSH_AUTH_METHOD_INTERACTIVE;
    }
    if (strstr(auth_methods, "publickey") != NULL) {
        session->auth.supported_methods |= SSH_AUTH_METHOD_PUBLICKEY;
    }
    if (strstr(auth_methods, "hostbased") != NULL) {
        session->auth.supported_methods |= SSH_AUTH_METHOD_HOSTBASED;
    }
    if (strstr(auth_methods, "gssapi-with-mic") != NULL) {
        session->auth.supported_methods |= SSH_AUTH_METHOD_GSSAPI_MIC;
    }

end:
    session->auth.current_method = SSH_AUTH_METHOD_UNKNOWN;
    SAFE_FREE(auth_methods);

    return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handles a SSH_USERAUTH_SUCCESS packet.
 *
 * It is also used to communicate the new to the upper levels.
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_success)
{
  struct ssh_crypto_struct *crypto = NULL;

  (void)packet;
  (void)type;
  (void)user;

  SSH_LOG(SSH_LOG_DEBUG, "Authentication successful");
  SSH_LOG(SSH_LOG_TRACE, "Received SSH_USERAUTH_SUCCESS");

  session->auth.state = SSH_AUTH_STATE_SUCCESS;
  session->session_state = SSH_SESSION_STATE_AUTHENTICATED;
  session->flags |= SSH_SESSION_FLAG_AUTHENTICATED;

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_OUT);
  if (crypto != NULL && crypto->delayed_compress_out) {
      SSH_LOG(SSH_LOG_DEBUG, "Enabling delayed compression OUT");
      crypto->do_compress_out = 1;
  }

  crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_IN);
  if (crypto != NULL && crypto->delayed_compress_in) {
      SSH_LOG(SSH_LOG_DEBUG, "Enabling delayed compression IN");
      crypto->do_compress_in = 1;
  }

    /* Reset errors by previous authentication methods. */
    ssh_reset_error(session);
    session->auth.current_method = SSH_AUTH_METHOD_UNKNOWN;
  return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handles a SSH_USERAUTH_PK_OK or SSH_USERAUTH_INFO_REQUEST packet.
 *
 * Since the two types of packets share the same code, additional work is done
 * to understand if we are in a public key or keyboard-interactive context.
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_pk_ok) {
    int rc;

    SSH_LOG(SSH_LOG_TRACE,
            "Received SSH_USERAUTH_PK_OK/INFO_REQUEST/GSSAPI_RESPONSE");

    if (session->auth.state == SSH_AUTH_STATE_KBDINT_SENT) {
        /* Assuming we are in keyboard-interactive context */
        SSH_LOG(SSH_LOG_TRACE,
                "keyboard-interactive context, "
                "assuming SSH_USERAUTH_INFO_REQUEST");
        rc = ssh_packet_userauth_info_request(session,type,packet,user);
#ifdef WITH_GSSAPI
    } else if (session->auth.state == SSH_AUTH_STATE_GSSAPI_REQUEST_SENT) {
        rc = ssh_packet_userauth_gssapi_response(session, type, packet, user);
#endif
    } else if (session->auth.state == SSH_AUTH_STATE_PUBKEY_OFFER_SENT) {
        session->auth.state = SSH_AUTH_STATE_PK_OK;
        SSH_LOG(SSH_LOG_TRACE, "Assuming SSH_USERAUTH_PK_OK");
        rc = SSH_PACKET_USED;
    } else {
        session->auth.state = SSH_AUTH_STATE_ERROR;
        SSH_LOG(SSH_LOG_TRACE, "SSH_USERAUTH_PK_OK received in wrong state");
        rc = SSH_PACKET_USED;
    }

    return rc;
}

/**
 * @brief Get available authentication methods from the server.
 *
 * This requires the function ssh_userauth_none() to be called before the
 * methods are available. The server MAY return a list of methods that may
 * continue.
 *
 * @param[in] session   The SSH session.
 *
 * @param[in] username  Deprecated, set to NULL.
 *
 * @returns             A bitfield of the fllowing values:
 *                      - SSH_AUTH_METHOD_PASSWORD
 *                      - SSH_AUTH_METHOD_PUBLICKEY
 *                      - SSH_AUTH_METHOD_HOSTBASED
 *                      - SSH_AUTH_METHOD_INTERACTIVE
 *
 * @warning Other reserved flags may appear in future versions.
 * @see ssh_userauth_none()
 */
int ssh_userauth_list(ssh_session session, const char *username)
{
    (void) username; /* unused */

    if (session == NULL) {
        return 0;
    }

    return session->auth.supported_methods;
}

/**
 * @brief Try to authenticate through the "none" method.
 *
 * @param[in] session   The ssh session to use.
 *
 * @param[in] username    The username, this SHOULD be NULL.
 *
 * @returns SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  Authentication failed: use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
int ssh_userauth_none(ssh_session session, const char *username) {
    int rc;

    switch(session->pending_call_state) {
        case SSH_PENDING_CALL_NONE:
            break;
        case SSH_PENDING_CALL_AUTH_NONE:
            goto pending;
        default:
            ssh_set_error(session, SSH_FATAL,
                          "Wrong state (%d) during pending SSH call",
                          session->pending_call_state);
            return SSH_AUTH_ERROR;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsss",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "none"
            );
    if (rc < 0) {
        goto fail;
    }

    session->auth.current_method = SSH_AUTH_METHOD_NONE;
    session->auth.state = SSH_AUTH_STATE_AUTH_NONE_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_NONE;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }

    return rc;
fail:
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

/**
 * @brief Try to authenticate with the given public key.
 *
 * To avoid unnecessary processing and user interaction, the following method
 * is provided for querying whether authentication using the 'pubkey' would
 * be possible.
 *
 * @param[in] session     The SSH session.
 *
 * @param[in] username    The username, this SHOULD be NULL.
 *
 * @param[in] pubkey      The public key to try.
 *
 * @return  SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  The server doesn't accept that public key as an
 *                            authentication token. Try another key or another
 *                            method.\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method.\n
 *          SSH_AUTH_SUCCESS: The public key is accepted, you want now to use
 *                            ssh_userauth_publickey().\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
int ssh_userauth_try_publickey(ssh_session session,
                               const char *username,
                               const ssh_key pubkey)
{
    ssh_string pubkey_s = NULL;
    const char *sig_type_c = NULL;
    int rc;

    if (session == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (pubkey == NULL || !ssh_key_is_public(pubkey)) {
        ssh_set_error(session, SSH_FATAL, "Invalid pubkey");
        return SSH_AUTH_ERROR;
    }

    switch(session->pending_call_state) {
        case SSH_PENDING_CALL_NONE:
            break;
        case SSH_PENDING_CALL_AUTH_OFFER_PUBKEY:
            goto pending;
        default:
            ssh_set_error(session,
                          SSH_FATAL,
                          "Wrong state (%d) during pending SSH call",
                          session->pending_call_state);
            return SSH_ERROR;
    }

    /* Check if the given public key algorithm is allowed */
    sig_type_c = ssh_key_get_signature_algorithm(session, pubkey->type);
    if (sig_type_c == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Invalid key type (unknown)");
        return SSH_AUTH_DENIED;
    }
    if (!ssh_key_algorithm_allowed(session, sig_type_c)) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "The key algorithm '%s' is not allowed to be used by"
                      " PUBLICKEY_ACCEPTED_TYPES configuration option",
                      sig_type_c);
        return SSH_AUTH_DENIED;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    /* public key */
    rc = ssh_pki_export_pubkey_blob(pubkey, &pubkey_s);
    if (rc < 0) {
        goto fail;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsssbsS",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "publickey",
            0, /* private key ? */
            sig_type_c, /* algo */
            pubkey_s /* public key */
            );
    if (rc < 0) {
        goto fail;
    }

    SSH_STRING_FREE(pubkey_s);

    session->auth.current_method = SSH_AUTH_METHOD_PUBLICKEY;
    session->auth.state = SSH_AUTH_STATE_PUBKEY_OFFER_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_OFFER_PUBKEY;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }

    return rc;
fail:
    SSH_STRING_FREE(pubkey_s);
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

/**
 * @brief Authenticate with public/private key or certificate.
 *
 * @param[in] session     The SSH session.
 *
 * @param[in] username    The username, this SHOULD be NULL.
 *
 * @param[in] privkey     The private key for authentication.
 *
 * @return  SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  The server doesn't accept that public key as an
 *                            authentication token. Try another key or another
 *                            method.\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method.\n
 *          SSH_AUTH_SUCCESS: The public key is accepted.\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
int ssh_userauth_publickey(ssh_session session,
                           const char *username,
                           const ssh_key privkey)
{
    ssh_string str = NULL;
    int rc;
    const char *sig_type_c = NULL;
    enum ssh_keytypes_e key_type;
    enum ssh_digest_e hash_type;

    if (session == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        ssh_set_error(session, SSH_FATAL, "Invalid private key");
        return SSH_AUTH_ERROR;
    }

    switch(session->pending_call_state) {
        case SSH_PENDING_CALL_NONE:
            break;
        case SSH_PENDING_CALL_AUTH_PUBKEY:
            goto pending;
        default:
            ssh_set_error(session,
                          SSH_FATAL,
                          "Bad call during pending SSH call in ssh_userauth_try_publickey");
            return SSH_AUTH_ERROR;
    }

    /* Cert auth requires presenting the cert type name (*-cert@openssh.com) */
    key_type = privkey->cert != NULL ? privkey->cert_type : privkey->type;

    /* Check if the given public key algorithm is allowed */
    sig_type_c = ssh_key_get_signature_algorithm(session, key_type);
    if (sig_type_c == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Invalid key type (unknown)");
        return SSH_AUTH_DENIED;
    }
    if (!ssh_key_algorithm_allowed(session, sig_type_c)) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "The key algorithm '%s' is not allowed to be used by"
                      " PUBLICKEY_ACCEPTED_TYPES configuration option",
                      sig_type_c);
        return SSH_AUTH_DENIED;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    /* get public key or cert */
    rc = ssh_pki_export_pubkey_blob(privkey, &str);
    if (rc < 0) {
        goto fail;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsssbsS",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "publickey",
            1, /* private key */
            sig_type_c, /* algo */
            str /* public key or cert */
            );
    if (rc < 0) {
        goto fail;
    }
    SSH_STRING_FREE(str);

    /* Get the hash type to be used in the signature based on the key type */
    hash_type = ssh_key_type_to_hash(session, privkey->type);

    /* sign the buffer with the private key */
    str = ssh_pki_do_sign(session, session->out_buffer, privkey, hash_type);
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, str);
    SSH_STRING_FREE(str);
    str = NULL;
    if (rc < 0) {
        goto fail;
    }

    session->auth.current_method = SSH_AUTH_METHOD_PUBLICKEY;
    session->auth.state = SSH_AUTH_STATE_PUBKEY_AUTH_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_PUBKEY;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }

    return rc;
fail:
    SSH_STRING_FREE(str);
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

#ifndef _WIN32
static int ssh_userauth_agent_publickey(ssh_session session,
                                        const char *username,
                                        ssh_key pubkey)
{
    ssh_string pubkey_s = NULL;
    ssh_string sig_blob = NULL;
    const char *sig_type_c = NULL;
    int rc;

    switch(session->pending_call_state) {
        case SSH_PENDING_CALL_NONE:
            break;
        case SSH_PENDING_CALL_AUTH_AGENT:
            goto pending;
        default:
            ssh_set_error(session,
                          SSH_FATAL,
                          "Bad call during pending SSH call in ssh_userauth_try_publickey");
            return SSH_ERROR;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    /* public key */
    rc = ssh_pki_export_pubkey_blob(pubkey, &pubkey_s);
    if (rc < 0) {
        goto fail;
    }

    /* Check if the given public key algorithm is allowed */
    sig_type_c = ssh_key_get_signature_algorithm(session, pubkey->type);
    if (sig_type_c == NULL) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "Invalid key type (unknown)");
        SSH_STRING_FREE(pubkey_s);
        return SSH_AUTH_DENIED;
    }
    if (!ssh_key_algorithm_allowed(session, sig_type_c)) {
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "The key algorithm '%s' is not allowed to be used by"
                      " PUBLICKEY_ACCEPTED_TYPES configuration option",
                      sig_type_c);
        SSH_STRING_FREE(pubkey_s);
        return SSH_AUTH_DENIED;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsssbsS",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "publickey",
            1, /* private key */
            sig_type_c, /* algo */
            pubkey_s /* public key */
            );
    SSH_STRING_FREE(pubkey_s);
    if (rc < 0) {
        goto fail;
    }

    /* sign the buffer with the private key */
    sig_blob = ssh_pki_do_sign_agent(session, session->out_buffer, pubkey);
    if (sig_blob == NULL) {
        goto fail;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, sig_blob);
    SSH_STRING_FREE(sig_blob);
    if (rc < 0) {
        goto fail;
    }

    session->auth.current_method = SSH_AUTH_METHOD_PUBLICKEY;
    session->auth.state = SSH_AUTH_STATE_PUBKEY_AUTH_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_AGENT;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }

    return rc;
fail:
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);
    SSH_STRING_FREE(pubkey_s);

    return SSH_AUTH_ERROR;
}

enum ssh_agent_state_e {
    SSH_AGENT_STATE_NONE = 0,
    SSH_AGENT_STATE_PUBKEY,
    SSH_AGENT_STATE_AUTH
};

struct ssh_agent_state_struct {
    enum ssh_agent_state_e state;
    ssh_key pubkey;
    char *comment;
};

/* Internal function */
void ssh_agent_state_free(void *data) {
    struct ssh_agent_state_struct *state = data;

    if (state) {
        SSH_STRING_FREE_CHAR(state->comment);
        ssh_key_free(state->pubkey);
        free (state);
    }
}

/**
 * @brief Try to do public key authentication with ssh agent.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @param[in]  username The username, this SHOULD be NULL.
 *
 * @return  SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  The server doesn't accept that public key as an
 *                            authentication token. Try another key or another
 *                            method.\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method.\n
 *          SSH_AUTH_SUCCESS: The public key is accepted, you want now to use
 *                            ssh_userauth_publickey().\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
int ssh_userauth_agent(ssh_session session,
                       const char *username) {
    int rc = SSH_AUTH_ERROR;
    struct ssh_agent_state_struct *state;

    if (session == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (!ssh_agent_is_running(session)) {
        return SSH_AUTH_DENIED;
    }

    if (!session->agent_state) {
        session->agent_state = malloc(sizeof(struct ssh_agent_state_struct));
        if (!session->agent_state) {
            ssh_set_error_oom(session);
            return SSH_AUTH_ERROR;
        }
        ZERO_STRUCTP(session->agent_state);
        session->agent_state->state=SSH_AGENT_STATE_NONE;
    }

    state = session->agent_state;
    if (state->pubkey == NULL) {
        state->pubkey = ssh_agent_get_first_ident(session, &state->comment);
    }

    if (state->pubkey == NULL) {
        return SSH_AUTH_DENIED;
    }

    while (state->pubkey != NULL) {
        if (state->state == SSH_AGENT_STATE_NONE) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Trying identity %s", state->comment);
        }
        if (state->state == SSH_AGENT_STATE_NONE ||
                state->state == SSH_AGENT_STATE_PUBKEY) {
            rc = ssh_userauth_try_publickey(session, username, state->pubkey);
            if (rc == SSH_AUTH_ERROR) {
                ssh_agent_state_free (state);
                session->agent_state = NULL;
                return rc;
            } else if (rc == SSH_AUTH_AGAIN) {
                state->state = SSH_AGENT_STATE_PUBKEY;
                return rc;
            } else if (rc != SSH_AUTH_SUCCESS) {
                SSH_LOG(SSH_LOG_DEBUG,
                        "Public key of %s refused by server", state->comment);
                SSH_STRING_FREE_CHAR(state->comment);
                state->comment = NULL;
                ssh_key_free(state->pubkey);
                state->pubkey = ssh_agent_get_next_ident(session, &state->comment);
                state->state = SSH_AGENT_STATE_NONE;
                continue;
            }

            SSH_LOG(SSH_LOG_DEBUG,
                    "Public key of %s accepted by server", state->comment);
            state->state = SSH_AGENT_STATE_AUTH;
        }
        if (state->state == SSH_AGENT_STATE_AUTH) {
            rc = ssh_userauth_agent_publickey(session, username, state->pubkey);
            if (rc == SSH_AUTH_AGAIN)
                return rc;
            SSH_STRING_FREE_CHAR(state->comment);
            state->comment = NULL;
            if (rc == SSH_AUTH_ERROR || rc == SSH_AUTH_PARTIAL) {
                ssh_agent_state_free (session->agent_state);
                session->agent_state = NULL;
                return rc;
            } else if (rc != SSH_AUTH_SUCCESS) {
                SSH_LOG(SSH_LOG_INFO,
                        "Server accepted public key but refused the signature");
                ssh_key_free(state->pubkey);
                state->pubkey = ssh_agent_get_next_ident(session, &state->comment);
                state->state = SSH_AGENT_STATE_NONE;
                continue;
            }
            ssh_agent_state_free (session->agent_state);
            session->agent_state = NULL;
            return SSH_AUTH_SUCCESS;
        }
    }

    ssh_agent_state_free (session->agent_state);
    session->agent_state = NULL;
    return rc;
}
#endif

enum ssh_auth_auto_state_e {
    SSH_AUTH_AUTO_STATE_NONE = 0,
    SSH_AUTH_AUTO_STATE_PUBKEY,
    SSH_AUTH_AUTO_STATE_KEY_IMPORTED,
    SSH_AUTH_AUTO_STATE_PUBKEY_ACCEPTED
};

struct ssh_auth_auto_state_struct {
    enum ssh_auth_auto_state_e state;
    struct ssh_iterator *it;
    ssh_key privkey;
    ssh_key pubkey;
};

/**
 * @brief Tries to automatically authenticate with public key and "none"
 *
 * It may fail, for instance it doesn't ask for a password and uses a default
 * asker for passphrases (in case the private key is encrypted).
 *
 * @param[in]  session     The SSH session.
 *
 * @param[in]  username    The username, this SHOULD be NULL.
 *
 * @param[in]  passphrase  Use this passphrase to unlock the privatekey. Use NULL
 *                         if you don't want to use a passphrase or the user
 *                         should be asked.
 *
 * @return  SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  The server doesn't accept that public key as an
 *                            authentication token. Try another key or another
 *                            method.\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method.\n
 *          SSH_AUTH_SUCCESS: The public key is accepted, you want now to use
 *                            ssh_userauth_publickey().\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 */
int ssh_userauth_publickey_auto(ssh_session session,
                                const char *username,
                                const char *passphrase)
{
    ssh_auth_callback auth_fn = NULL;
    void *auth_data = NULL;
    struct ssh_auth_auto_state_struct *state;
    int rc;

    if (session == NULL) {
        return SSH_AUTH_ERROR;
    }
    if (! (session->opts.flags & SSH_OPT_FLAG_PUBKEY_AUTH)) {
        session->auth.supported_methods &= ~SSH_AUTH_METHOD_PUBLICKEY;
        return SSH_AUTH_DENIED;
    }
    if (session->common.callbacks) {
        auth_fn = session->common.callbacks->auth_function;
        auth_data = session->common.callbacks->userdata;
    }
    if (!session->auth.auto_state) {
        session->auth.auto_state =
                calloc(1, sizeof(struct ssh_auth_auto_state_struct));
        if (!session->auth.auto_state) {
            ssh_set_error_oom(session);
            return SSH_AUTH_ERROR;
        }

        /* Set state explicitly */
        session->auth.auto_state->state = SSH_AUTH_AUTO_STATE_NONE;
    }
    state = session->auth.auto_state;
    if (state->state == SSH_AUTH_AUTO_STATE_NONE) {
#ifndef _WIN32
        /* Try authentication with ssh-agent first */
        rc = ssh_userauth_agent(session, username);
        if (rc == SSH_AUTH_SUCCESS ||
            rc == SSH_AUTH_PARTIAL ||
            rc == SSH_AUTH_AGAIN ) {
            return rc;
        }
#endif
        state->state = SSH_AUTH_AUTO_STATE_PUBKEY;
    }
    if (state->it == NULL) {
        state->it = ssh_list_get_iterator(session->opts.identity);
    }

    while (state->it != NULL) {
        const char *privkey_file = state->it->data;
        char pubkey_file[1024] = {0};
        if (state->state == SSH_AUTH_AUTO_STATE_PUBKEY) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Trying to authenticate with %s", privkey_file);
            state->privkey = NULL;
            state->pubkey = NULL;
            snprintf(pubkey_file, sizeof(pubkey_file), "%s.pub", privkey_file);

            rc = ssh_pki_import_pubkey_file(pubkey_file, &state->pubkey);
            if (rc == SSH_ERROR) {
                ssh_set_error(session,
                        SSH_FATAL,
                        "Failed to import public key: %s",
                        pubkey_file);
                SAFE_FREE(session->auth.auto_state);
                return SSH_AUTH_ERROR;
            } else if (rc == SSH_EOF) {
                /* Read the private key and save the public key to file */
                rc = ssh_pki_import_privkey_file(privkey_file,
                        passphrase,
                        auth_fn,
                        auth_data,
                        &state->privkey);
                if (rc == SSH_ERROR) {
                    ssh_set_error(session,
                            SSH_FATAL,
                            "Failed to read private key: %s",
                            privkey_file);
                    state->it=state->it->next;
                    continue;
                } else if (rc == SSH_EOF) {
                    /* If the file doesn't exist, continue */
                    SSH_LOG(SSH_LOG_DEBUG,
                            "Private key %s doesn't exist.",
                            privkey_file);
                    state->it=state->it->next;
                    continue;
                }

                rc = ssh_pki_export_privkey_to_pubkey(state->privkey, &state->pubkey);
                if (rc == SSH_ERROR) {
                    ssh_key_free(state->privkey);
                    SAFE_FREE(session->auth.auto_state);
                    return SSH_AUTH_ERROR;
                }

                rc = ssh_pki_export_pubkey_file(state->pubkey, pubkey_file);
                if (rc == SSH_ERROR) {
                    SSH_LOG(SSH_LOG_WARN,
                            "Could not write public key to file: %s",
                            pubkey_file);
                }
            }
            state->state = SSH_AUTH_AUTO_STATE_KEY_IMPORTED;
        }
        if (state->state == SSH_AUTH_AUTO_STATE_KEY_IMPORTED) {
            rc = ssh_userauth_try_publickey(session, username, state->pubkey);
            if (rc == SSH_AUTH_ERROR) {
                SSH_LOG(SSH_LOG_WARN,
                        "Public key authentication error for %s",
                        privkey_file);
                ssh_key_free(state->privkey);
                state->privkey = NULL;
                ssh_key_free(state->pubkey);
                state->pubkey = NULL;
                SAFE_FREE(session->auth.auto_state);
                return rc;
            } else if (rc == SSH_AUTH_AGAIN) {
                return rc;
            } else if (rc != SSH_AUTH_SUCCESS) {
                SSH_LOG(SSH_LOG_DEBUG,
                        "Public key for %s refused by server",
                        privkey_file);
                ssh_key_free(state->privkey);
                state->privkey = NULL;
                ssh_key_free(state->pubkey);
                state->pubkey = NULL;
                state->it=state->it->next;
                state->state = SSH_AUTH_AUTO_STATE_PUBKEY;
                continue;
            }
            state->state = SSH_AUTH_AUTO_STATE_PUBKEY_ACCEPTED;
        }
        if (state->state == SSH_AUTH_AUTO_STATE_PUBKEY_ACCEPTED) {
            /* Public key has been accepted by the server */
            if (state->privkey == NULL) {
                rc = ssh_pki_import_privkey_file(privkey_file,
                        passphrase,
                        auth_fn,
                        auth_data,
                        &state->privkey);
                if (rc == SSH_ERROR) {
                    ssh_key_free(state->pubkey);
                    state->pubkey=NULL;
                    ssh_set_error(session,
                            SSH_FATAL,
                            "Failed to read private key: %s",
                            privkey_file);
                    state->it=state->it->next;
                    state->state = SSH_AUTH_AUTO_STATE_PUBKEY;
                    continue;
                } else if (rc == SSH_EOF) {
                    /* If the file doesn't exist, continue */
                    ssh_key_free(state->pubkey);
                    state->pubkey = NULL;
                    SSH_LOG(SSH_LOG_INFO,
                            "Private key %s doesn't exist.",
                            privkey_file);
                    state->it = state->it->next;
                    state->state = SSH_AUTH_AUTO_STATE_PUBKEY;
                    continue;
                }
            }

            rc = ssh_userauth_publickey(session, username, state->privkey);
            if (rc != SSH_AUTH_AGAIN && rc != SSH_AUTH_DENIED) {
                ssh_key_free(state->privkey);
                ssh_key_free(state->pubkey);
                SAFE_FREE(session->auth.auto_state);
                if (rc == SSH_AUTH_SUCCESS) {
                    SSH_LOG(SSH_LOG_INFO,
                            "Successfully authenticated using %s",
                            privkey_file);
                }
                return rc;
            }
            if (rc == SSH_AUTH_AGAIN) {
                return rc;
            }

            ssh_key_free(state->privkey);
            ssh_key_free(state->pubkey);

            SSH_LOG(SSH_LOG_WARN,
                    "The server accepted the public key but refused the signature");
            state->it = state->it->next;
            state->state = SSH_AUTH_AUTO_STATE_PUBKEY;
            /* continue */
        }
    }
    SSH_LOG(SSH_LOG_INFO,
            "Tried every public key, none matched");
    SAFE_FREE(session->auth.auto_state);
    return SSH_AUTH_DENIED;
}

/**
 * @brief Try to authenticate by password.
 *
 * This authentication method is normally disabled on SSHv2 server. You should
 * use keyboard-interactive mode.
 *
 * The 'password' value MUST be encoded UTF-8.  It is up to the server how to
 * interpret the password and validate it against the password database.
 * However, if you read the password in some other encoding, you MUST convert
 * the password to UTF-8.
 *
 * @param[in] session   The ssh session to use.
 *
 * @param[in] username  The username, this SHOULD be NULL.
 *
 * @param[in] password  The password to authenticate in UTF-8.
 *
 * @returns SSH_AUTH_ERROR:   A serious error happened.\n
 *          SSH_AUTH_DENIED:  Authentication failed: use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @note Most server implementations do not permit changing the username during
 * authentication. The username should only be set with ssh_options_set() only
 * before you connect to the server.
 *
 * @see ssh_userauth_none()
 * @see ssh_userauth_kbdint()
 */
int ssh_userauth_password(ssh_session session,
                          const char *username,
                          const char *password) {
    int rc;

    switch(session->pending_call_state) {
        case SSH_PENDING_CALL_NONE:
            break;
        case SSH_PENDING_CALL_AUTH_PASSWORD:
            goto pending;
        default:
            ssh_set_error(session,
                          SSH_FATAL,
                          "Wrong state (%d) during pending SSH call",
                          session->pending_call_state);
            return SSH_ERROR;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsssbs",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "password",
            0, /* false */
            password
    );
    if (rc < 0) {
        goto fail;
    }

    /* Set the buffer as secure to be explicitly zeroed when freed */
    ssh_buffer_set_secure(session->out_buffer);

    session->auth.current_method = SSH_AUTH_METHOD_PASSWORD;
    session->auth.state = SSH_AUTH_STATE_PASSWORD_AUTH_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_PASSWORD;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }

    return rc;
fail:
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

#ifndef _WIN32
/* LEGACY */
int ssh_userauth_agent_pubkey(ssh_session session,
                              const char *username,
                              ssh_public_key publickey)
{
    ssh_key key;
    int rc;

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_AUTH_ERROR;
    }

    key->type = publickey->type;
    key->type_c = ssh_key_type_to_char(key->type);
    key->flags = SSH_KEY_FLAG_PUBLIC;
    key->dsa = publickey->dsa_pub;
    key->rsa = publickey->rsa_pub;

    rc = ssh_userauth_agent_publickey(session, username, key);

    key->dsa = NULL;
    key->rsa = NULL;
    ssh_key_free(key);

    return rc;
}
#endif /* _WIN32 */

ssh_kbdint ssh_kbdint_new(void) {
    ssh_kbdint kbd;

    kbd = calloc(1, sizeof(struct ssh_kbdint_struct));
    if (kbd == NULL) {
        return NULL;
    }

    return kbd;
}


void ssh_kbdint_free(ssh_kbdint kbd) {
    size_t i, n;

    if (kbd == NULL) {
        return;
    }

    SAFE_FREE(kbd->name);
    SAFE_FREE(kbd->instruction);
    SAFE_FREE(kbd->echo);

    n = kbd->nprompts;
    if (kbd->prompts) {
        for (i = 0; i < n; i++) {
            if (kbd->prompts[i] != NULL) {
                explicit_bzero(kbd->prompts[i], strlen(kbd->prompts[i]));
            }
            SAFE_FREE(kbd->prompts[i]);
        }
        SAFE_FREE(kbd->prompts);
    }

    n = kbd->nanswers;
    if (kbd->answers) {
        for (i = 0; i < n; i++) {
            if (kbd->answers[i] != NULL) {
                explicit_bzero(kbd->answers[i], strlen(kbd->answers[i]));
            }
            SAFE_FREE(kbd->answers[i]);
        }
        SAFE_FREE(kbd->answers);
    }

    SAFE_FREE(kbd);
}

void ssh_kbdint_clean(ssh_kbdint kbd) {
    size_t i, n;

    if (kbd == NULL) {
        return;
    }

    SAFE_FREE(kbd->name);
    SAFE_FREE(kbd->instruction);
    SAFE_FREE(kbd->echo);

    n = kbd->nprompts;
    if (kbd->prompts) {
        for (i = 0; i < n; i++) {
            explicit_bzero(kbd->prompts[i], strlen(kbd->prompts[i]));
            SAFE_FREE(kbd->prompts[i]);
        }
        SAFE_FREE(kbd->prompts);
    }

    n = kbd->nanswers;

    if (kbd->answers) {
        for (i = 0; i < n; i++) {
            explicit_bzero(kbd->answers[i], strlen(kbd->answers[i]));
            SAFE_FREE(kbd->answers[i]);
        }
        SAFE_FREE(kbd->answers);
    }

    kbd->nprompts = 0;
    kbd->nanswers = 0;
}

/*
 * This function sends the first packet as explained in RFC 3066 section 3.1.
 */
static int ssh_userauth_kbdint_init(ssh_session session,
                                    const char *username,
                                    const char *submethods)
{
    int rc;

    if (session->pending_call_state == SSH_PENDING_CALL_AUTH_KBDINT_INIT) {
        goto pending;
    }
    if (session->pending_call_state != SSH_PENDING_CALL_NONE) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    }
    if (rc != SSH_OK) {
        return SSH_AUTH_ERROR;
    }

    /* request */
    rc = ssh_buffer_pack(session->out_buffer, "bsssss",
            SSH2_MSG_USERAUTH_REQUEST,
            username ? username : session->opts.username,
            "ssh-connection",
            "keyboard-interactive",
            "", /* lang (ignore it) */
            submethods ? submethods : ""
    );
    if (rc < 0) {
        goto fail;
    }


    session->auth.state = SSH_AUTH_STATE_KBDINT_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_KBDINT_INIT;

    SSH_LOG(SSH_LOG_DEBUG,
            "Sending keyboard-interactive init request");

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN)
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    return rc;
fail:
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

/**
 * @internal
 *
 * @brief Send the current challenge response and wait for a reply from the
 *        server.
 *
 * @returns SSH_AUTH_INFO if more info is needed
 * @returns SSH_AUTH_SUCCESS
 * @returns SSH_AUTH_FAILURE
 * @returns SSH_AUTH_PARTIAL
 */
static int ssh_userauth_kbdint_send(ssh_session session)
{
    uint32_t i;
    int rc;
    if (session->pending_call_state == SSH_PENDING_CALL_AUTH_KBDINT_SEND)
        goto pending;
    if (session->pending_call_state != SSH_PENDING_CALL_NONE) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }
    rc = ssh_buffer_pack(session->out_buffer, "bd",
            SSH2_MSG_USERAUTH_INFO_RESPONSE,
            session->kbdint->nprompts);
    if (rc < 0) {
        goto fail;
    }

    for (i = 0; i < session->kbdint->nprompts; i++) {
        rc = ssh_buffer_pack(session->out_buffer, "s",
                session->kbdint->answers && session->kbdint->answers[i] ?
                        session->kbdint->answers[i]:"");
        if (rc < 0) {
            goto fail;
        }
    }

    session->auth.current_method = SSH_AUTH_METHOD_INTERACTIVE;
    session->auth.state = SSH_AUTH_STATE_KBDINT_SENT;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_KBDINT_SEND;
    ssh_kbdint_free(session->kbdint);
    session->kbdint = NULL;

    SSH_LOG(SSH_LOG_DEBUG,
            "Sending keyboard-interactive response packet");

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN)
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    return rc;
fail:
    ssh_set_error_oom(session);
    ssh_buffer_reinit(session->out_buffer);

    return SSH_AUTH_ERROR;
}

/**
 * @internal
 * @brief handles a SSH_USERAUTH_INFO_REQUEST packet, as used in
 *        keyboard-interactive authentication, and changes the
 *        authentication state.
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_info_request) {
    ssh_string tmp = NULL;
    uint32_t nprompts;
    uint32_t i;
    int rc;
    (void)user;
    (void)type;


    if (session->kbdint == NULL) {
        session->kbdint = ssh_kbdint_new();
        if (session->kbdint == NULL) {
            ssh_set_error_oom(session);
            return SSH_PACKET_USED;
        }
    } else {
        ssh_kbdint_clean(session->kbdint);
    }

    rc = ssh_buffer_unpack(packet, "ssSd",
            &session->kbdint->name, /* name of the "asking" window shown to client */
            &session->kbdint->instruction,
            &tmp, /* to ignore */
            &nprompts
            );

    /* We don't care about tmp */
    SSH_STRING_FREE(tmp);

    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Invalid USERAUTH_INFO_REQUEST msg");
        ssh_kbdint_free(session->kbdint);
        session->kbdint = NULL;
        return SSH_PACKET_USED;
    }

    SSH_LOG(SSH_LOG_DEBUG,
            "%d keyboard-interactive prompts", nprompts);
    if (nprompts > KBDINT_MAX_PROMPT) {
        ssh_set_error(session, SSH_FATAL,
                "Too much prompts requested by the server: %u (0x%.4x)",
                nprompts, nprompts);
        ssh_kbdint_free(session->kbdint);
        session->kbdint = NULL;

        return SSH_PACKET_USED;
    }

    session->kbdint->nprompts = nprompts;
    session->kbdint->nanswers = nprompts;
    session->kbdint->prompts = calloc(nprompts, sizeof(char *));
    if (session->kbdint->prompts == NULL) {
        session->kbdint->nprompts = 0;
        ssh_set_error_oom(session);
        ssh_kbdint_free(session->kbdint);
        session->kbdint = NULL;

        return SSH_PACKET_USED;
    }

    session->kbdint->echo = calloc(nprompts, sizeof(unsigned char));
    if (session->kbdint->echo == NULL) {
        session->kbdint->nprompts = 0;
        ssh_set_error_oom(session);
        ssh_kbdint_free(session->kbdint);
        session->kbdint = NULL;

        return SSH_PACKET_USED;
    }

    for (i = 0; i < nprompts; i++) {
        rc = ssh_buffer_unpack(packet, "sb",
                &session->kbdint->prompts[i],
                &session->kbdint->echo[i]);
        if (rc == SSH_ERROR) {
            ssh_set_error(session, SSH_FATAL, "Short INFO_REQUEST packet");
            ssh_kbdint_free(session->kbdint);
            session->kbdint = NULL;

            return SSH_PACKET_USED;
        }
    }
    session->auth.state=SSH_AUTH_STATE_INFO;

    return SSH_PACKET_USED;
}

/**
 * @brief Try to authenticate through the "keyboard-interactive" method.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @param[in]  user     The username to authenticate. You can specify NULL if
 *                      ssh_option_set_username() has been used. You cannot try
 *                      two different logins in a row.
 *
 * @param[in]  submethods Undocumented. Set it to NULL.
 *
 * @returns SSH_AUTH_ERROR:   A serious error happened\n
 *          SSH_AUTH_DENIED:  Authentication failed : use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_INFO:    The server asked some questions. Use
 *                            ssh_userauth_kbdint_getnprompts() and such.\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 *
 * @see ssh_userauth_kbdint_getnprompts()
 * @see ssh_userauth_kbdint_getname()
 * @see ssh_userauth_kbdint_getinstruction()
 * @see ssh_userauth_kbdint_getprompt()
 * @see ssh_userauth_kbdint_setanswer()
 */
int ssh_userauth_kbdint(ssh_session session, const char *user,
    const char *submethods) {
    int rc = SSH_AUTH_ERROR;

    if (session == NULL) {
        return SSH_AUTH_ERROR;
    }

    if ((session->pending_call_state == SSH_PENDING_CALL_NONE && session->kbdint == NULL) ||
            session->pending_call_state == SSH_PENDING_CALL_AUTH_KBDINT_INIT)
        rc = ssh_userauth_kbdint_init(session, user, submethods);
    else if (session->pending_call_state == SSH_PENDING_CALL_AUTH_KBDINT_SEND ||
            session->kbdint != NULL) {
        /*
         * If we are at this point, it is because session->kbdint exists.
         * It means the user has set some information there we need to send
         * the server and then we need to ack the status (new questions or ok
         * pass in).
         * It is possible that session->kbdint is NULL while we're waiting for
         * a reply, hence the test for the pending call.
         */
        rc = ssh_userauth_kbdint_send(session);
    } else {
        /* We are here because session->kbdint == NULL & state != NONE.
         * This should not happen
         */
        rc = SSH_AUTH_ERROR;
        ssh_set_error(session, SSH_FATAL, "Invalid state in %s", __func__);
    }
    return rc;
}

/**
 * @brief Get the number of prompts (questions) the server has given.
 *
 * Once you have called ssh_userauth_kbdint() and received SSH_AUTH_INFO return
 * code, this function can be used to retrieve information about the keyboard
 * interactive authentication questions sent by the remote host.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @returns             The number of prompts.
 */
int ssh_userauth_kbdint_getnprompts(ssh_session session) {
    if (session == NULL) {
        return SSH_ERROR;
    }
    if (session->kbdint == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }
    return session->kbdint->nprompts;
}

/**
 * @brief Get the "name" of the message block.
 *
 * Once you have called ssh_userauth_kbdint() and received SSH_AUTH_INFO return
 * code, this function can be used to retrieve information about the keyboard
 * interactive authentication questions sent by the remote host.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @returns             The name of the message block. Do not free it.
 */
const char *ssh_userauth_kbdint_getname(ssh_session session) {
    if (session == NULL) {
        return NULL;
    }
    if (session->kbdint == NULL) {
        ssh_set_error_invalid(session);
        return NULL;
    }
    return session->kbdint->name;
}

/**
 * @brief Get the "instruction" of the message block.
 *
 * Once you have called ssh_userauth_kbdint() and received SSH_AUTH_INFO return
 * code, this function can be used to retrieve information about the keyboard
 * interactive authentication questions sent by the remote host.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @returns             The instruction of the message block.
 */

const char *ssh_userauth_kbdint_getinstruction(ssh_session session) {
    if (session == NULL)
        return NULL;
    if (session->kbdint == NULL) {
        ssh_set_error_invalid(session);
        return NULL;
    }
    return session->kbdint->instruction;
}

/**
 * @brief Get a prompt from a message block.
 *
 * Once you have called ssh_userauth_kbdint() and received SSH_AUTH_INFO return
 * code, this function can be used to retrieve information about the keyboard
 * interactive authentication questions sent by the remote host.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @param[in]  i        The index number of the i'th prompt.
 *
 * @param[out] echo     This is an optional variable. You can obtain a
 *                      boolean if the user input should be echoed or
 *                      hidden. For passwords it is usually hidden.
 *
 * @returns             A pointer to the prompt. Do not free it.
 *
 * @code
 *   const char prompt;
 *   char echo;
 *
 *   prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
 *   if (echo) ...
 * @endcode
 */
const char *ssh_userauth_kbdint_getprompt(ssh_session session, unsigned int i,
    char *echo) {
    if (session == NULL)
        return NULL;
    if (session->kbdint == NULL) {
        ssh_set_error_invalid(session);
        return NULL;
    }
    if (i > session->kbdint->nprompts) {
        ssh_set_error_invalid(session);
        return NULL;
    }

    if (echo) {
        *echo = (char)session->kbdint->echo[i];
    }

    return session->kbdint->prompts[i];
}

#ifdef WITH_SERVER
/**
 * @brief Get the number of answers the client has given.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @returns             The number of answers.
 */
int ssh_userauth_kbdint_getnanswers(ssh_session session) {
    if (session == NULL || session->kbdint == NULL) {
        return SSH_ERROR;
    }
    return session->kbdint->nanswers;
}

/**
 * @brief Get the answer for a question from a message block.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @param[in]  i index  The number of the ith answer.
 *
 * @return              0 on success, < 0 on error.
 */
const char *ssh_userauth_kbdint_getanswer(ssh_session session, unsigned int i) {
    if (session == NULL || session->kbdint == NULL
            || session->kbdint->answers == NULL) {
        return NULL;
    }
    if (i >= session->kbdint->nanswers) {
        return NULL;
    }

    return session->kbdint->answers[i];
}
#endif

/**
 * @brief Set the answer for a question from a message block.
 *
 * If you have called ssh_userauth_kbdint() and got SSH_AUTH_INFO, this
 * function returns the questions from the server.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @param[in]  i index  The number of the ith prompt.
 *
 * @param[in]  answer   The answer to give to the server. The answer MUST be
 *                      encoded UTF-8. It is up to the server how to interpret
 *                      the value and validate it. However, if you read the
 *                      answer in some other encoding, you MUST convert it to
 *                      UTF-8.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_userauth_kbdint_setanswer(ssh_session session, unsigned int i,
    const char *answer) {
    if (session == NULL) {
        return -1;
    }
    if (answer == NULL || session->kbdint == NULL ||
            i >= session->kbdint->nprompts) {
        ssh_set_error_invalid(session);
        return -1;
    }

    if (session->kbdint->answers == NULL) {
        session->kbdint->answers = calloc(session->kbdint->nprompts, sizeof(char *));
        if (session->kbdint->answers == NULL) {
            ssh_set_error_oom(session);
            return -1;
        }
    }

    if (session->kbdint->answers[i]) {
        explicit_bzero(session->kbdint->answers[i],
                strlen(session->kbdint->answers[i]));
        SAFE_FREE(session->kbdint->answers[i]);
    }

    session->kbdint->answers[i] = strdup(answer);
    if (session->kbdint->answers[i] == NULL) {
        ssh_set_error_oom(session);
        return -1;
    }

    return 0;
}

/**
 * @brief Try to authenticate through the "gssapi-with-mic" method.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @returns SSH_AUTH_ERROR:   A serious error happened\n
 *          SSH_AUTH_DENIED:  Authentication failed : use another method\n
 *          SSH_AUTH_PARTIAL: You've been partially authenticated, you still
 *                            have to use another method\n
 *          SSH_AUTH_SUCCESS: Authentication success\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 */
int ssh_userauth_gssapi(ssh_session session) {
    int rc = SSH_AUTH_DENIED;
#ifdef WITH_GSSAPI
    switch(session->pending_call_state) {
    case SSH_PENDING_CALL_NONE:
        break;
    case SSH_PENDING_CALL_AUTH_GSSAPI_MIC:
        goto pending;
    default:
        ssh_set_error(session,
                SSH_FATAL,
                "Wrong state (%d) during pending SSH call",
                session->pending_call_state);
        return SSH_ERROR;
    }

    rc = ssh_userauth_request_service(session);
    if (rc == SSH_AGAIN) {
        return SSH_AUTH_AGAIN;
    } else if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "Authenticating with gssapi-with-mic");

    session->auth.current_method = SSH_AUTH_METHOD_GSSAPI_MIC;
    session->auth.state = SSH_AUTH_STATE_NONE;
    session->pending_call_state = SSH_PENDING_CALL_AUTH_GSSAPI_MIC;
    rc = ssh_gssapi_auth_mic(session);

    if (rc == SSH_AUTH_ERROR || rc == SSH_AUTH_DENIED) {
        session->auth.state = SSH_AUTH_STATE_NONE;
        session->pending_call_state = SSH_PENDING_CALL_NONE;
        return rc;
    }

pending:
    rc = ssh_userauth_get_response(session);
    if (rc != SSH_AUTH_AGAIN) {
        session->pending_call_state = SSH_PENDING_CALL_NONE;
    }
#else
    (void) session; /* unused */
#endif
    return rc;
}

/** @} */
