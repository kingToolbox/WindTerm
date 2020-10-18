/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Aris Adamantiadis <aris@badcode.be>
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gssapi/gssapi.h>

#include <libssh/gssapi.h>
#include <libssh/libssh.h>
#include <libssh/ssh2.h>
#include <libssh/buffer.h>
#include <libssh/crypto.h>
#include <libssh/callbacks.h>
#include <libssh/string.h>
#include <libssh/server.h>

/** current state of an GSSAPI authentication */
enum ssh_gssapi_state_e {
    SSH_GSSAPI_STATE_NONE, /* no status */
    SSH_GSSAPI_STATE_RCV_TOKEN, /* Expecting a token */
    SSH_GSSAPI_STATE_RCV_MIC, /* Expecting a MIC */
};

struct ssh_gssapi_struct{
    enum ssh_gssapi_state_e state; /* current state */
    struct gss_OID_desc_struct mech; /* mechanism being elected for auth */
    gss_cred_id_t server_creds; /* credentials of server */
    gss_cred_id_t client_creds; /* creds delegated by the client */
    gss_ctx_id_t ctx; /* the authentication context */
    gss_name_t client_name; /* Identity of the client */
    char *user; /* username of client */
    char *canonic_user; /* canonic form of the client's username */
    char *service; /* name of the service */
    struct {
        gss_name_t server_name; /* identity of server */
        OM_uint32 flags; /* flags used for init context */
        gss_OID oid; /* mech being used for authentication */
        gss_cred_id_t creds; /* creds used to initialize context */
        gss_cred_id_t client_deleg_creds; /* delegated creds (const, not freeable) */
    } client;
};


/** @internal
 * @initializes a gssapi context for authentication
 */
static int ssh_gssapi_init(ssh_session session){
    if (session->gssapi != NULL)
        return SSH_OK;
    session->gssapi = malloc(sizeof(struct ssh_gssapi_struct));
    if(!session->gssapi){
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    ZERO_STRUCTP(session->gssapi);
    session->gssapi->server_creds = GSS_C_NO_CREDENTIAL;
    session->gssapi->client_creds = GSS_C_NO_CREDENTIAL;
    session->gssapi->ctx = GSS_C_NO_CONTEXT;
    session->gssapi->state = SSH_GSSAPI_STATE_NONE;
    return SSH_OK;
}

/** @internal
 * @frees a gssapi context
 */
static void ssh_gssapi_free(ssh_session session){
    OM_uint32 min;
    if (session->gssapi == NULL)
        return;
    SAFE_FREE(session->gssapi->user);
    SAFE_FREE(session->gssapi->mech.elements);
    gss_release_cred(&min,&session->gssapi->server_creds);
    if (session->gssapi->client.creds !=
                    session->gssapi->client.client_deleg_creds) {
        gss_release_cred(&min, &session->gssapi->client.creds);
    }
    SAFE_FREE(session->gssapi);
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token){
#ifdef WITH_SERVER
    if(session->server)
        return ssh_packet_userauth_gssapi_token_server(session, type, packet, user);
#endif
    return ssh_packet_userauth_gssapi_token_client(session, type, packet, user);
}
#ifdef WITH_SERVER

/** @internal
 * @brief sends a SSH_MSG_USERAUTH_GSSAPI_RESPONSE packet
 * @param[in] oid the OID that was selected for authentication
 */
static int ssh_gssapi_send_response(ssh_session session, ssh_string oid){
    if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE) < 0 ||
            ssh_buffer_add_ssh_string(session->out_buffer,oid) < 0) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    session->auth.state = SSH_AUTH_STATE_GSSAPI_TOKEN;

    ssh_packet_send(session);
    SSH_LOG(SSH_LOG_PACKET,
            "Sent SSH_MSG_USERAUTH_GSSAPI_RESPONSE");
    return SSH_OK;
}

#endif /* WITH_SERVER */

static void ssh_gssapi_log_error(int verb,
                                 const char *msg,
                                 int maj_stat,
                                 int min_stat)
{
    gss_buffer_desc msg_maj = {
        .length = 0,
    };
    gss_buffer_desc msg_min = {
        .length = 0,
    };
    OM_uint32 dummy_maj, dummy_min;
    OM_uint32 message_context = 0;

    dummy_maj = gss_display_status(&dummy_min,
                                   maj_stat,
                                   GSS_C_GSS_CODE,
                                   GSS_C_NO_OID,
                                   &message_context,
                                   &msg_maj);
    if (dummy_maj != 0) {
        goto out;
    }

    dummy_maj = gss_display_status(&dummy_min,
                                   min_stat,
                                   GSS_C_MECH_CODE,
                                   GSS_C_NO_OID,
                                   &message_context,
                                   &msg_min);
    if (dummy_maj != 0) {
        goto out;
    }

    SSH_LOG(verb,
            "GSSAPI(%s): %s - %s",
            msg,
            (const char *)msg_maj.value,
            (const char *)msg_min.value);

out:
    if (msg_maj.value) {
        gss_release_buffer(&dummy_min, &msg_maj);
    }
    if (msg_min.value) {
        gss_release_buffer(&dummy_min, &msg_min);
    }
}

#ifdef WITH_SERVER

/** @internal
 * @brief handles an user authentication using GSSAPI
 */
int ssh_gssapi_handle_userauth(ssh_session session, const char *user, uint32_t n_oid, ssh_string *oids){
    char service_name[]="host";
    gss_buffer_desc name_buf;
    gss_name_t server_name; /* local server fqdn */
    OM_uint32 maj_stat, min_stat;
    size_t i;
    char *ptr;
    gss_OID_set supported; /* oids supported by server */
    gss_OID_set both_supported; /* oids supported by both client and server */
    gss_OID_set selected; /* oid selected for authentication */
    int present=0;
    size_t oid_count=0;
    struct gss_OID_desc_struct oid;
    int rc;

    if (ssh_callbacks_exists(session->server_callbacks, gssapi_select_oid_function)){
        ssh_string oid_s = session->server_callbacks->gssapi_select_oid_function(session,
                user, n_oid, oids,
                session->server_callbacks->userdata);
        if (oid_s != NULL){
            if (ssh_gssapi_init(session) == SSH_ERROR)
                return SSH_ERROR;
            session->gssapi->state = SSH_GSSAPI_STATE_RCV_TOKEN;
            rc = ssh_gssapi_send_response(session, oid_s);
            SSH_STRING_FREE(oid_s);
            return rc;
        } else {
            return ssh_auth_reply_default(session,0);
        }
    }
    gss_create_empty_oid_set(&min_stat, &both_supported);

    maj_stat = gss_indicate_mechs(&min_stat, &supported);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(SSH_LOG_WARNING, "indicate mecks %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "indicate mechs",
                             maj_stat,
                             min_stat);
        return SSH_ERROR;
    }

    for (i=0; i < supported->count; ++i){
        ptr = ssh_get_hexa(supported->elements[i].elements, supported->elements[i].length);
        SSH_LOG(SSH_LOG_DEBUG, "Supported mech %zu: %s", i, ptr);
        free(ptr);
    }

    for (i=0 ; i< n_oid ; ++i){
        unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
        size_t len = ssh_string_len(oids[i]);

        if (oid_s == NULL) {
            continue;
        }
        if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
            SSH_LOG(SSH_LOG_WARNING,"GSSAPI: received invalid OID");
            continue;
        }
        oid.elements = &oid_s[2];
        oid.length = len - 2;
        gss_test_oid_set_member(&min_stat,&oid,supported,&present);
        if(present){
            gss_add_oid_set_member(&min_stat,&oid,&both_supported);
            oid_count++;
        }
    }
    gss_release_oid_set(&min_stat, &supported);
    if (oid_count == 0){
        SSH_LOG(SSH_LOG_PROTOCOL,"GSSAPI: no OID match");
        ssh_auth_reply_default(session, 0);
        gss_release_oid_set(&min_stat, &both_supported);
        return SSH_OK;
    }
    /* from now we have room for context */
    if (ssh_gssapi_init(session) == SSH_ERROR)
        return SSH_ERROR;

    name_buf.value = service_name;
    name_buf.length = strlen(name_buf.value) + 1;
    maj_stat = gss_import_name(&min_stat, &name_buf,
            (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &server_name);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(SSH_LOG_WARNING, "importing name %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "importing name",
                             maj_stat,
                             min_stat);
        return -1;
    }

    maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
            both_supported, GSS_C_ACCEPT,
            &session->gssapi->server_creds, &selected, NULL);
    gss_release_name(&min_stat, &server_name);
    gss_release_oid_set(&min_stat, &both_supported);

    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(SSH_LOG_WARNING, "error acquiring credentials %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "acquiring creds",
                             maj_stat,
                             min_stat);
        ssh_auth_reply_default(session,0);
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "acquiring credentials %d, %d", maj_stat, min_stat);

    /* finding which OID from client we selected */
    for (i=0 ; i< n_oid ; ++i){
        unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
        size_t len = ssh_string_len(oids[i]);

        if (oid_s == NULL) {
            continue;
        }
        if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
            SSH_LOG(SSH_LOG_WARNING,"GSSAPI: received invalid OID");
            continue;
        }
        oid.elements = &oid_s[2];
        oid.length = len - 2;
        gss_test_oid_set_member(&min_stat,&oid,selected,&present);
        if(present){
            SSH_LOG(SSH_LOG_PACKET, "Selected oid %zu", i);
            break;
        }
    }
    session->gssapi->mech.length = oid.length;
    session->gssapi->mech.elements = malloc(oid.length);
    if (session->gssapi->mech.elements == NULL){
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    memcpy(session->gssapi->mech.elements, oid.elements, oid.length);
    gss_release_oid_set(&min_stat, &selected);
    session->gssapi->user = strdup(user);
    session->gssapi->service = service_name;
    session->gssapi->state = SSH_GSSAPI_STATE_RCV_TOKEN;
    return ssh_gssapi_send_response(session, oids[i]);
}

static char *ssh_gssapi_name_to_char(gss_name_t name){
    gss_buffer_desc buffer;
    OM_uint32 maj_stat, min_stat;
    char *ptr;
    maj_stat = gss_display_name(&min_stat, name, &buffer, NULL);
    ssh_gssapi_log_error(SSH_LOG_WARNING,
                         "converting name",
                         maj_stat,
                         min_stat);
    ptr = malloc(buffer.length + 1);
    if (ptr == NULL) {
        return NULL;
    }
    memcpy(ptr, buffer.value, buffer.length);
    ptr[buffer.length] = '\0';
    gss_release_buffer(&min_stat, &buffer);
    return ptr;

}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_server){
    ssh_string token;
    char *hexa;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    OM_uint32 ret_flags=0;
    gss_channel_bindings_t input_bindings=GSS_C_NO_CHANNEL_BINDINGS;
    int rc;

    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_TOKEN");
    if (!session->gssapi || session->gssapi->state != SSH_GSSAPI_STATE_RCV_TOKEN){
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_TOKEN in invalid state");
        return SSH_PACKET_USED;
    }
    token = ssh_buffer_get_ssh_string(packet);

    if (token == NULL){
        ssh_set_error(session, SSH_REQUEST_DENIED, "ssh_packet_userauth_gssapi_token: invalid packet");
        return SSH_PACKET_USED;
    }

    if (ssh_callbacks_exists(session->server_callbacks, gssapi_accept_sec_ctx_function)){
        ssh_string out_token=NULL;
        rc = session->server_callbacks->gssapi_accept_sec_ctx_function(session,
                token, &out_token, session->server_callbacks->userdata);
        if (rc == SSH_ERROR){
            ssh_auth_reply_default(session, 0);
            ssh_gssapi_free(session);
            session->gssapi=NULL;
            return SSH_PACKET_USED;
        }
        if (ssh_string_len(out_token) != 0){
            rc = ssh_buffer_pack(session->out_buffer,
                                 "bS",
                                 SSH2_MSG_USERAUTH_GSSAPI_TOKEN,
                                 out_token);
            if (rc != SSH_OK) {
                ssh_set_error_oom(session);
                return SSH_PACKET_USED;
            }
            ssh_packet_send(session);
            SSH_STRING_FREE(out_token);
        } else {
            session->gssapi->state = SSH_GSSAPI_STATE_RCV_MIC;
        }
        return SSH_PACKET_USED;
    }
    hexa = ssh_get_hexa(ssh_string_data(token),ssh_string_len(token));
    SSH_LOG(SSH_LOG_PACKET, "GSSAPI Token : %s",hexa);
    SAFE_FREE(hexa);
    input_token.length = ssh_string_len(token);
    input_token.value = ssh_string_data(token);

    maj_stat = gss_accept_sec_context(&min_stat, &session->gssapi->ctx, session->gssapi->server_creds,
            &input_token, input_bindings, &client_name, NULL /*mech_oid*/, &output_token, &ret_flags,
            NULL /*time*/, &session->gssapi->client_creds);
    ssh_gssapi_log_error(SSH_LOG_PROTOCOL,
                         "accepting token",
                         maj_stat,
                         min_stat);
    SSH_STRING_FREE(token);
    if (client_name != GSS_C_NO_NAME){
        session->gssapi->client_name = client_name;
        session->gssapi->canonic_user = ssh_gssapi_name_to_char(client_name);
    }
    if (GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "Gssapi error",
                             maj_stat,
                             min_stat);
        ssh_auth_reply_default(session,0);
        ssh_gssapi_free(session);
        session->gssapi=NULL;
        return SSH_PACKET_USED;
    }

    if (output_token.length != 0){
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
        SAFE_FREE(hexa);
        ssh_buffer_pack(session->out_buffer,
                        "bdP",
                        SSH2_MSG_USERAUTH_GSSAPI_TOKEN,
                        output_token.length,
                        (size_t)output_token.length, output_token.value);
        ssh_packet_send(session);
    }
    if(maj_stat == GSS_S_COMPLETE){
        session->gssapi->state = SSH_GSSAPI_STATE_RCV_MIC;
    }
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

static ssh_buffer ssh_gssapi_build_mic(ssh_session session)
{
    struct ssh_crypto_struct *crypto = NULL;
    ssh_buffer mic_buffer = NULL;
    int rc;

    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_BOTH);
    if (crypto == NULL) {
        return NULL;
    }

    mic_buffer = ssh_buffer_new();
    if (mic_buffer == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    rc = ssh_buffer_pack(mic_buffer,
                         "dPbsss",
                         crypto->digest_len,
                         (size_t)crypto->digest_len, crypto->session_id,
                         SSH2_MSG_USERAUTH_REQUEST,
                         session->gssapi->user,
                         "ssh-connection",
                         "gssapi-with-mic");
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        SSH_BUFFER_FREE(mic_buffer);
        return NULL;
    }

    return mic_buffer;
}

#ifdef WITH_SERVER

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic)
{
    ssh_string mic_token;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mic_token_buf = GSS_C_EMPTY_BUFFER;
    ssh_buffer mic_buffer = NULL;

    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_MIC");
    mic_token = ssh_buffer_get_ssh_string(packet);
    if (mic_token == NULL) {
        ssh_set_error(session, SSH_FATAL, "Missing MIC in packet");
        goto error;
    }
    if (session->gssapi == NULL
        || session->gssapi->state != SSH_GSSAPI_STATE_RCV_MIC) {
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_MIC in invalid state");
        goto error;
    }

    mic_buffer = ssh_gssapi_build_mic(session);
    if (mic_buffer == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    if (ssh_callbacks_exists(session->server_callbacks, gssapi_verify_mic_function)){
        int rc = session->server_callbacks->gssapi_verify_mic_function(session, mic_token,
                ssh_buffer_get(mic_buffer), ssh_buffer_get_len(mic_buffer),
                session->server_callbacks->userdata);
        if (rc != SSH_OK) {
            goto error;
        }
    } else {
        mic_buf.length = ssh_buffer_get_len(mic_buffer);
        mic_buf.value = ssh_buffer_get(mic_buffer);
        mic_token_buf.length = ssh_string_len(mic_token);
        mic_token_buf.value = ssh_string_data(mic_token);

        maj_stat = gss_verify_mic(&min_stat, session->gssapi->ctx, &mic_buf, &mic_token_buf, NULL);
        ssh_gssapi_log_error(SSH_LOG_PROTOCOL,
                             "verifying MIC",
                             maj_stat,
                             min_stat);
        if (maj_stat == GSS_S_DEFECTIVE_TOKEN || GSS_ERROR(maj_stat)) {
            goto error;
        }
    }

    if (ssh_callbacks_exists(session->server_callbacks, auth_gssapi_mic_function)){
        switch(session->server_callbacks->auth_gssapi_mic_function(session,
                    session->gssapi->user, session->gssapi->canonic_user,
                    session->server_callbacks->userdata)){
            case SSH_AUTH_SUCCESS:
                ssh_auth_reply_success(session, 0);
                break;
            case SSH_AUTH_PARTIAL:
                ssh_auth_reply_success(session, 1);
                break;
            default:
                ssh_auth_reply_default(session, 0);
                break;
        }
    }

    goto end;

error:
    ssh_auth_reply_default(session,0);

end:
    ssh_gssapi_free(session);
    if (mic_buffer != NULL) {
        SSH_BUFFER_FREE(mic_buffer);
    }
    if (mic_token != NULL) {
        SSH_STRING_FREE(mic_token);
    }

    return SSH_PACKET_USED;
}

/** @brief returns the client credentials of the connected client.
 * If the client has given a forwardable token, the SSH server will
 * retrieve it.
 * @returns gssapi credentials handle.
 * @returns NULL if no forwardable token is available.
 */
ssh_gssapi_creds ssh_gssapi_get_creds(ssh_session session){
    if (!session || !session->gssapi || session->gssapi->client_creds == GSS_C_NO_CREDENTIAL)
        return NULL;
    return (ssh_gssapi_creds)session->gssapi->client_creds;
}

#endif /* SERVER */

/**
 * @brief Set the forwadable ticket to be given to the server for authentication.
 * Unlike ssh_gssapi_get_creds() this is called on the client side of an ssh
 * connection.
 *
 * @param[in] creds gssapi credentials handle.
 */
void ssh_gssapi_set_creds(ssh_session session, const ssh_gssapi_creds creds)
{
    if (session == NULL) {
        return;
    }
    if (session->gssapi == NULL) {
        ssh_gssapi_init(session);
        if (session->gssapi == NULL) {
            return;
        }
    }

    session->gssapi->client.client_deleg_creds = (gss_cred_id_t)creds;
}

static int ssh_gssapi_send_auth_mic(ssh_session session, ssh_string *oid_set, int n_oid){
    int rc;
    int i;

    rc = ssh_buffer_pack(session->out_buffer,
                         "bsssd",
                         SSH2_MSG_USERAUTH_REQUEST,
                         session->opts.username,
                         "ssh-connection",
                         "gssapi-with-mic",
                         n_oid);

    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        goto fail;
    }

    for (i=0; i<n_oid; ++i){
        rc = ssh_buffer_add_ssh_string(session->out_buffer, oid_set[i]);
        if (rc < 0) {
            goto fail;
        }
    }

    session->auth.state = SSH_AUTH_STATE_GSSAPI_REQUEST_SENT;
    return ssh_packet_send(session);
fail:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/** @brief returns the OIDs of the mechs that have usable credentials
 */
static int ssh_gssapi_match(ssh_session session, gss_OID_set *valid_oids)
{
    OM_uint32 maj_stat, min_stat, lifetime;
    gss_OID_set actual_mechs;
    gss_buffer_desc namebuf;
    gss_name_t client_id = GSS_C_NO_NAME;
    gss_OID oid;
    unsigned int i;
    char *ptr;
    int ret;

    if (session->gssapi->client.client_deleg_creds == NULL) {
        if (session->opts.gss_client_identity != NULL) {
            namebuf.value = (void *)session->opts.gss_client_identity;
            namebuf.length = strlen(session->opts.gss_client_identity);

            maj_stat = gss_import_name(&min_stat, &namebuf,
                                       GSS_C_NT_USER_NAME, &client_id);
            if (GSS_ERROR(maj_stat)) {
                ret = SSH_ERROR;
                goto end;
            }
        }

        maj_stat = gss_acquire_cred(&min_stat, client_id, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                    &session->gssapi->client.creds,
                                    &actual_mechs, NULL);
        if (GSS_ERROR(maj_stat)) {
            ret = SSH_ERROR;
            goto end;
        }
    } else {
        session->gssapi->client.creds =
                                    session->gssapi->client.client_deleg_creds;

        maj_stat = gss_inquire_cred(&min_stat, session->gssapi->client.creds,
                                    &client_id, NULL, NULL, &actual_mechs);
        if (GSS_ERROR(maj_stat)) {
            ret = SSH_ERROR;
            goto end;
        }
    }

    gss_create_empty_oid_set(&min_stat, valid_oids);

    /* double check each single cred */
    for (i = 0; i < actual_mechs->count; i++) {
        /* check lifetime is not 0 or skip */
        lifetime = 0;
        oid = &actual_mechs->elements[i];
        maj_stat = gss_inquire_cred_by_mech(&min_stat,
                                            session->gssapi->client.creds,
                                            oid, NULL, &lifetime, NULL, NULL);
        if (maj_stat == GSS_S_COMPLETE && lifetime > 0) {
            gss_add_oid_set_member(&min_stat, oid, valid_oids);
            ptr = ssh_get_hexa(oid->elements, oid->length);
            SSH_LOG(SSH_LOG_DEBUG, "GSSAPI valid oid %d : %s", i, ptr);
            SAFE_FREE(ptr);
        }
    }

    ret = SSH_OK;

end:
    gss_release_name(&min_stat, &client_id);
    return ret;
}

/**
 * @brief launches a gssapi-with-mic auth request
 * @returns SSH_AUTH_ERROR:   A serious error happened\n
 *          SSH_AUTH_DENIED:  Authentication failed : use another method\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 */
int ssh_gssapi_auth_mic(ssh_session session){
    size_t i;
    gss_OID_set selected; /* oid selected for authentication */
    ssh_string *oids = NULL;
    int rc;
    size_t n_oids = 0;
    OM_uint32 maj_stat, min_stat;
    char name_buf[256] = {0};
    gss_buffer_desc hostname;
    const char *gss_host = session->opts.host;

    rc = ssh_gssapi_init(session);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_ERROR;
    }

    if (session->opts.gss_server_identity != NULL) {
        gss_host = session->opts.gss_server_identity;
    }
    /* import target host name */
    snprintf(name_buf, sizeof(name_buf), "host@%s", gss_host);

    hostname.value = name_buf;
    hostname.length = strlen(name_buf) + 1;
    maj_stat = gss_import_name(&min_stat, &hostname,
                               (gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
                               &session->gssapi->client.server_name);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(SSH_LOG_WARNING, "importing name %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "importing name",
                             maj_stat,
                             min_stat);
        return SSH_AUTH_DENIED;
    }

    /* copy username */
    session->gssapi->user = strdup(session->opts.username);
    if (session->gssapi->user == NULL) {
        ssh_set_error_oom(session);
        return SSH_AUTH_ERROR;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "Authenticating with gssapi to host %s with user %s",
            session->opts.host, session->gssapi->user);
    rc = ssh_gssapi_match(session, &selected);
    if (rc == SSH_ERROR) {
        return SSH_AUTH_DENIED;
    }

    n_oids = selected->count;
    SSH_LOG(SSH_LOG_PROTOCOL, "Sending %zu oids", n_oids);

    oids = calloc(n_oids, sizeof(ssh_string));
    if (oids == NULL) {
        ssh_set_error_oom(session);
        return SSH_AUTH_ERROR;
    }

    for (i=0; i<n_oids; ++i){
        oids[i] = ssh_string_new(selected->elements[i].length + 2);
        if (oids[i] == NULL) {
            ssh_set_error_oom(session);
            rc = SSH_ERROR;
            goto out;
        }
        ((unsigned char *)oids[i]->data)[0] = SSH_OID_TAG;
        ((unsigned char *)oids[i]->data)[1] = selected->elements[i].length;
        memcpy((unsigned char *)oids[i]->data + 2, selected->elements[i].elements,
                selected->elements[i].length);
    }

    rc = ssh_gssapi_send_auth_mic(session, oids, n_oids);

out:
    for (i = 0; i < n_oids; i++) {
        SSH_STRING_FREE(oids[i]);
    }
    free(oids);
    if (rc != SSH_ERROR) {
        return SSH_AUTH_AGAIN;
    }

    return SSH_AUTH_ERROR;
}

static gss_OID ssh_gssapi_oid_from_string(ssh_string oid_s)
{
    gss_OID ret = NULL;
    unsigned char *data = ssh_string_data(oid_s);
    size_t len = ssh_string_len(oid_s);

    if (data == NULL) {
        return NULL;
    }

    if (len > 256 || len <= 2) {
        SAFE_FREE(ret);
        return NULL;
    }

    if (data[0] != SSH_OID_TAG || data[1] != len - 2) {
        SAFE_FREE(ret);
        return NULL;
    }

    ret = malloc(sizeof(gss_OID_desc));
    if (ret == NULL) {
        return NULL;
    }

    ret->elements = malloc(len - 2);
    if (ret->elements == NULL) {
        SAFE_FREE(ret);
        return NULL;
    }
    memcpy(ret->elements, &data[2], len-2);
    ret->length = len-2;

    return ret;
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_response){
    ssh_string oid_s;
    gss_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    char *hexa;
    (void)type;
    (void)user;

    SSH_LOG(SSH_LOG_PACKET, "Received SSH_USERAUTH_GSSAPI_RESPONSE");
    if (session->auth.state != SSH_AUTH_STATE_GSSAPI_REQUEST_SENT){
        ssh_set_error(session, SSH_FATAL, "Invalid state in ssh_packet_userauth_gssapi_response");
        goto error;
    }

    oid_s = ssh_buffer_get_ssh_string(packet);
    if (!oid_s){
        ssh_set_error(session, SSH_FATAL, "Missing OID");
        goto error;
    }
    session->gssapi->client.oid = ssh_gssapi_oid_from_string(oid_s);
    SSH_STRING_FREE(oid_s);
    if (!session->gssapi->client.oid) {
        ssh_set_error(session, SSH_FATAL, "Invalid OID");
        goto error;
    }

    session->gssapi->client.flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
    if (session->opts.gss_delegate_creds) {
        session->gssapi->client.flags |= GSS_C_DELEG_FLAG;
    }

    /* prepare the first TOKEN response */
    maj_stat = gss_init_sec_context(&min_stat,
                                    session->gssapi->client.creds,
                                    &session->gssapi->ctx,
                                    session->gssapi->client.server_name,
                                    session->gssapi->client.oid,
                                    session->gssapi->client.flags,
                                    0, NULL, &input_token, NULL,
                                    &output_token, NULL, NULL);
    if(GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_WARNING,
                             "Initializing gssapi context",
                             maj_stat,
                             min_stat);
        goto error;
    }
    if (output_token.length != 0){
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s", hexa);
        SAFE_FREE(hexa);
        ssh_buffer_pack(session->out_buffer,
                        "bdP",
                        SSH2_MSG_USERAUTH_GSSAPI_TOKEN,
                        output_token.length,
                        (size_t)output_token.length, output_token.value);
        ssh_packet_send(session);
        session->auth.state = SSH_AUTH_STATE_GSSAPI_TOKEN;
    }
    return SSH_PACKET_USED;

error:
    session->auth.state = SSH_AUTH_STATE_ERROR;
    ssh_gssapi_free(session);
    session->gssapi = NULL;
    return SSH_PACKET_USED;
}

static int ssh_gssapi_send_mic(ssh_session session){
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mic_token_buf = GSS_C_EMPTY_BUFFER;
    ssh_buffer mic_buffer;
    int rc;

    SSH_LOG(SSH_LOG_PACKET,"Sending SSH_MSG_USERAUTH_GSSAPI_MIC");

    mic_buffer = ssh_gssapi_build_mic(session);
    if (mic_buffer == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    mic_buf.length = ssh_buffer_get_len(mic_buffer);
    mic_buf.value = ssh_buffer_get(mic_buffer);

    maj_stat = gss_get_mic(&min_stat,session->gssapi->ctx, GSS_C_QOP_DEFAULT,
                           &mic_buf, &mic_token_buf);
    if (GSS_ERROR(maj_stat)){
        SSH_BUFFER_FREE(mic_buffer);
        ssh_gssapi_log_error(SSH_LOG_PROTOCOL,
                             "generating MIC",
                             maj_stat,
                             min_stat);
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bdP",
                         SSH2_MSG_USERAUTH_GSSAPI_MIC,
                         mic_token_buf.length,
                         (size_t)mic_token_buf.length, mic_token_buf.value);
    if (rc != SSH_OK) {
        SSH_BUFFER_FREE(mic_buffer);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    return ssh_packet_send(session);
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_client){
    ssh_string token;
    char *hexa;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;
    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_TOKEN");
    if (!session->gssapi || session->auth.state != SSH_AUTH_STATE_GSSAPI_TOKEN) {
        ssh_set_error(session, SSH_FATAL,
                      "Received SSH_MSG_USERAUTH_GSSAPI_TOKEN in invalid state");
        goto error;
    }
    token = ssh_buffer_get_ssh_string(packet);

    if (token == NULL){
        ssh_set_error(session, SSH_REQUEST_DENIED,
                      "ssh_packet_userauth_gssapi_token: invalid packet");
        goto error;
    }

    hexa = ssh_get_hexa(ssh_string_data(token),ssh_string_len(token));
    SSH_LOG(SSH_LOG_PACKET, "GSSAPI Token : %s",hexa);
    SAFE_FREE(hexa);
    input_token.length = ssh_string_len(token);
    input_token.value = ssh_string_data(token);
    maj_stat = gss_init_sec_context(&min_stat,
                                    session->gssapi->client.creds,
                                    &session->gssapi->ctx,
                                    session->gssapi->client.server_name,
                                    session->gssapi->client.oid,
                                    session->gssapi->client.flags,
                                    0, NULL, &input_token, NULL,
                                    &output_token, NULL, NULL);

    ssh_gssapi_log_error(SSH_LOG_PROTOCOL,
                         "accepting token",
                         maj_stat,
                         min_stat);
    SSH_STRING_FREE(token);
    if (GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_PROTOCOL,
                             "Gssapi error",
                             maj_stat,
                             min_stat);
        goto error;
    }

    if (output_token.length != 0) {
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
        SAFE_FREE(hexa);
        ssh_buffer_pack(session->out_buffer,
                        "bdP",
                        SSH2_MSG_USERAUTH_GSSAPI_TOKEN,
                        output_token.length,
                        (size_t)output_token.length, output_token.value);
        ssh_packet_send(session);
    }

    if (maj_stat == GSS_S_COMPLETE) {
        ssh_gssapi_send_mic(session);
        session->auth.state = SSH_AUTH_STATE_GSSAPI_MIC_SENT;
    }

    return SSH_PACKET_USED;

error:
    session->auth.state = SSH_AUTH_STATE_ERROR;
    ssh_gssapi_free(session);
    session->gssapi = NULL;
    return SSH_PACKET_USED;
}
