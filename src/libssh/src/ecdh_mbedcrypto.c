/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2017 Sartura d.o.o.
 *
 * Author: Juraj Vijtiuk <juraj.vijtiuk@sartura.hr>
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

#include "libssh/session.h"
#include "libssh/ecdh.h"
#include "libssh/buffer.h"
#include "libssh/ssh2.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"
#include "libssh/libmbedcrypto.h"

#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>

#ifdef HAVE_ECDH

static mbedtls_ecp_group_id ecdh_kex_type_to_curve(enum ssh_key_exchange_e kex_type) {
    if (kex_type == SSH_KEX_ECDH_SHA2_NISTP256) {
        return MBEDTLS_ECP_DP_SECP256R1;
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP384) {
        return MBEDTLS_ECP_DP_SECP384R1;
    } else if (kex_type == SSH_KEX_ECDH_SHA2_NISTP521) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }

    return MBEDTLS_ECP_DP_NONE;
}
int ssh_client_ecdh_init(ssh_session session)
{
    ssh_string client_pubkey = NULL;
    mbedtls_ecp_group grp;
    int rc;
    mbedtls_ecp_group_id curve;

    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == MBEDTLS_ECP_DP_NONE) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_ECDH_INIT);
    if (rc < 0) {
        return SSH_ERROR;
    }

    session->next_crypto->ecdh_privkey = malloc(sizeof(mbedtls_ecp_keypair));
    if (session->next_crypto->ecdh_privkey == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecp_keypair_init(session->next_crypto->ecdh_privkey);
    mbedtls_ecp_group_init(&grp);

    rc = mbedtls_ecp_group_load(&grp, curve);
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = mbedtls_ecp_gen_keypair(&grp,
                                 &session->next_crypto->ecdh_privkey->d,
                                 &session->next_crypto->ecdh_privkey->Q,
                                 mbedtls_ctr_drbg_random,
                                 ssh_get_mbedtls_ctr_drbg_context());

    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    client_pubkey = make_ecpoint_string(&grp,
            &session->next_crypto->ecdh_privkey->Q);
    if (client_pubkey == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, client_pubkey);
    if (rc < 0) {
        rc = SSH_ERROR;
        goto out;
    }

    session->next_crypto->ecdh_client_pubkey = client_pubkey;
    client_pubkey = NULL;

    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_ecdh_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;
    rc = ssh_packet_send(session);

out:
    mbedtls_ecp_group_free(&grp);
    SSH_STRING_FREE(client_pubkey);

    return rc;
}

int ecdh_build_k(ssh_session session)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pubkey;
    int rc;
    mbedtls_ecp_group_id curve;

    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == MBEDTLS_ECP_DP_NONE) {
        return SSH_ERROR;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pubkey);

    rc = mbedtls_ecp_group_load(&grp, curve);
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    if (session->server) {
        rc = mbedtls_ecp_point_read_binary(&grp, &pubkey,
                ssh_string_data(session->next_crypto->ecdh_client_pubkey),
                ssh_string_len(session->next_crypto->ecdh_client_pubkey));
    } else {
        rc = mbedtls_ecp_point_read_binary(&grp, &pubkey,
                ssh_string_data(session->next_crypto->ecdh_server_pubkey),
                ssh_string_len(session->next_crypto->ecdh_server_pubkey));
    }

    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    session->next_crypto->shared_secret = malloc(sizeof(mbedtls_mpi));
    if (session->next_crypto->shared_secret == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    mbedtls_mpi_init(session->next_crypto->shared_secret);

    rc = mbedtls_ecdh_compute_shared(&grp,
                                     session->next_crypto->shared_secret,
                                     &pubkey,
                                     &session->next_crypto->ecdh_privkey->d,
                                     mbedtls_ctr_drbg_random,
                                     ssh_get_mbedtls_ctr_drbg_context());
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

out:
    mbedtls_ecp_keypair_free(session->next_crypto->ecdh_privkey);
    SAFE_FREE(session->next_crypto->ecdh_privkey);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pubkey);
    return rc;
}

#ifdef WITH_SERVER

SSH_PACKET_CALLBACK(ssh_packet_server_ecdh_init){
    ssh_string q_c_string = NULL;
    ssh_string q_s_string = NULL;
    mbedtls_ecp_group grp;
    ssh_key privkey = NULL;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    ssh_string pubkey_blob = NULL;
    int rc;
    mbedtls_ecp_group_id curve;
    (void)type;
    (void)user;

    ssh_packet_remove_callbacks(session, &ssh_ecdh_server_callbacks);
    curve = ecdh_kex_type_to_curve(session->next_crypto->kex_type);
    if (curve == MBEDTLS_ECP_DP_NONE) {
        return SSH_ERROR;
    }

    q_c_string = ssh_buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session, SSH_FATAL, "No Q_C ECC point in packet");
        return SSH_ERROR;
    }

    session->next_crypto->ecdh_privkey = malloc(sizeof(mbedtls_ecp_keypair));
    if (session->next_crypto->ecdh_privkey == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    session->next_crypto->ecdh_client_pubkey = q_c_string;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_keypair_init(session->next_crypto->ecdh_privkey);

    rc = mbedtls_ecp_group_load(&grp, curve);
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = mbedtls_ecp_gen_keypair(&grp,
                                 &session->next_crypto->ecdh_privkey->d,
                                 &session->next_crypto->ecdh_privkey->Q,
                                 mbedtls_ctr_drbg_random,
                                 ssh_get_mbedtls_ctr_drbg_context());
    if (rc != 0) {
        rc = SSH_ERROR;
        goto out;
    }

    q_s_string = make_ecpoint_string(&grp, &session->next_crypto->ecdh_privkey->Q);
    if (q_s_string == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    session->next_crypto->ecdh_server_pubkey = q_s_string;

    /* build k and session_id */
    rc = ecdh_build_k(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto out;
    }

    /* privkey is not allocated */
    rc = ssh_get_key_params(session, &privkey, &digest);
    if (rc == SSH_ERROR) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        rc = SSH_ERROR;
        goto out;
    }

    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey, digest);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_dh_get_next_server_publickey_blob(session, &pubkey_blob);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        SSH_STRING_FREE(sig_blob);
        goto out;
    }

    rc = ssh_buffer_pack(session->out_buffer, "bSSS",
                         SSH2_MSG_KEXDH_REPLY,
                         pubkey_blob, /* host's pubkey */
                         q_s_string, /* ecdh public key */
                         sig_blob); /* signature blob */

    SSH_STRING_FREE(sig_blob);
    SSH_STRING_FREE(pubkey_blob);

    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto out;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEXDH_REPLY sent");
    rc = ssh_packet_send(session);
    if (rc != SSH_OK) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc < 0) {
        rc = SSH_ERROR;
        goto out;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    rc = ssh_packet_send(session);
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");

out:
    mbedtls_ecp_group_free(&grp);
    if (rc == SSH_ERROR) {
        ssh_buffer_reinit(session->out_buffer);
        session->session_state = SSH_SESSION_STATE_ERROR;
    }
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */
#endif
