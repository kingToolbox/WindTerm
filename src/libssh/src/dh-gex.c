/*
 * dh-gex.c - diffie-hellman group exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2016 by Aris Adamantiadis <aris@0xbadc0de.be>
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

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/dh-gex.h"
#include "libssh/libssh.h"
#include "libssh/ssh2.h"
#include "libssh/callbacks.h"
#include "libssh/dh.h"
#include "libssh/buffer.h"
#include "libssh/session.h"

/* Minimum, recommanded and maximum size of DH group */
#define DH_PMIN 2048
#define DH_PREQ 2048
#define DH_PMAX 8192

static SSH_PACKET_CALLBACK(ssh_packet_client_dhgex_group);
static SSH_PACKET_CALLBACK(ssh_packet_client_dhgex_reply);

static ssh_packet_callback dhgex_client_callbacks[] = {
    ssh_packet_client_dhgex_group, /* SSH_MSG_KEX_DH_GEX_GROUP */
    NULL,                          /* SSH_MSG_KEX_DH_GEX_INIT */
    ssh_packet_client_dhgex_reply  /* SSH_MSG_KEX_DH_GEX_REPLY */
};

static struct ssh_packet_callbacks_struct ssh_dhgex_client_callbacks = {
    .start = SSH2_MSG_KEX_DH_GEX_GROUP,
    .n_callbacks = 3,
    .callbacks = dhgex_client_callbacks,
    .user = NULL
};

/** @internal
 * @brief initiates a diffie-hellman-group-exchange kex
 */
int ssh_client_dhgex_init(ssh_session session)
{
    int rc;

    rc = ssh_dh_init_common(session->next_crypto);
    if (rc != SSH_OK){
        goto error;
    }

    session->next_crypto->dh_pmin = DH_PMIN;
    session->next_crypto->dh_pn = DH_PREQ;
    session->next_crypto->dh_pmax = DH_PMAX;
    /* Minimum group size, preferred group size, maximum group size */
    rc = ssh_buffer_pack(session->out_buffer,
                         "bddd",
                         SSH2_MSG_KEX_DH_GEX_REQUEST,
                         session->next_crypto->dh_pmin,
                         session->next_crypto->dh_pn,
                         session->next_crypto->dh_pmax);
    if (rc != SSH_OK) {
        goto error;
    }

    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_dhgex_client_callbacks);
    session->dh_handshake_state = DH_STATE_REQUEST_SENT;
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        goto error;
    }
    return rc;
error:
    ssh_dh_cleanup(session->next_crypto);
    return SSH_ERROR;
}

/** @internal
 *  @brief handle a DH_GEX_GROUP packet, client side. This packet contains
 *         the group parameters.
 */
SSH_PACKET_CALLBACK(ssh_packet_client_dhgex_group)
{
    int rc;
    int blen;
    bignum pmin1 = NULL, one = NULL;
    bignum_CTX ctx = bignum_ctx_new();
    bignum modulus = NULL, generator = NULL;
    const_bignum pubkey;
    (void) type;
    (void) user;

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEX_DH_GEX_GROUP received");

    if (bignum_ctx_invalid(ctx)) {
        goto error;
    }

    if (session->dh_handshake_state != DH_STATE_REQUEST_SENT) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Received DH_GEX_GROUP in invalid state");
        goto error;
    }
    one = bignum_new();
    pmin1 = bignum_new();
    if (one == NULL || pmin1 == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    rc = ssh_buffer_unpack(packet,
                           "BB",
                           &modulus,
                           &generator);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Invalid DH_GEX_GROUP packet");
        goto error;
    }
    /* basic checks */
    if (ssh_fips_mode() &&
        !ssh_dh_is_known_group(modulus, generator)) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "The received DH group is not FIPS approved");
        goto error;
    }
    rc = bignum_set_word(one, 1);
    if (rc != 1) {
        goto error;
    }
    blen = bignum_num_bits(modulus);
    if (blen < DH_PMIN || blen > DH_PMAX) {
        ssh_set_error(session,
                SSH_FATAL,
                "Invalid dh group parameter p: %d not in [%d:%d]",
                blen,
                DH_PMIN,
                DH_PMAX);
        goto error;
    }
    if (bignum_cmp(modulus, one) <= 0) {
        /* p must be positive and preferably bigger than one */
        ssh_set_error(session, SSH_FATAL, "Invalid dh group parameter p");
    }
    if (!bignum_is_bit_set(modulus, 0)) {
        /* p must be a prime and therefore not divisible by 2 */
        ssh_set_error(session, SSH_FATAL, "Invalid dh group parameter p");
        goto error;
    }
    bignum_sub(pmin1, modulus, one);
    if (bignum_cmp(generator, one) <= 0 ||
        bignum_cmp(generator, pmin1) > 0) {
        /* generator must be at least 2 and smaller than p-1*/
        ssh_set_error(session, SSH_FATAL, "Invalid dh group parameter g");
        goto error;
    }
    bignum_ctx_free(ctx);
    ctx = NULL;

    /* all checks passed, set parameters (the BNs are copied in openssl backend) */
    rc = ssh_dh_set_parameters(session->next_crypto->dh_ctx,
                               modulus, generator);
    if (rc != SSH_OK) {
        goto error;
    }
#ifdef HAVE_LIBCRYPTO
    bignum_safe_free(modulus);
    bignum_safe_free(generator);
#endif
    modulus = NULL;
    generator = NULL;

    /* compute and send DH public parameter */
    rc = ssh_dh_keypair_gen_keys(session->next_crypto->dh_ctx,
                                 DH_CLIENT_KEYPAIR);
    if (rc == SSH_ERROR) {
        goto error;
    }

    rc = ssh_dh_keypair_get_keys(session->next_crypto->dh_ctx,
                                 DH_CLIENT_KEYPAIR, NULL, &pubkey);
    if (rc != SSH_OK) {
        goto error;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bB",
                         SSH2_MSG_KEX_DH_GEX_INIT,
                         pubkey);
    if (rc != SSH_OK) {
        goto error;
    }

    session->dh_handshake_state = DH_STATE_INIT_SENT;

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        goto error;
    }

    bignum_safe_free(one);
    bignum_safe_free(pmin1);
    return SSH_PACKET_USED;

error:
    bignum_safe_free(modulus);
    bignum_safe_free(generator);
    bignum_safe_free(one);
    bignum_safe_free(pmin1);
    if(!bignum_ctx_invalid(ctx)) {
        bignum_ctx_free(ctx);
    }
    ssh_dh_cleanup(session->next_crypto);
    session->session_state = SSH_SESSION_STATE_ERROR;

    return SSH_PACKET_USED;
}

static SSH_PACKET_CALLBACK(ssh_packet_client_dhgex_reply)
{
    struct ssh_crypto_struct *crypto=session->next_crypto;
    int rc;
    ssh_string pubkey_blob = NULL;
    bignum server_pubkey = NULL;
    (void)type;
    (void)user;
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEX_DH_GEX_REPLY received");

    ssh_packet_remove_callbacks(session, &ssh_dhgex_client_callbacks);
    rc = ssh_buffer_unpack(packet,
                           "SBS",
                           &pubkey_blob, &server_pubkey,
                           &crypto->dh_server_signature);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Invalid DH_GEX_REPLY packet");
        goto error;
    }
    rc = ssh_dh_keypair_set_keys(crypto->dh_ctx, DH_SERVER_KEYPAIR,
                                 NULL, server_pubkey);
    if (rc != SSH_OK) {
        bignum_safe_free(server_pubkey);
        goto error;
    }

    rc = ssh_dh_import_next_pubkey_blob(session, pubkey_blob);
    SSH_STRING_FREE(pubkey_blob);
    if (rc != 0) {
        goto error;
    }

    rc = ssh_dh_compute_shared_secret(session->next_crypto->dh_ctx,
                                      DH_CLIENT_KEYPAIR, DH_SERVER_KEYPAIR,
                                      &session->next_crypto->shared_secret);
    ssh_dh_debug_crypto(session->next_crypto);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Could not generate shared secret");
        goto error;
    }

    /* Send the MSG_NEWKEYS */
    if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
        goto error;
    }

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

    return SSH_PACKET_USED;
error:
    ssh_dh_cleanup(session->next_crypto);
    session->session_state = SSH_SESSION_STATE_ERROR;

    return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

#define MODULI_FILE "/etc/ssh/moduli"
/* 2     "Safe" prime; (p-1)/2 is also prime. */
#define SAFE_PRIME 2
/* 0x04  Probabilistic Miller-Rabin primality tests. */
#define PRIM_TEST_REQUIRED 0x04

/**
 * @internal
 *
 * @brief Determines if the proposed modulus size is more appropriate than the
 * current one.
 *
 * @returns 1 if it's more appropriate. Returns 0 if same or less appropriate
 */
static bool dhgroup_better_size(uint32_t pmin,
                                uint32_t pn,
                                uint32_t pmax,
                                size_t current_size,
                                size_t proposed_size)
{
    if (current_size == proposed_size) {
        return false;
    }

    if (current_size == pn) {
        /* can't do better */
        return false;
    }

    if (current_size == 0 && proposed_size >= pmin && proposed_size <= pmax) {
        return true;
    }

    if (proposed_size < pmin || proposed_size > pmax) {
        /* out of bounds */
        return false;
    }

    if (current_size == 0) {
        /* not in the allowed window */
        return false;
    }

    if (proposed_size >= pn && proposed_size < current_size) {
        return true;
    }

    if (proposed_size <= pn && proposed_size > current_size) {
        return true;
    }

    if (proposed_size >= pn && current_size < pn) {
        return true;
    }

    /* We're in the allowed window but a better match already exists. */
    return false;
}

/** @internal
 * @brief returns 1 with 1/n probability
 * @returns 1 on with P(1/n), 0 with P(n-1/n).
 */
static bool invn_chance(int n)
{
    uint32_t nounce = 0;
    int ok;

    ok = ssh_get_random(&nounce, sizeof(nounce), 0);
    if (!ok) {
        return false;
    }
    return (nounce % n) == 0;
}

/** @internal
 * @brief retrieves a DH group from an open moduli file.
 */
static int ssh_retrieve_dhgroup_file(FILE *moduli,
                                     uint32_t pmin,
                                     uint32_t pn,
                                     uint32_t pmax,
                                     size_t *best_size,
                                     char **best_generator,
                                     char **best_modulus)
{
    char timestamp[32] = {0};
    char generator[32] = {0};
    char modulus[4096] = {0};
    size_t type, tests, tries, size, proposed_size;
    int firstbyte;
    int rc;
    size_t line = 0;
    size_t best_nlines = 0;

    for(;;) {
        line++;
        firstbyte = getc(moduli);
        if (firstbyte == '#'){
            do {
                firstbyte = getc(moduli);
            } while(firstbyte != '\n' && firstbyte != EOF);
            continue;
        }
        if (firstbyte == EOF) {
            break;
        }
        ungetc(firstbyte, moduli);
        rc = fscanf(moduli,
                    "%31s %zu %zu %zu %zu %31s %4095s\n",
                    timestamp,
                    &type,
                    &tests,
                    &tries,
                    &size,
                    generator,
                    modulus);
        if (rc != 7){
            if (rc == EOF) {
                break;
            }
            SSH_LOG(SSH_LOG_INFO, "Invalid moduli entry line %zu", line);
            do {
                firstbyte = getc(moduli);
            } while(firstbyte != '\n' && firstbyte != EOF);
            continue;
        }

        /* we only want safe primes that were tested */
        if (type != SAFE_PRIME || !(tests & PRIM_TEST_REQUIRED)) {
            continue;
        }

        proposed_size = size + 1;
        if (proposed_size != *best_size &&
            dhgroup_better_size(pmin, pn, pmax, *best_size, proposed_size)) {
            best_nlines = 0;
            *best_size = proposed_size;
        }
        if (proposed_size == *best_size) {
            best_nlines++;
        }

        /* Use reservoir sampling algorithm */
        if (proposed_size == *best_size && invn_chance(best_nlines)) {
            SAFE_FREE(*best_generator);
            SAFE_FREE(*best_modulus);
            *best_generator = strdup(generator);
            if (*best_generator == NULL) {
                return SSH_ERROR;
            }
            *best_modulus = strdup(modulus);
            if (*best_modulus == NULL) {
                SAFE_FREE(*best_generator);
                return SSH_ERROR;
            }
        }
    }
    if (*best_size != 0) {
        SSH_LOG(SSH_LOG_INFO,
                "Selected %zu bits modulus out of %zu candidates in %zu lines",
                *best_size,
                best_nlines - 1,
                line);
    } else {
        SSH_LOG(SSH_LOG_WARNING,
                "No moduli found for [%u:%u:%u]",
                pmin,
                pn,
                pmax);
    }

    return SSH_OK;
}

/** @internal
 * @brief retrieves a DH group from the moduli file based on bits len parameters
 * @param[in] pmin minimum group size in bits
 * @param[in] pn preferred group size
 * @param[in] pmax maximum group size
 * @param[out] size size of the chosen modulus
 * @param[out] p modulus
 * @param[out] g generator
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
static int ssh_retrieve_dhgroup(uint32_t pmin,
                                uint32_t pn,
                                uint32_t pmax,
                                size_t *size,
                                bignum *p,
                                bignum *g)
{
    FILE *moduli = NULL;
    char *generator = NULL;
    char *modulus = NULL;
    int rc;

    /* In FIPS mode, we can not negotiate arbitrary primes,
     * but just the approved ones */
    if (ssh_fips_mode()) {
        SSH_LOG(SSH_LOG_TRACE, "In FIPS mode, using built-in primes");
        return ssh_fallback_group(pmax, p, g);
    }

    moduli = fopen(MODULI_FILE, "r");
    if (moduli == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Unable to open moduli file: %s",
                strerror(errno));
        return ssh_fallback_group(pmax, p, g);
    }

    *size = 0;
    *p = NULL;
    *g = NULL;

    rc = ssh_retrieve_dhgroup_file(moduli,
                                   pmin,
                                   pn,
                                   pmax,
                                   size,
                                   &generator,
                                   &modulus);
    fclose(moduli);
    if (rc == SSH_ERROR || *size == 0) {
        goto error;
    }
    rc = bignum_hex2bn(generator, g);
    if (rc == 0) {
        goto error;
    }
    rc = bignum_hex2bn(modulus, p);
    if (rc == 0) {
        goto error;
    }
    SAFE_FREE(generator);
    SAFE_FREE(modulus);

    return SSH_OK;

error:
    bignum_safe_free(*g);
    bignum_safe_free(*p);
    SAFE_FREE(generator);
    SAFE_FREE(modulus);

    return SSH_ERROR;
}

static SSH_PACKET_CALLBACK(ssh_packet_server_dhgex_request);
static SSH_PACKET_CALLBACK(ssh_packet_server_dhgex_init);

static ssh_packet_callback dhgex_server_callbacks[]= {
    NULL, /* SSH_MSG_KEX_DH_GEX_REQUEST_OLD */
    NULL, /* SSH_MSG_KEX_DH_GEX_GROUP */
    ssh_packet_server_dhgex_init,   /* SSH_MSG_KEX_DH_GEX_INIT */
    NULL,                           /* SSH_MSG_KEX_DH_GEX_REPLY */
    ssh_packet_server_dhgex_request /* SSH_MSG_GEX_DH_GEX_REQUEST */

};

static struct ssh_packet_callbacks_struct ssh_dhgex_server_callbacks = {
    .start = SSH2_MSG_KEX_DH_GEX_REQUEST_OLD,
    .n_callbacks = 5,
    .callbacks = dhgex_server_callbacks,
    .user = NULL
};

/** @internal
 * @brief sets up the diffie-hellman-groupx kex callbacks
 */
void ssh_server_dhgex_init(ssh_session session){
    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_dhgex_server_callbacks);
    ssh_dh_init_common(session->next_crypto);
    session->dh_handshake_state = DH_STATE_INIT;
}

static SSH_PACKET_CALLBACK(ssh_packet_server_dhgex_request)
{
    bignum modulus = NULL, generator = NULL;
    uint32_t pmin, pn, pmax;
    size_t size = 0;
    int rc;

    (void) type;
    (void) user;

    if (session->dh_handshake_state != DH_STATE_INIT) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Received DH_GEX_REQUEST in invalid state");
        goto error;
    }

    /* Minimum group size, preferred group size, maximum group size */
    rc = ssh_buffer_unpack(packet, "ddd", &pmin, &pn, &pmax);
    if (rc != SSH_OK){
        ssh_set_error_invalid(session);
        goto error;
    }
    SSH_LOG(SSH_LOG_INFO, "dh-gex: DHGEX_REQUEST[%u:%u:%u]", pmin, pn, pmax);

    if (pmin > pn || pn > pmax || pn > DH_PMAX || pmax < DH_PMIN) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Invalid dh-gex arguments [%u:%u:%u]",
                      pmin,
                      pn,
                      pmax);
        goto error;
    }
    session->next_crypto->dh_pmin = pmin;
    session->next_crypto->dh_pn = pn;
    session->next_crypto->dh_pmax = pmax;

    /* ensure safe parameters */
    if (pmin < DH_PMIN) {
        pmin = DH_PMIN;
        if (pn < pmin) {
            pn = pmin;
        }
    }
    rc = ssh_retrieve_dhgroup(pmin,
                              pn,
                              pmax,
                              &size,
                              &modulus,
                              &generator);
    if (rc == SSH_ERROR) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Couldn't find DH group for [%u:%u:%u]",
                      pmin,
                      pn,
                      pmax);
        goto error;
    }
    rc = ssh_dh_set_parameters(session->next_crypto->dh_ctx,
                               modulus, generator);
    if (rc != SSH_OK) {
        bignum_safe_free(generator);
        bignum_safe_free(modulus);
        goto error;
    }
    rc = ssh_buffer_pack(session->out_buffer,
                         "bBB",
                         SSH2_MSG_KEX_DH_GEX_GROUP,
                         modulus,
                         generator);

#ifdef HAVE_LIBCRYPTO
    bignum_safe_free(generator);
    bignum_safe_free(modulus);
#endif

    if (rc != SSH_OK) {
        ssh_set_error_invalid(session);
        goto error;
    }

    session->dh_handshake_state = DH_STATE_GROUP_SENT;

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        goto error;
    }

error:
    return SSH_PACKET_USED;
}

/** @internal
 * @brief parse an incoming SSH_MSG_KEX_DH_GEX_INIT packet and complete
 *        Diffie-Hellman key exchange
 **/
static SSH_PACKET_CALLBACK(ssh_packet_server_dhgex_init){
    (void) type;
    (void) user;
    SSH_LOG(SSH_LOG_DEBUG, "Received SSH_MSG_KEX_DHGEX_INIT");
    ssh_packet_remove_callbacks(session, &ssh_dhgex_server_callbacks);
    ssh_server_dh_process_init(session, packet);
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */
