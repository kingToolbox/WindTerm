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

#ifdef HAVE_LIBMBEDCRYPTO
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/buffer.h"
#include "libssh/bignum.h"
#include "libssh/misc.h"

#define MAX_PASSPHRASE_SIZE 1024
#define MAX_KEY_SIZE 32

ssh_string pki_private_key_to_pem(const ssh_key key, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data)
{
    (void) key;
    (void) passphrase;
    (void) auth_fn;
    (void) auth_data; return NULL;
}

static int pki_key_ecdsa_to_nid(mbedtls_ecdsa_context *ecdsa)
{
    mbedtls_ecp_group_id id;

    id = ecdsa->grp.id;
    if (id == MBEDTLS_ECP_DP_SECP256R1) {
        return NID_mbedtls_nistp256;
    } else if (id == MBEDTLS_ECP_DP_SECP384R1) {
        return NID_mbedtls_nistp384;
    } else if (id == MBEDTLS_ECP_DP_SECP521R1) {
        return NID_mbedtls_nistp521;
    }

    return -1;
}

static enum ssh_keytypes_e pki_key_ecdsa_to_key_type(mbedtls_ecdsa_context *ecdsa)
{
    int nid;

    nid = pki_key_ecdsa_to_nid(ecdsa);

    switch (nid) {
        case NID_mbedtls_nistp256:
            return SSH_KEYTYPE_ECDSA_P256;
        case NID_mbedtls_nistp384:
            return SSH_KEYTYPE_ECDSA_P384;
        case NID_mbedtls_nistp521:
            return SSH_KEYTYPE_ECDSA_P521;
        default:
            return SSH_KEYTYPE_UNKNOWN;
    }
}

ssh_key pki_private_key_from_base64(const char *b64_key, const char *passphrase,
        ssh_auth_callback auth_fn, void *auth_data)
{
    ssh_key key = NULL;
    mbedtls_pk_context *rsa = NULL;
    mbedtls_pk_context *ecdsa = NULL;
    ed25519_privkey *ed25519 = NULL;
    enum ssh_keytypes_e type;
    int valid;
    /* mbedtls pk_parse_key expects strlen to count the 0 byte */
    size_t b64len = strlen(b64_key) + 1;
    unsigned char tmp[MAX_PASSPHRASE_SIZE] = {0};

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key.");
        return NULL;
    }

    switch (type) {
        case SSH_KEYTYPE_RSA:
            rsa = malloc(sizeof(mbedtls_pk_context));
            if (rsa == NULL) {
                return NULL;
            }

            mbedtls_pk_init(rsa);

            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = auth_fn("Passphrase for private key:", (char *) tmp,
                            MAX_PASSPHRASE_SIZE, 0, 0, auth_data);
                    if (valid < 0) {
                        goto fail;
                    }
                    /* TODO fix signedness and strlen */
                    valid = mbedtls_pk_parse_key(rsa,
                            (const unsigned char *) b64_key,
                            b64len, tmp,
                            strnlen((const char *) tmp, MAX_PASSPHRASE_SIZE));
                } else {
                    valid = mbedtls_pk_parse_key(rsa,
                            (const unsigned char *) b64_key,
                            b64len, NULL,
                            0);
                }
            } else {
                valid = mbedtls_pk_parse_key(rsa,
                        (const unsigned char *) b64_key, b64len,
                        (const unsigned char *) passphrase,
                        strnlen(passphrase, MAX_PASSPHRASE_SIZE));
            }

            if (valid != 0) {
                char error_buf[100];
                mbedtls_strerror(valid, error_buf, 100);
                SSH_LOG(SSH_LOG_WARN,"Parsing private key %s", error_buf);
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            ecdsa = malloc(sizeof(mbedtls_pk_context));
            if (ecdsa == NULL) {
                return NULL;
            }

            mbedtls_pk_init(ecdsa);

            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = auth_fn("Passphrase for private key:", (char *) tmp,
                            MAX_PASSPHRASE_SIZE, 0, 0, auth_data);
                    if (valid < 0) {
                        goto fail;
                    }
                    valid = mbedtls_pk_parse_key(ecdsa,
                            (const unsigned char *) b64_key,
                            b64len, tmp,
                            strnlen((const char *) tmp, MAX_PASSPHRASE_SIZE));
                } else {
                    valid = mbedtls_pk_parse_key(ecdsa,
                            (const unsigned char *) b64_key,
                            b64len, NULL,
                            0);
                }
            } else {
                valid = mbedtls_pk_parse_key(ecdsa,
                        (const unsigned char *) b64_key, b64len,
                        (const unsigned char *) passphrase,
                        strnlen(passphrase, MAX_PASSPHRASE_SIZE));
            }

            if (valid != 0) {
                char error_buf[100];
                mbedtls_strerror(valid, error_buf, 100);
                SSH_LOG(SSH_LOG_WARN,"Parsing private key %s", error_buf);
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            /* Cannot open ed25519 keys with libmbedcrypto */
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown or invalid private key type %d",
                    type);
            return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    if (ecdsa != NULL) {
        mbedtls_ecp_keypair *keypair = mbedtls_pk_ec(*ecdsa);

        key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
        if (key->ecdsa == NULL) {
            goto fail;
        }

        mbedtls_ecdsa_init(key->ecdsa);
        mbedtls_ecdsa_from_keypair(key->ecdsa, keypair);
        mbedtls_pk_free(ecdsa);
        SAFE_FREE(ecdsa);

        key->ecdsa_nid = pki_key_ecdsa_to_nid(key->ecdsa);

        /* pki_privatekey_type_from_string always returns P256 for ECDSA
        * keys, so we need to figure out the correct type here */
        type = pki_key_ecdsa_to_key_type(key->ecdsa);
        if (type == SSH_KEYTYPE_UNKNOWN) {
            SSH_LOG(SSH_LOG_WARN, "Invalid private key.");
            goto fail;
        }
    } else {
        key->ecdsa = NULL;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->rsa = rsa;
    key->ed25519_privkey = ed25519;
    rsa = NULL;
    ecdsa = NULL;

    return key;
fail:
    ssh_key_free(key);
    if (rsa != NULL) {
        mbedtls_pk_free(rsa);
        SAFE_FREE(rsa);
    }
    if (ecdsa != NULL) {
        mbedtls_pk_free(ecdsa);
        SAFE_FREE(ecdsa);
    }
    return NULL;
}

int pki_privkey_build_rsa(ssh_key key,
                          ssh_string n,
                          ssh_string e,
                          ssh_string d,
                          UNUSED_PARAM(ssh_string iqmp),
                          ssh_string p,
                          ssh_string q)
{
    mbedtls_rsa_context *rsa = NULL;
    const mbedtls_pk_info_t *pk_info = NULL;
    int rc;

    key->rsa = malloc(sizeof(mbedtls_pk_context));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_pk_init(key->rsa);
    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    mbedtls_pk_setup(key->rsa, pk_info);

    rc = mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA);
    if (rc == 0) {
        goto fail;
    }

    rsa = mbedtls_pk_rsa(*key->rsa);
    rc = mbedtls_rsa_import_raw(rsa,
                                ssh_string_data(n), ssh_string_len(n),
                                ssh_string_data(p), ssh_string_len(p),
                                ssh_string_data(q), ssh_string_len(q),
                                ssh_string_data(d), ssh_string_len(d),
                                ssh_string_data(e), ssh_string_len(e));
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARN, "Failed to import private RSA key");
        goto fail;
    }

    rc = mbedtls_rsa_complete(rsa);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARN, "Failed to complete private RSA key");
        goto fail;
    }

    rc = mbedtls_rsa_check_privkey(rsa);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARN, "Inconsistent private RSA key");
        goto fail;
    }

    return SSH_OK;

fail:
    mbedtls_pk_free(key->rsa);
    SAFE_FREE(key->rsa);
    return SSH_ERROR;
}

int pki_pubkey_build_rsa(ssh_key key, ssh_string e, ssh_string n)
{
    mbedtls_rsa_context *rsa = NULL;
    const mbedtls_pk_info_t *pk_info = NULL;
    int rc;

    key->rsa = malloc(sizeof(mbedtls_pk_context));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_pk_init(key->rsa);
    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    mbedtls_pk_setup(key->rsa, pk_info);

    rc = mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA);
    if (rc == 0) {
        goto fail;
    }

    rsa = mbedtls_pk_rsa(*key->rsa);
    rc = mbedtls_mpi_read_binary(&rsa->N, ssh_string_data(n),
                                 ssh_string_len(n));
    if (rc != 0) {
        goto fail;
    }
    rc = mbedtls_mpi_read_binary(&rsa->E, ssh_string_data(e),
                                 ssh_string_len(e));
    if (rc != 0) {
        goto fail;
    }

    rsa->len = (mbedtls_mpi_bitlen(&rsa->N) + 7) >> 3;

    return SSH_OK;

fail:
    mbedtls_pk_free(key->rsa);
    SAFE_FREE(key->rsa);
    return SSH_ERROR;
}

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new = NULL;
    int rc;
    const mbedtls_pk_info_t *pk_info = NULL;


    new = ssh_key_new();
    if (new == NULL) {
        return NULL;
    }

    new->type = key->type;
    new->type_c = key->type_c;
    if (demote) {
        new->flags = SSH_KEY_FLAG_PUBLIC;
    } else {
        new->flags = key->flags;
    }


    switch(key->type) {
        case SSH_KEYTYPE_RSA: {
            mbedtls_rsa_context *rsa, *new_rsa;

            new->rsa = malloc(sizeof(mbedtls_pk_context));
            if (new->rsa == NULL) {
                goto fail;
            }

            mbedtls_pk_init(new->rsa);
            pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
            mbedtls_pk_setup(new->rsa, pk_info);

            if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA) &&
                        mbedtls_pk_can_do(new->rsa, MBEDTLS_PK_RSA)) {
                rsa = mbedtls_pk_rsa(*key->rsa);
                new_rsa = mbedtls_pk_rsa(*new->rsa);

                rc = mbedtls_mpi_copy(&new_rsa->N, &rsa->N);
                if (rc != 0) {
                    goto fail;
                }

                rc = mbedtls_mpi_copy(&new_rsa->E, &rsa->E);
                if (rc != 0) {
                    goto fail;
                }
                new_rsa->len = (mbedtls_mpi_bitlen(&new_rsa->N) + 7) >> 3;

                if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
                    rc = mbedtls_mpi_copy(&new_rsa->D, &rsa->D);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->P, &rsa->P);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->Q, &rsa->Q);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->DP, &rsa->DP);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->DQ, &rsa->DQ);
                    if (rc != 0) {
                        goto fail;
                    }

                    rc = mbedtls_mpi_copy(&new_rsa->QP, &rsa->QP);
                    if (rc != 0) {
                        goto fail;
                    }
                }
            } else {
                goto fail;
            }

            break;
        }
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            new->ecdsa_nid = key->ecdsa_nid;

            new->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));

            if (new->ecdsa == NULL) {
                goto fail;
            }

            mbedtls_ecdsa_init(new->ecdsa);

            if (demote && ssh_key_is_private(key)) {
                rc = mbedtls_ecp_copy(&new->ecdsa->Q, &key->ecdsa->Q);
                if (rc != 0) {
                    goto fail;
                }

                rc = mbedtls_ecp_group_copy(&new->ecdsa->grp, &key->ecdsa->grp);
                if (rc != 0) {
                    goto fail;
                }
            } else {
                mbedtls_ecdsa_from_keypair(new->ecdsa, key->ecdsa);
            }

            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_key_dup(new, key);
            if (rc != SSH_OK) {
                goto fail;
            }
            break;
        default:
            goto fail;
    }

    return new;
fail:
    ssh_key_free(new);
    return NULL;
}

int pki_key_generate_rsa(ssh_key key, int parameter)
{
    int rc;
    const mbedtls_pk_info_t *info = NULL;

    key->rsa = malloc(sizeof(mbedtls_pk_context));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_pk_init(key->rsa);

    info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    rc = mbedtls_pk_setup(key->rsa, info);
    if (rc != 0) {
        return SSH_ERROR;
    }

    if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA)) {
        rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key->rsa),
                                 mbedtls_ctr_drbg_random,
                                 ssh_get_mbedtls_ctr_drbg_context(),
                                 parameter,
                                 65537);
        if (rc != 0) {
            mbedtls_pk_free(key->rsa);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

int pki_key_compare(const ssh_key k1, const ssh_key k2, enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_RSA: {
            mbedtls_rsa_context *rsa1, *rsa2;
            if (mbedtls_pk_can_do(k1->rsa, MBEDTLS_PK_RSA) &&
                    mbedtls_pk_can_do(k2->rsa, MBEDTLS_PK_RSA)) {
                if (mbedtls_pk_get_type(k1->rsa) != mbedtls_pk_get_type(k2->rsa) ||
                        mbedtls_pk_get_bitlen(k1->rsa) !=
                        mbedtls_pk_get_bitlen(k2->rsa)) {
                    return 1;
                }

                rsa1 = mbedtls_pk_rsa(*k1->rsa);
                rsa2 = mbedtls_pk_rsa(*k2->rsa);
                if (mbedtls_mpi_cmp_mpi(&rsa1->N, &rsa2->N) != 0) {
                    return 1;
                }

                if (mbedtls_mpi_cmp_mpi(&rsa1->E, &rsa2->E) != 0) {
                    return 1;
                }

                if (what == SSH_KEY_CMP_PRIVATE) {
                    if (mbedtls_mpi_cmp_mpi(&rsa1->P, &rsa2->P) != 0) {
                        return 1;
                    }

                    if (mbedtls_mpi_cmp_mpi(&rsa1->Q, &rsa2->Q) != 0) {
                        return 1;
                    }
                }
            }
            break;
        }
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521: {
            mbedtls_ecp_keypair *ecdsa1 = k1->ecdsa;
            mbedtls_ecp_keypair *ecdsa2 = k2->ecdsa;

            if (ecdsa1->grp.id != ecdsa2->grp.id) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.X, &ecdsa2->Q.X)) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.Y, &ecdsa2->Q.Y)) {
                return 1;
            }

            if (mbedtls_mpi_cmp_mpi(&ecdsa1->Q.Z, &ecdsa2->Q.Z)) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (mbedtls_mpi_cmp_mpi(&ecdsa1->d, &ecdsa2->d)) {
                    return 1;
                }
            }

            break;
        }
        case SSH_KEYTYPE_ED25519:
            /* ed25519 keys handled globally */
            return 0;
        default:
            return 1;
    }

    return 0;
}

ssh_string make_ecpoint_string(const mbedtls_ecp_group *g, const
        mbedtls_ecp_point *p)
{
    ssh_string s = NULL;
    size_t len = 1;
    int rc;

    s = ssh_string_new(len);
    if (s == NULL) {
        return NULL;
    }

    rc = mbedtls_ecp_point_write_binary(g, p, MBEDTLS_ECP_PF_UNCOMPRESSED,
                &len, ssh_string_data(s), ssh_string_len(s));
    if (rc == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        SSH_STRING_FREE(s);

        s = ssh_string_new(len);
        if (s == NULL) {
            return NULL;
        }

        rc = mbedtls_ecp_point_write_binary(g, p, MBEDTLS_ECP_PF_UNCOMPRESSED,
                &len, ssh_string_data(s), ssh_string_len(s));
    }

    if (rc != 0) {
        SSH_STRING_FREE(s);
        return NULL;
    }

    if (len != ssh_string_len(s)) {
        SSH_STRING_FREE(s);
        return NULL;
    }

    return s;
}

static const char* pki_key_ecdsa_nid_to_char(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return "nistp256";
        case NID_mbedtls_nistp384:
            return "nistp384";
        case NID_mbedtls_nistp521:
            return "nistp521";
        default:
            break;
    }

    return "unknown";
}

ssh_string pki_publickey_to_blob(const ssh_key key)
{
    ssh_buffer buffer = NULL;
    ssh_string type_s = NULL;
    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string str = NULL;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    if (key->cert != NULL) {
        rc = ssh_buffer_add_buffer(buffer, key->cert);
        if (rc < 0) {
            SSH_BUFFER_FREE(buffer);
            return NULL;
        }

        goto makestring;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        SSH_BUFFER_FREE(buffer);
        return NULL;
    }

    rc = ssh_buffer_add_ssh_string(buffer, type_s);
    SSH_STRING_FREE(type_s);
    if (rc < 0) {
        SSH_BUFFER_FREE(buffer);
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_RSA: {
            mbedtls_rsa_context *rsa;
            if (mbedtls_pk_can_do(key->rsa, MBEDTLS_PK_RSA) == 0) {
                SSH_BUFFER_FREE(buffer);
                return NULL;
            }

            rsa = mbedtls_pk_rsa(*key->rsa);

            e = ssh_make_bignum_string(&rsa->E);
            if (e == NULL) {
                goto fail;
            }

            n = ssh_make_bignum_string(&rsa->N);
            if (n == NULL) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }

            if (ssh_buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            SSH_STRING_FREE(e);
            e = NULL;
            ssh_string_burn(n);
            SSH_STRING_FREE(n);
            n = NULL;

            break;
        }
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            type_s =
                ssh_string_from_char(pki_key_ecdsa_nid_to_char(key->ecdsa_nid));
            if (type_s == NULL) {
                SSH_BUFFER_FREE(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, type_s);
            SSH_STRING_FREE(type_s);
            if (rc < 0) {
                SSH_BUFFER_FREE(buffer);
                return NULL;
            }

            e = make_ecpoint_string(&key->ecdsa->grp, &key->ecdsa->Q);

            if (e == NULL) {
                SSH_BUFFER_FREE(buffer);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(buffer, e);
            if (rc < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            SSH_STRING_FREE(e);
            e = NULL;

            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_public_key_to_blob(buffer, key);
            if (rc != SSH_OK) {
                goto fail;
            }
            break;
        default:
            goto fail;
    }
makestring:
    str = ssh_string_new(ssh_buffer_get_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, ssh_buffer_get(buffer),
            ssh_buffer_get_len(buffer));
    if (rc < 0) {
        goto fail;
    }

    SSH_BUFFER_FREE(buffer);
    return str;
fail:
    SSH_BUFFER_FREE(buffer);
    ssh_string_burn(str);
    SSH_STRING_FREE(str);
    ssh_string_burn(e);
    SSH_STRING_FREE(e);
    ssh_string_burn(n);
    SSH_STRING_FREE(n);

    return NULL;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    ssh_string sig_blob = NULL;

    switch(sig->type) {
        case SSH_KEYTYPE_RSA:
            sig_blob = ssh_string_copy(sig->rsa_sig);
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521: {
            ssh_string r;
            ssh_string s;
            ssh_buffer b;
            int rc;

            b = ssh_buffer_new();
            if (b == NULL) {
                return NULL;
            }

            r = ssh_make_bignum_string(sig->ecdsa_sig.r);
            if (r == NULL) {
                SSH_BUFFER_FREE(b);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(b, r);
            SSH_STRING_FREE(r);
            if (rc < 0) {
                SSH_BUFFER_FREE(b);
                return NULL;
            }

            s = ssh_make_bignum_string(sig->ecdsa_sig.s);
            if (s == NULL) {
                SSH_BUFFER_FREE(b);
                return NULL;
            }

            rc = ssh_buffer_add_ssh_string(b, s);
            SSH_STRING_FREE(s);
            if (rc < 0) {
                SSH_BUFFER_FREE(b);
                return NULL;
            }

            sig_blob = ssh_string_new(ssh_buffer_get_len(b));
            if (sig_blob == NULL) {
                SSH_BUFFER_FREE(b);
                return NULL;
            }

            ssh_string_fill(sig_blob, ssh_buffer_get(b), ssh_buffer_get_len(b));
            SSH_BUFFER_FREE(b);
            break;
        }
        case SSH_KEYTYPE_ED25519:
            sig_blob = pki_ed25519_signature_to_blob(sig);
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature key type: %s",
                    sig->type_c);
            return NULL;
    }

    return sig_blob;
}

static ssh_signature pki_signature_from_rsa_blob(const ssh_key pubkey, const
        ssh_string sig_blob, ssh_signature sig)
{
    size_t pad_len = 0;
    char *blob_orig = NULL;
    char *blob_padded_data = NULL;
    ssh_string sig_blob_padded = NULL;

    size_t rsalen = 0;
    size_t len = ssh_string_len(sig_blob);

    if (pubkey->rsa == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Pubkey RSA field NULL");
        goto errout;
    }

    rsalen = mbedtls_pk_get_bitlen(pubkey->rsa) / 8;
    if (len > rsalen) {
        SSH_LOG(SSH_LOG_WARN,
                "Signature is too big: %lu > %lu",
                (unsigned long) len,
                (unsigned long) rsalen);
        goto errout;
    }
#ifdef DEBUG_CRYPTO
    SSH_LOG(SSH_LOG_WARN, "RSA signature len: %lu", (unsigned long)len);
    ssh_log_hexdump("RSA signature", ssh_string_data(sig_blob), len);
#endif

    if (len == rsalen) {
        sig->rsa_sig = ssh_string_copy(sig_blob);
    } else {
        SSH_LOG(SSH_LOG_DEBUG, "RSA signature len %lu < %lu",
                (unsigned long) len,
                (unsigned long) rsalen);
        pad_len = rsalen - len;

        sig_blob_padded = ssh_string_new(rsalen);
        if (sig_blob_padded == NULL) {
            goto errout;
        }

        blob_padded_data = (char *) ssh_string_data(sig_blob_padded);
        blob_orig = (char *) ssh_string_data(sig_blob);

        explicit_bzero(blob_padded_data, pad_len);
        memcpy(blob_padded_data + pad_len, blob_orig, len);

        sig->rsa_sig = sig_blob_padded;
    }

    return sig;

errout:
    ssh_signature_free(sig);
    return NULL;
}
ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type,
                                      enum ssh_digest_e hash_type)
{
    ssh_signature sig = NULL;
    int rc;

    if (ssh_key_type_plain(pubkey->type) != type) {
        SSH_LOG(SSH_LOG_WARN,
                "Incompatible public key provided (%d) expecting (%d)",
                type,
                pubkey->type);
        return NULL;
    }

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;
    sig->type_c = ssh_key_signature_to_char(type, hash_type);
    sig->hash_type = hash_type;

    switch(type) {
        case SSH_KEYTYPE_RSA:
            sig = pki_signature_from_rsa_blob(pubkey, sig_blob, sig);
            if (sig == NULL) {
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521: {
            ssh_buffer b;
            ssh_string r;
            ssh_string s;
            size_t rlen;

            b = ssh_buffer_new();
            if (b == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            rc = ssh_buffer_add_data(b, ssh_string_data(sig_blob),
                    ssh_string_len(sig_blob));

            if (rc < 0) {
                SSH_BUFFER_FREE(b);
                ssh_signature_free(sig);
                return NULL;
            }

            r = ssh_buffer_get_ssh_string(b);
            if (r == NULL) {
                SSH_BUFFER_FREE(b);
                ssh_signature_free(sig);
                return NULL;
            }
#ifdef DEBUG_CRYPTO
            ssh_log_hexdump("r", ssh_string_data(r), ssh_string_len(r));
#endif
            sig->ecdsa_sig.r = ssh_make_string_bn(r);
            ssh_string_burn(r);
            SSH_STRING_FREE(r);
            if (sig->ecdsa_sig.r == NULL) {
                SSH_BUFFER_FREE(b);
                ssh_signature_free(sig);
                return NULL;
            }

            s = ssh_buffer_get_ssh_string(b);
            rlen = ssh_buffer_get_len(b);
            SSH_BUFFER_FREE(b);
            if (s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_log_hexdump("s", ssh_string_data(s), ssh_string_len(s));
#endif
            sig->ecdsa_sig.s = ssh_make_string_bn(s);
            ssh_string_burn(s);
            SSH_STRING_FREE(s);
            if (sig->ecdsa_sig.s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            if (rlen != 0) {
                SSH_LOG(SSH_LOG_WARN, "Signature has remaining bytes in inner "
                        "sigblob: %lu",
                        (unsigned long)rlen);
                ssh_signature_free(sig);
                return NULL;
            }

            break;
        }
        case SSH_KEYTYPE_ED25519:
            rc = pki_signature_from_ed25519_blob(sig, sig_blob);
            if (rc == SSH_ERROR) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown signature type");
            return NULL;
    }

    return sig;
}

static ssh_string rsa_do_sign_hash(const unsigned char *digest,
                                   int dlen,
                                   mbedtls_pk_context *privkey,
                                   enum ssh_digest_e hash_type)
{
    ssh_string sig_blob = NULL;
    mbedtls_md_type_t md = 0;
    unsigned char *sig = NULL;
    size_t slen;
    int ok;

    switch (hash_type) {
    case SSH_DIGEST_SHA1:
        md = MBEDTLS_MD_SHA1;
        break;
    case SSH_DIGEST_SHA256:
        md = MBEDTLS_MD_SHA256;
        break;
    case SSH_DIGEST_SHA512:
        md = MBEDTLS_MD_SHA512;
        break;
    case SSH_DIGEST_AUTO:
    default:
        SSH_LOG(SSH_LOG_WARN, "Incompatible key algorithm");
        return NULL;
    }

    sig = malloc(mbedtls_pk_get_bitlen(privkey) / 8);
    if (sig == NULL) {
        return NULL;
    }

    ok = mbedtls_pk_sign(privkey,
                         md,
                         digest,
                         dlen,
                         sig,
                         &slen,
                         mbedtls_ctr_drbg_random,
                         ssh_get_mbedtls_ctr_drbg_context());

    if (ok != 0) {
        SAFE_FREE(sig);
        return NULL;
    }

    sig_blob = ssh_string_new(slen);
    if (sig_blob == NULL) {
        SAFE_FREE(sig);
        return NULL;
    }

    ssh_string_fill(sig_blob, sig, slen);
    explicit_bzero(sig, slen);
    SAFE_FREE(sig);

    return sig_blob;
}


ssh_signature pki_do_sign_hash(const ssh_key privkey,
                               const unsigned char *hash,
                               size_t hlen,
                               enum ssh_digest_e hash_type)
{
    ssh_signature sig = NULL;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = privkey->type;
    sig->type_c = ssh_key_signature_to_char(privkey->type, hash_type);
    sig->hash_type = hash_type;

    switch(privkey->type) {
        case SSH_KEYTYPE_RSA:
            sig->rsa_sig = rsa_do_sign_hash(hash, hlen, privkey->rsa, hash_type);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
            sig->ecdsa_sig.r = bignum_new();
            if (sig->ecdsa_sig.r == NULL) {
                return NULL;
            }

            sig->ecdsa_sig.s = bignum_new();
            if (sig->ecdsa_sig.s == NULL) {
                bignum_safe_free(sig->ecdsa_sig.r);
                return NULL;
            }

            rc = mbedtls_ecdsa_sign(&privkey->ecdsa->grp,
                                    sig->ecdsa_sig.r,
                                    sig->ecdsa_sig.s,
                                    &privkey->ecdsa->d,
                                    hash,
                                    hlen,
                                    mbedtls_ctr_drbg_random,
                                    ssh_get_mbedtls_ctr_drbg_context());
            if (rc != 0) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sign(privkey, sig, hash, hlen);
            if (rc != SSH_OK) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
            ssh_signature_free(sig);
            return NULL;

    }

    return sig;
}

/**
 * @internal
 *
 * @brief Sign the given input data. The digest of to be signed is calculated
 * internally as necessary.
 *
 * @param[in]   privkey     The private key to be used for signing.
 * @param[in]   hash_type   The digest algorithm to be used.
 * @param[in]   input       The data to be signed.
 * @param[in]   input_len   The length of the data to be signed.
 *
 * @return  a newly allocated ssh_signature or NULL on error.
 */
ssh_signature pki_sign_data(const ssh_key privkey,
                            enum ssh_digest_e hash_type,
                            const unsigned char *input,
                            size_t input_len)
{
    unsigned char hash[SHA512_DIGEST_LEN] = {0};
    const unsigned char *sign_input = NULL;
    uint32_t hlen = 0;
    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey) || input == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad parameter provided to "
                               "pki_sign_data()");
        return NULL;
    }

    /* Check if public key and hash type are compatible */
    rc = pki_key_check_hash_compatible(privkey, hash_type);
    if (rc != SSH_OK) {
        return NULL;
    }

    switch (hash_type) {
    case SSH_DIGEST_SHA256:
        sha256(input, input_len, hash);
        hlen = SHA256_DIGEST_LEN;
        sign_input = hash;
        break;
    case SSH_DIGEST_SHA384:
        sha384(input, input_len, hash);
        hlen = SHA384_DIGEST_LEN;
        sign_input = hash;
        break;
    case SSH_DIGEST_SHA512:
        sha512(input, input_len, hash);
        hlen = SHA512_DIGEST_LEN;
        sign_input = hash;
        break;
    case SSH_DIGEST_SHA1:
        sha1(input, input_len, hash);
        hlen = SHA_DIGEST_LEN;
        sign_input = hash;
        break;
    case SSH_DIGEST_AUTO:
        if (privkey->type == SSH_KEYTYPE_ED25519) {
            /* SSH_DIGEST_AUTO should only be used with ed25519 */
            sign_input = input;
            hlen = input_len;
            break;
        }
        FALL_THROUGH;
    default:
        SSH_LOG(SSH_LOG_TRACE, "Unknown hash algorithm for type: %d",
                hash_type);
        return NULL;
    }

    return pki_do_sign_hash(privkey, sign_input, hlen, hash_type);
}

/**
 * @internal
 *
 * @brief Verify the signature of a given input. The digest of the input is
 * calculated internally as necessary.
 *
 * @param[in]   signature   The signature to be verified.
 * @param[in]   pubkey      The public key used to verify the signature.
 * @param[in]   input       The signed data.
 * @param[in]   input_len   The length of the signed data.
 *
 * @return  SSH_OK if the signature is valid; SSH_ERROR otherwise.
 */
int pki_verify_data_signature(ssh_signature signature,
                              const ssh_key pubkey,
                              const unsigned char *input,
                              size_t input_len)
{

    unsigned char hash[SHA512_DIGEST_LEN] = {0};
    const unsigned char *verify_input = NULL;
    uint32_t hlen = 0;

    mbedtls_md_type_t md = 0;

    int rc;

    if (pubkey == NULL || ssh_key_is_private(pubkey) || input == NULL ||
        signature == NULL)
    {
        SSH_LOG(SSH_LOG_TRACE, "Bad parameter provided to "
                               "pki_verify_data_signature()");
        return SSH_ERROR;
    }

    /* Check if public key and hash type are compatible */
    rc = pki_key_check_hash_compatible(pubkey, signature->hash_type);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    switch (signature->hash_type) {
    case SSH_DIGEST_SHA256:
        sha256(input, input_len, hash);
        hlen = SHA256_DIGEST_LEN;
        md = MBEDTLS_MD_SHA256;
        verify_input = hash;
        break;
    case SSH_DIGEST_SHA384:
        sha384(input, input_len, hash);
        hlen = SHA384_DIGEST_LEN;
        md = MBEDTLS_MD_SHA384;
        verify_input = hash;
        break;
    case SSH_DIGEST_SHA512:
        sha512(input, input_len, hash);
        hlen = SHA512_DIGEST_LEN;
        md = MBEDTLS_MD_SHA512;
        verify_input = hash;
        break;
    case SSH_DIGEST_SHA1:
        sha1(input, input_len, hash);
        hlen = SHA_DIGEST_LEN;
        md = MBEDTLS_MD_SHA1;
        verify_input = hash;
        break;
    case SSH_DIGEST_AUTO:
        if (pubkey->type == SSH_KEYTYPE_ED25519 ||
            pubkey->type == SSH_KEYTYPE_ED25519_CERT01)
        {
            verify_input = input;
            hlen = input_len;
            break;
        }
        FALL_THROUGH;
    default:
        SSH_LOG(SSH_LOG_TRACE, "Unknown sig->hash_type: %d",
                signature->hash_type);
        return SSH_ERROR;
    }

    switch (pubkey->type) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA_CERT01:
            rc = mbedtls_pk_verify(pubkey->rsa, md, hash, hlen,
                    ssh_string_data(signature->rsa_sig),
                    ssh_string_len(signature->rsa_sig));
            if (rc != 0) {
                char error_buf[100];
                mbedtls_strerror(rc, error_buf, 100);
                SSH_LOG(SSH_LOG_TRACE, "RSA error: %s", error_buf);
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
        case SSH_KEYTYPE_ECDSA_P256_CERT01:
        case SSH_KEYTYPE_ECDSA_P384_CERT01:
        case SSH_KEYTYPE_ECDSA_P521_CERT01:
            rc = mbedtls_ecdsa_verify(&pubkey->ecdsa->grp, hash, hlen,
                    &pubkey->ecdsa->Q, signature->ecdsa_sig.r,
                    signature->ecdsa_sig.s);
            if (rc != 0) {
                char error_buf[100];
                mbedtls_strerror(rc, error_buf, 100);
                SSH_LOG(SSH_LOG_TRACE, "ECDSA error: %s", error_buf);
                return SSH_ERROR;

            }
            break;
        case SSH_KEYTYPE_ED25519:
        case SSH_KEYTYPE_ED25519_CERT01:
            rc = pki_ed25519_verify(pubkey, signature, verify_input, hlen);
            if (rc != SSH_OK) {
                SSH_LOG(SSH_LOG_TRACE, "ED25519 error: Signature invalid");
                return SSH_ERROR;
            }
            break;
        default:
            SSH_LOG(SSH_LOG_TRACE, "Unknown public key type");
            return SSH_ERROR;
    }

    return SSH_OK;
}

const char *pki_key_ecdsa_nid_to_name(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return "ecdsa-sha2-nistp256";
        case NID_mbedtls_nistp384:
            return "ecdsa-sha2-nistp384";
        case NID_mbedtls_nistp521:
            return "ecdsa-sha2-nistp521";
        default:
            break;
    }

    return "unknown";
}

int pki_key_ecdsa_nid_from_name(const char *name)
{
    if (strcmp(name, "nistp256") == 0) {
        return NID_mbedtls_nistp256;
    } else if (strcmp(name, "nistp384") == 0) {
        return NID_mbedtls_nistp384;
    } else if (strcmp(name, "nistp521") == 0) {
        return NID_mbedtls_nistp521;
    }

    return -1;
}

static mbedtls_ecp_group_id pki_key_ecdsa_nid_to_mbed_gid(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return MBEDTLS_ECP_DP_SECP256R1;
        case NID_mbedtls_nistp384:
            return MBEDTLS_ECP_DP_SECP384R1;
        case NID_mbedtls_nistp521:
            return MBEDTLS_ECP_DP_SECP521R1;
    }

    return MBEDTLS_ECP_DP_NONE;
}

int pki_privkey_build_ecdsa(ssh_key key, int nid, ssh_string e, ssh_string exp)
{
    int rc;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_group group;
    mbedtls_ecp_point Q;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecdsa_init(key->ecdsa);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&Q);

    rc = mbedtls_ecp_group_load(&group,
                                pki_key_ecdsa_nid_to_mbed_gid(nid));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_point_read_binary(&group, &Q, ssh_string_data(e),
                                       ssh_string_len(e));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_copy(&keypair.Q, &Q);
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_group_copy(&keypair.grp, &group);
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_mpi_read_binary(&keypair.d, ssh_string_data(exp),
                                 ssh_string_len(exp));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecdsa_from_keypair(key->ecdsa, &keypair);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    return SSH_OK;

fail:
    mbedtls_ecdsa_free(key->ecdsa);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    SAFE_FREE(key->ecdsa);
    return SSH_ERROR;
}

int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    int rc;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_group group;
    mbedtls_ecp_point Q;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecdsa_init(key->ecdsa);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&Q);

    rc = mbedtls_ecp_group_load(&group,
            pki_key_ecdsa_nid_to_mbed_gid(nid));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_point_read_binary(&group, &Q, ssh_string_data(e),
            ssh_string_len(e));
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_copy(&keypair.Q, &Q);
    if (rc != 0) {
        goto fail;
    }

    rc = mbedtls_ecp_group_copy(&keypair.grp, &group);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_mpi_init(&keypair.d);

    rc = mbedtls_ecdsa_from_keypair(key->ecdsa, &keypair);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    return SSH_OK;
fail:
    mbedtls_ecdsa_free(key->ecdsa);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_keypair_free(&keypair);
    SAFE_FREE(key->ecdsa);
    return SSH_ERROR;
}

int pki_key_generate_ecdsa(ssh_key key, int parameter)
{
    int ok;

    switch (parameter) {
        case 384:
            key->ecdsa_nid = NID_mbedtls_nistp384;
            key->type = SSH_KEYTYPE_ECDSA_P384;
            break;
        case 521:
            key->ecdsa_nid = NID_mbedtls_nistp521;
            key->type = SSH_KEYTYPE_ECDSA_P521;
            break;
        case 256:
        default:
            key->ecdsa_nid = NID_mbedtls_nistp256;
            key->type = SSH_KEYTYPE_ECDSA_P256;
            break;
    }

    key->ecdsa = malloc(sizeof(mbedtls_ecdsa_context));
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    mbedtls_ecdsa_init(key->ecdsa);

    ok = mbedtls_ecdsa_genkey(key->ecdsa,
                              pki_key_ecdsa_nid_to_mbed_gid(key->ecdsa_nid),
                              mbedtls_ctr_drbg_random,
                              ssh_get_mbedtls_ctr_drbg_context());

    if (ok != 0) {
        mbedtls_ecdsa_free(key->ecdsa);
        SAFE_FREE(key->ecdsa);
    }

    return SSH_OK;
}

int pki_privkey_build_dss(ssh_key key, ssh_string p, ssh_string q, ssh_string g,
        ssh_string pubkey, ssh_string privkey)
{
    (void) key;
    (void) p;
    (void) q;
    (void) g;
    (void) pubkey;
    (void) privkey;
    return SSH_ERROR;
}

int pki_pubkey_build_dss(ssh_key key, ssh_string p, ssh_string q, ssh_string g,
        ssh_string pubkey)
{
    (void) key;
    (void) p;
    (void) q;
    (void) g;
    (void) pubkey;
    return SSH_ERROR;
}

int pki_key_generate_dss(ssh_key key, int parameter)
{
    (void) key;
    (void) parameter;
    return SSH_ERROR;
}
#endif /* HAVE_LIBMBEDCRYPTO */
