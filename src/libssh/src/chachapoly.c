/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2015 by Aris Adamantiadis
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

#include "libssh/libssh.h"
#include "libssh/crypto.h"
#include "libssh/chacha.h"
#include "libssh/poly1305.h"
#include "libssh/misc.h"

/* size of the keys k1 and k2 as defined in specs */
#define CHACHA20_KEYLEN 32
struct chacha20_poly1305_keysched {
    /* key used for encrypting the length field*/
    struct chacha_ctx k1;
    /* key used for encrypting the packets */
    struct chacha_ctx k2;
};

#pragma pack(push, 1)
struct ssh_packet_header {
    uint32_t length;
    uint8_t payload[];
};
#pragma pack(pop)

static const uint8_t zero_block_counter[8] = {0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t payload_block_counter[8] = {1, 0, 0, 0, 0, 0, 0, 0};

static int chacha20_set_encrypt_key(struct ssh_cipher_struct *cipher,
                                    void *key,
                                    void *IV)
{
    struct chacha20_poly1305_keysched *sched;
    uint8_t *u8key = key;
    (void)IV;

    if (cipher->chacha20_schedule == NULL) {
        sched = malloc(sizeof *sched);
        if (sched == NULL){
            return -1;
        }
    } else {
        sched = cipher->chacha20_schedule;
    }

    chacha_keysetup(&sched->k2, u8key, CHACHA20_KEYLEN * 8);
    chacha_keysetup(&sched->k1, u8key + CHACHA20_KEYLEN, CHACHA20_KEYLEN * 8);
    cipher->chacha20_schedule = sched;

    return 0;
}

/**
 * @internal
 *
 * @brief encrypts an outgoing packet with chacha20 and authenticate it
 * with poly1305.
 */
static void chacha20_poly1305_aead_encrypt(struct ssh_cipher_struct *cipher,
                                           void *in,
                                           void *out,
                                           size_t len,
                                           uint8_t *tag,
                                           uint64_t seq)
{
    struct ssh_packet_header *in_packet = in, *out_packet = out;
    uint8_t poly1305_ctx[POLY1305_KEYLEN] = {0};
    struct chacha20_poly1305_keysched *keys = cipher->chacha20_schedule;

    seq = htonll(seq);
    /* step 1, prepare the poly1305 key */
    chacha_ivsetup(&keys->k2, (uint8_t *)&seq, zero_block_counter);
    chacha_encrypt_bytes(&keys->k2,
                         poly1305_ctx,
                         poly1305_ctx,
                         POLY1305_KEYLEN);

    /* step 2, encrypt length field */
    chacha_ivsetup(&keys->k1, (uint8_t *)&seq, zero_block_counter);
    chacha_encrypt_bytes(&keys->k1,
                         (uint8_t *)&in_packet->length,
                         (uint8_t *)&out_packet->length,
                         sizeof(uint32_t));

    /* step 3, encrypt packet payload */
    chacha_ivsetup(&keys->k2, (uint8_t *)&seq, payload_block_counter);
    chacha_encrypt_bytes(&keys->k2,
                         in_packet->payload,
                         out_packet->payload,
                         len - sizeof(uint32_t));

    /* ssh_log_hexdump("poly1305_ctx", poly1305_ctx, sizeof(poly1305_ctx)); */
    /* step 4, compute the MAC */
    poly1305_auth(tag, (uint8_t *)out_packet, len, poly1305_ctx);
    /* ssh_log_hexdump("poly1305 src", (uint8_t *)out_packet, len);
    ssh_log_hexdump("poly1305 tag", tag, POLY1305_TAGLEN); */
}

static int chacha20_poly1305_aead_decrypt_length(
        struct ssh_cipher_struct *cipher,
        void *in,
        uint8_t *out,
        size_t len,
        uint64_t seq)
{
    struct chacha20_poly1305_keysched *keys = cipher->chacha20_schedule;

    if (len < sizeof(uint32_t)) {
        return SSH_ERROR;
    }
    seq = htonll(seq);

    chacha_ivsetup(&keys->k1, (uint8_t *)&seq, zero_block_counter);
    chacha_encrypt_bytes(&keys->k1,
                         in,
                         (uint8_t *)out,
                         sizeof(uint32_t));
    return SSH_OK;
}

static int chacha20_poly1305_aead_decrypt(struct ssh_cipher_struct *cipher,
                                          void *complete_packet,
                                          uint8_t *out,
                                          size_t encrypted_size,
                                          uint64_t seq)
{
    uint8_t poly1305_ctx[POLY1305_KEYLEN] = {0};
    uint8_t tag[POLY1305_TAGLEN] = {0};
    struct chacha20_poly1305_keysched *keys = cipher->chacha20_schedule;
    uint8_t *mac = (uint8_t *)complete_packet + sizeof(uint32_t) + encrypted_size;
    int cmp;

    seq = htonll(seq);

    ZERO_STRUCT(poly1305_ctx);
    chacha_ivsetup(&keys->k2, (uint8_t *)&seq, zero_block_counter);
    chacha_encrypt_bytes(&keys->k2,
                         poly1305_ctx,
                         poly1305_ctx,
                         POLY1305_KEYLEN);
#if 0
    ssh_log_hexdump("poly1305_ctx", poly1305_ctx, sizeof(poly1305_ctx));
#endif

    poly1305_auth(tag, (uint8_t *)complete_packet, encrypted_size +
            sizeof(uint32_t), poly1305_ctx);
#if 0
    ssh_log_hexdump("poly1305 src",
                   (uint8_t*)complete_packet,
                   encrypted_size + 4);
    ssh_log_hexdump("poly1305 tag", tag, POLY1305_TAGLEN);
    ssh_log_hexdump("received tag", mac, POLY1305_TAGLEN);
#endif

    cmp = memcmp(tag, mac, POLY1305_TAGLEN);
    if(cmp != 0) {
        /* mac error */
        SSH_LOG(SSH_LOG_PACKET,"poly1305 verify error");
        return SSH_ERROR;
    }
    chacha_ivsetup(&keys->k2, (uint8_t *)&seq, payload_block_counter);
    chacha_encrypt_bytes(&keys->k2,
                         (uint8_t *)complete_packet + sizeof(uint32_t),
                         out,
                         encrypted_size);

    return SSH_OK;
}

static void chacha20_cleanup(struct ssh_cipher_struct *cipher) {
    SAFE_FREE(cipher->chacha20_schedule);
}

const struct ssh_cipher_struct chacha20poly1305_cipher = {
    .ciphertype = SSH_AEAD_CHACHA20_POLY1305,
    .name = "chacha20-poly1305@openssh.com",
    .blocksize = 8,
    .lenfield_blocksize = 4,
    .keylen = sizeof(struct chacha20_poly1305_keysched),
    .keysize = 512,
    .tag_size = POLY1305_TAGLEN,
    .set_encrypt_key = chacha20_set_encrypt_key,
    .set_decrypt_key = chacha20_set_encrypt_key,
    .aead_encrypt = chacha20_poly1305_aead_encrypt,
    .aead_decrypt_length = chacha20_poly1305_aead_decrypt_length,
    .aead_decrypt = chacha20_poly1305_aead_decrypt,
    .cleanup = chacha20_cleanup
};

const struct ssh_cipher_struct *ssh_get_chacha20poly1305_cipher(void)
{
    return &chacha20poly1305_cipher;
}
