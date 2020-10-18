/* $OpenBSD: ed25519.c,v 1.3 2013/12/09 11:03:45 markus Exp $ */

/*
 * Public Domain, Authors: Daniel J. Bernstein, Niels Duif, Tanja Lange,
 * Peter Schwabe, Bo-Yin Yang.
 * Copied from supercop-20130419/crypto_sign/ed25519/ref/ed25519.c
 */

#include "config.h"

#include "libssh/libcrypto.h"
#include "libssh/wrapper.h"
#include "libssh/ge25519.h"
#include "libssh/sc25519.h"
#include "libssh/ed25519.h"

/*
 * Public Domain, Author: Daniel J. Bernstein
 * Copied from nacl-20110221/crypto_verify/32/ref/verify.c
 */

static int crypto_verify_32(const unsigned char *x,const unsigned char *y)
{
    unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
    F(0)
    F(1)
    F(2)
    F(3)
    F(4)
    F(5)
    F(6)
    F(7)
    F(8)
    F(9)
    F(10)
    F(11)
    F(12)
    F(13)
    F(14)
    F(15)
    F(16)
    F(17)
    F(18)
    F(19)
    F(20)
    F(21)
    F(22)
    F(23)
    F(24)
    F(25)
    F(26)
    F(27)
    F(28)
    F(29)
    F(30)
    F(31)

    return (1 & ((differentbits - 1) >> 8)) - 1;
}

static void get_hram(unsigned char *hram,
                     const unsigned char *sm,
                     const unsigned char *pk,
                     unsigned char *playground,
                     uint64_t smlen)
{
    uint64_t i;
    SHA512CTX ctx;
    for (i =  0;i < 32;++i)    playground[i] = sm[i];
    for (i = 32;i < 64;++i)    playground[i] = pk[i-32];
    for (i = 64;i < smlen;++i) playground[i] = sm[i];

    ctx = sha512_init();
    sha512_update(ctx, playground, smlen);
    sha512_final(hram, ctx);
}


int crypto_sign_ed25519_keypair(unsigned char *pk,
                                unsigned char *sk)
{
    sc25519 scsk;
    ge25519 gepk;
    SHA512CTX ctx;
    unsigned char extsk[64];
    int i;
    int ok;

    ok = ssh_get_random(sk, 32, 0);
    if (!ok) {
        return -1;
    }

    ctx = sha512_init();
    sha512_update(ctx, sk, 32);
    sha512_final(extsk, ctx);
    extsk[0] &= 248;
    extsk[31] &= 127;
    extsk[31] |= 64;

    sc25519_from32bytes(&scsk,extsk);

    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(pk, &gepk);
    for(i=0;i<32;i++) {
        sk[32 + i] = pk[i];
    }

    return 0;
}

int crypto_sign_ed25519(unsigned char *sm,
                        uint64_t *smlen,
                        const unsigned char *m,
                        uint64_t mlen,
                        const unsigned char *sk)
{
    sc25519 sck, scs, scsk;
    ge25519 ger;
    SHA512CTX ctx;
    unsigned char r[32];
    unsigned char s[32];
    unsigned char extsk[64];
    uint64_t i;
    unsigned char hmg[SHA512_DIGEST_LEN];
    unsigned char hram[SHA512_DIGEST_LEN];

    ctx = sha512_init();
    sha512_update(ctx, sk, 32);
    sha512_final(extsk, ctx);

    extsk[0] &= 248;
    extsk[31] &= 127;
    extsk[31] |= 64;

    *smlen = mlen + 64;
    for (i = 0;i < mlen; i++) {
        sm[64 + i] = m[i];
    }
    for (i = 0;i < 32; i++) {
        sm[32 + i] = extsk[32+i];
    }

    /* Generate k as h(extsk[32],...,extsk[63],m) */
    ctx = sha512_init();
    sha512_update(ctx, sm + 32, mlen + 32);
    sha512_final(hmg, ctx);

    /* Computation of R */
    sc25519_from64bytes(&sck, hmg);
    ge25519_scalarmult_base(&ger, &sck);
    ge25519_pack(r, &ger);

    /* Computation of s */
    for (i = 0; i < 32; i++) {
        sm[i] = r[i];
    }

    get_hram(hram, sm, sk+32, sm, mlen+64);

    sc25519_from64bytes(&scs, hram);
    sc25519_from32bytes(&scsk, extsk);
    sc25519_mul(&scs, &scs, &scsk);

    sc25519_add(&scs, &scs, &sck);

    sc25519_to32bytes(s,&scs); /* cat s */
    for (i = 0;i < 32; i++) {
        sm[32 + i] = s[i];
    }

    return 0;
}

int crypto_sign_ed25519_open(unsigned char *m,
                             uint64_t *mlen,
                             const unsigned char *sm,
                             uint64_t smlen,
                             const unsigned char *pk)
{
    unsigned int i;
    int ret;
    unsigned char t2[32];
    ge25519 get1, get2;
    sc25519 schram, scs;
    unsigned char hram[SHA512_DIGEST_LEN];

    *mlen = (uint64_t) -1;
    if (smlen < 64) return -1;

    if (ge25519_unpackneg_vartime(&get1, pk)) {
        return -1;
    }

    get_hram(hram,sm,pk,m,smlen);

    sc25519_from64bytes(&schram, hram);

    sc25519_from32bytes(&scs, sm+32);

    ge25519_double_scalarmult_vartime(&get2,
                                      &get1,
                                      &schram,
                                      &ge25519_base,
                                      &scs);
    ge25519_pack(t2, &get2);

    ret = crypto_verify_32(sm, t2);
    if (ret != 0) {
        for (i = 0; i < smlen - 64; i++) {
            m[i] = sm[i + 64];
        }
        *mlen = smlen-64;
    } else {
        for (i = 0; i < smlen - 64; i++) {
            m[i] = 0;
        }
    }

    return ret;
}
