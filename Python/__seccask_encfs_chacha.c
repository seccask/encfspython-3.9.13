/**
 * @file __seccask_encfs.c
 * @brief Chacha20 Stream cipher from github:Legrandin/pycryptodome
 */

#include "internal/seccask_encfs_chacha.h"
#include <assert.h>

#ifndef _ERRORS_H
#define _ERRORS_H

/** Standard errors common to all ciphers **/
#define ERR_NULL                1
#define ERR_MEMORY              2
#define ERR_NOT_ENOUGH_DATA     3
#define ERR_ENCRYPT             4
#define ERR_DECRYPT             5
#define ERR_KEY_SIZE            6
#define ERR_NONCE_SIZE          7
#define ERR_NR_ROUNDS           8
#define ERR_DIGEST_SIZE         9
#define ERR_MAX_DATA            10
#define ERR_MAX_OFFSET          11
#define ERR_BLOCK_SIZE          12
#define ERR_TAG_SIZE            13
#define ERR_VALUE               14
#define ERR_EC_POINT            15
#define ERR_EC_CURVE            16
#define ERR_MODULUS             17
#define ERR_UNKNOWN             32

#endif

/* ===================================================================
 *
 * Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#ifndef ENDIANESS_H
#define ENDIANESS_H

static inline void u32to8_little(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
#endif
}

static inline void u8to32_little(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
#endif
}

static inline void u32to8_big(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)(*w >> 24);
    p[1] = (uint8_t)(*w >> 16);
    p[2] = (uint8_t)(*w >> 8);
    p[3] = (uint8_t)*w;
#endif
}

static inline void u8to32_big(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[3] | (uint32_t)p[2]<<8 | (uint32_t)p[1]<<16 | (uint32_t)p[0]<<24;
#endif
}

static inline uint32_t load_u8to32_little(const uint8_t *p)
{
    uint32_t w;

    u8to32_little(&w, p);
    return w;
}

static inline uint32_t load_u8to32_big(const uint8_t *p)
{
    uint32_t w;

    u8to32_big(&w, p);
    return w;
}

#define LOAD_U32_LITTLE(p) load_u8to32_little(p)
#define LOAD_U32_BIG(p) load_u8to32_big(p)

#define STORE_U32_LITTLE(p, w) u32to8_little((p), &(w))
#define STORE_U32_BIG(p, w) u32to8_big((p), &(w))

static inline void u64to8_little(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
    p[4] = (uint8_t)(*w >> 32);
    p[5] = (uint8_t)(*w >> 40);
    p[6] = (uint8_t)(*w >> 48);
    p[7] = (uint8_t)(*w >> 56);
#endif
}

static inline void u8to64_little(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0]       |
         (uint64_t)p[1] << 8  |
         (uint64_t)p[2] << 16 |
         (uint64_t)p[3] << 24 |
         (uint64_t)p[4] << 32 |
         (uint64_t)p[5] << 40 |
         (uint64_t)p[6] << 48 |
         (uint64_t)p[7] << 56;
#endif
}

static inline void u64to8_big(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)(*w >> 56);
    p[1] = (uint8_t)(*w >> 48);
    p[2] = (uint8_t)(*w >> 40);
    p[3] = (uint8_t)(*w >> 32);
    p[4] = (uint8_t)(*w >> 24);
    p[5] = (uint8_t)(*w >> 16);
    p[6] = (uint8_t)(*w >> 8);
    p[7] = (uint8_t)*w;
#endif
}

static inline void u8to64_big(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0] << 56 |
         (uint64_t)p[1] << 48 |
         (uint64_t)p[2] << 40 |
         (uint64_t)p[3] << 32 |
         (uint64_t)p[4] << 24 |
         (uint64_t)p[5] << 16 |
         (uint64_t)p[6] << 8  |
         (uint64_t)p[7];
#endif
}

static inline uint64_t load_u8to64_little(const uint8_t *p)
{
    uint64_t w;

    u8to64_little(&w, p);
    return w;
}

static inline uint64_t load_u8to64_big(const uint8_t *p)
{
    uint64_t w;

    u8to64_big(&w, p);
    return w;
}

#define LOAD_U64_LITTLE(p) load_u8to64_little(p)
#define LOAD_U64_BIG(p) load_u8to64_big(p)

#define STORE_U64_LITTLE(p, w) u64to8_little((p), &(w))
#define STORE_U64_BIG(p, w) u64to8_big((p), &(w))

/**
 * Convert a big endian-encoded number in[] into a little-endian
 * 64-bit word array x[]. There must be enough words to contain the entire
 * number.
 */
static inline int bytes_to_words(uint64_t *x, size_t words, const uint8_t *in, size_t len)
{
    uint8_t buf8[8];
    size_t words_used, bytes_in_msw, i;
    uint64_t *xp;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == in)
        return ERR_NULL;

    memset(x, 0, words*sizeof(uint64_t));

    /** Shorten the input **/
    for (; len > 0 && 0 == *in; in++, len--);
    if (0 == len)
        return 0;

    /** How many words we actually need **/
    words_used = (len + 7) / 8;
    if (words_used > words)
        return ERR_MAX_DATA;

    /** Not all bytes in the most-significant words are used **/
    bytes_in_msw = len % 8;
    if (bytes_in_msw == 0)
        bytes_in_msw = 8;

    /** Do most significant word **/
    memset(buf8, 0, 8);
    memcpy(buf8 + (8 - bytes_in_msw), in, bytes_in_msw);
    xp = &x[words_used-1];
    *xp = LOAD_U64_BIG(buf8);
    in += bytes_in_msw;

    /** Do the other words **/
    for (i=0; i<words_used-1; i++, in += 8) {
        xp--;
        *xp = LOAD_U64_BIG(in);
    }
    return 0;
}

/**
 * Convert a little-endian 64-bit word array x[] into a big endian-encoded
 * number out[]. The number is left-padded with zeroes if required.
 */
static inline int words_to_bytes(uint8_t *out, size_t len, const uint64_t *x, size_t words)
{
    size_t i;
    const uint64_t *msw;
    uint8_t buf8[8];
    size_t partial, real_len;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == out)
        return ERR_NULL;

    memset(out, 0, len);

    /* Shorten the input, so that the rightmost word is
     * the most significant one (and non-zero)
     */
    for (; words>0 && x[words-1]==0; words--);
    if (words == 0)
        return 0;
    msw = &x[words-1];

    /* Find how many non-zero bytes there are in the most-significant word */
    STORE_U64_BIG(buf8, *msw);
    for (partial=8; partial>0 && buf8[8-partial] == 0; partial--);
    assert(partial > 0);
    
    /** Check if there is enough room **/
    real_len = partial + 8*(words-1);
    if (real_len > len)
        return ERR_MAX_DATA;

    /** Pad **/
    out += len - real_len;

    /** Most significant word **/
    memcpy(out, buf8+(8-partial), partial);
    out += partial;
    msw--;

    /** Any remaining full word **/
    for (i=0; i<words-1; i++, out += 8, msw--)
        STORE_U64_BIG(out, *msw);

    return 0;
}

#endif

/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */
#define KEY_SIZE   32

#define ROTL(q, n)  (((q) << (n)) | ((q) >> (32 - (n))))

#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
}

int chacha20_init(chacha_state_t **pState,
                             const uint8_t *key,
                             size_t keySize,
                             const uint8_t *nonce,
                             size_t nonceSize)
{
    chacha_state_t *hs;
    unsigned i;

    if (NULL == pState || NULL == nonce)
        return ERR_NULL;

    if (NULL == key || keySize != KEY_SIZE)
        return ERR_KEY_SIZE;

    if (nonceSize != 8 && nonceSize != 12 && nonceSize != 16)
        return ERR_NONCE_SIZE;

    *pState = hs = (chacha_state_t*) calloc(1, sizeof(chacha_state_t));
    if (NULL == hs)
        return ERR_MEMORY;
    memset(*pState, 0, sizeof(chacha_state_t));

    hs->h[0] = 0x61707865;
    hs->h[1] = 0x3320646e;
    hs->h[2] = 0x79622d32;
    hs->h[3] = 0x6b206574;

    /** Move 256-bit/32-byte key into h[4..11] **/
    for (i=0; i<32/4; i++) {
        hs->h[4+i] = LOAD_U32_LITTLE(key + 4*i);
    }

    switch (nonceSize) {
    case 8: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  BBBBBBBB  nnnnnnnn  nnnnnnnn
                c=constant k=key b=blockcount(low) B=blockcount(high) n=nonce
                */

                /** h[12] remains 0 (offset) **/
                /** h[13] remains 0 (offset) **/
                hs->h[14] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 4);
                break;
                }
    case 12: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
                c=constant k=key b=blockcount n=nonce
                */

                /** h[12] remains 0 (offset) **/
                hs->h[13] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 8);
                break;
            }
    case 16: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
                c=constant k=key n=nonce
                */

                hs->h[12] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[13] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 8);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 12);
                break;
            }
    default:
             return ERR_NONCE_SIZE;
    }

    hs->nonceSize = nonceSize;
    hs->usedKeyStream = sizeof(hs->keyStream);

    return 0;
}

int chacha20_destroy(chacha_state_t *state)
{
    if (NULL == state)
        return ERR_NULL;
    free(state);
    return 0;
}

static int chacha20_core(chacha_state_t *state, uint32_t h[16])
{
    unsigned i;

    memcpy(h, state->h, sizeof(state->h));

    for (i=0; i<10; i++) {
        /** Column round **/
        QR(h[0], h[4], h[ 8], h[12]);
        QR(h[1], h[5], h[ 9], h[13]);
        QR(h[2], h[6], h[10], h[14]);
        QR(h[3], h[7], h[11], h[15]);
        /** Diagonal round **/
        QR(h[0], h[5], h[10], h[15]);
        QR(h[1], h[6], h[11], h[12]);
        QR(h[2], h[7], h[ 8], h[13]);
        QR(h[3], h[4], h[ 9], h[14]);
    }

    for (i=0; i<16; i++) {
        uint32_t sum;

        sum = h[i] + state->h[i];
        STORE_U32_LITTLE(state->keyStream + 4*i, sum);
    }

    state->usedKeyStream = 0;

    switch (state->nonceSize) {
    case 8: {
                /** Nonce is 64 bits, counter is two words **/
                if (++state->h[12] == 0) {
                    if (++state->h[13] == 0) {
                        return ERR_MAX_DATA;
                    }
                }
                break;
            }
    case 12: {
                /** Nonce is 96 bits, counter is one word **/
                if (++state->h[12] == 0) {
                    return ERR_MAX_DATA;
                }
                break;
            }
    case 16: {
                 /** Nonce is 192 bits, there is no counter as this is intended
                  * to be run once only (HChaCha20) **/
                 break;
            }
    }

    return 0;
}

int chacha20_encrypt(chacha_state_t *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len)
{
    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    while (len > 0) {
        unsigned keyStreamToUse;
        unsigned i;
        uint32_t h[16];

        if (state->usedKeyStream == sizeof(state->keyStream)) {
            int result;

            result = chacha20_core(state, h);
            if (result)
                return result;
        }

        keyStreamToUse = (unsigned)MIN(len, sizeof(state->keyStream) - state->usedKeyStream);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ state->keyStream[i + state->usedKeyStream];

        len -= keyStreamToUse;
        state->usedKeyStream += keyStreamToUse;
    }

    return 0;
}

int chacha20_seek(chacha_state_t *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset)
{
    int result;
    uint32_t h[16];

    if (NULL == state)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    if (offset >= sizeof(state->keyStream))
        return ERR_MAX_OFFSET;

    if (state->nonceSize == 8) {
        /** Nonce is 64 bits, counter is two words **/
        state->h[12] = (uint32_t)block_low;
        state->h[13] = (uint32_t)block_high;
    } else {
        /** Nonce is 96 bits, counter is one word **/
        if (block_high > 0) {
            return ERR_MAX_OFFSET;
        }
        state->h[12] = (uint32_t)block_low;
    }

    result = chacha20_core(state, h);
    if (result)
        return result;

    state->usedKeyStream = offset;

    return 0;
}

/*
 * Based on https://tools.ietf.org/html/draft-arciszewski-xchacha-03
 */
int hchacha20(const uint8_t key[KEY_SIZE],
                         const uint8_t nonce16[16],                 /* First 16 bytes of the 24 byte nonce */
                         uint8_t subkey[KEY_SIZE])
{
    chacha_state_t *pState;
    uint32_t h[16];

    if (NULL == key || NULL == nonce16 || NULL == subkey) {
        return ERR_NULL;
    }

    chacha20_init(&pState, key, KEY_SIZE, nonce16, 16);
    if (NULL == pState)
        return ERR_MEMORY;

    chacha20_core(pState, h);
    /* We only keep first and last row from the new state */
    STORE_U32_LITTLE(subkey + 0,  h[0]);
    STORE_U32_LITTLE(subkey + 4,  h[1]);
    STORE_U32_LITTLE(subkey + 8,  h[2]);
    STORE_U32_LITTLE(subkey + 12, h[3]);
    STORE_U32_LITTLE(subkey + 16, h[12]);
    STORE_U32_LITTLE(subkey + 20, h[13]);
    STORE_U32_LITTLE(subkey + 24, h[14]);
    STORE_U32_LITTLE(subkey + 28, h[15]);
    chacha20_destroy(pState);

    return 0;
}

#ifdef CHACHA_PROFILE
int main(void)
{
    const unsigned data_size = 1024*1024;
    const uint8_t key[32] = "12345678901234561234567890123456";
    const uint8_t nonce[8] = "12345678";
    chacha_state_t *state;
    uint8_t *data;

    data = malloc(data_size);
    for (int i=0; i<data_size; i++) {
        data[i] = (uint8_t) i;
    }

    chacha20_init(&state, key, 32, nonce, 8);

    for (int i=0; i<1024; i++)
        chacha20_encrypt(state, data, data, data_size);

    chacha20_destroy(state);
    free(data);
}
#endif