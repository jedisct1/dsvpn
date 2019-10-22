#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __SSSE3__
#include <x86intrin.h>
#endif
#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "charm.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NATIVE_BIG_ENDIAN
#endif
#ifndef NATIVE_BIG_ENDIAN
#ifndef NATIVE_LITTLE_ENDIAN
#define NATIVE_LITTLE_ENDIAN
#endif
#endif

#ifndef XOODOO_ROUNDS
#define XOODOO_ROUNDS 12
#endif

static inline void mem_cpy(unsigned char *dst, const unsigned char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static const uint32_t RK[12] = { 0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014,
                                 0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012 };

#ifdef __SSSE3__
#define ROL32in128(x, b) _mm_or_si128(_mm_slli_epi32((x), (b)), _mm_srli_epi32((x), 32 - (b)))

static void permute(uint32_t st[12])
{
    const __m128i rhoEast2 = _mm_set_epi32(0x06050407, 0x02010003, 0x0e0d0c0f, 0x0a09080b);
    __m128i       a, b, c, p, e;
    int           r;

    a = _mm_loadu_si128((const __m128i *) (const void *) &st[0]);
    b = _mm_loadu_si128((const __m128i *) (const void *) &st[4]);
    c = _mm_loadu_si128((const __m128i *) (const void *) &st[8]);
    for (r = 0; r < XOODOO_ROUNDS; r++) {
        p = _mm_shuffle_epi32(_mm_xor_si128(_mm_xor_si128(a, b), c), 0x93);
        e = ROL32in128(p, 5);
        p = ROL32in128(p, 14);
        e = _mm_xor_si128(e, p);
        a = _mm_xor_si128(a, e);
        b = _mm_xor_si128(b, e);
        c = _mm_xor_si128(c, e);
        b = _mm_shuffle_epi32(b, 0x93);
        c = ROL32in128(c, 11);
        a = _mm_xor_si128(a, _mm_set_epi32(0, 0, 0, RK[r]));
        a = _mm_xor_si128(a, _mm_andnot_si128(b, c));
        b = _mm_xor_si128(b, _mm_andnot_si128(c, a));
        c = _mm_xor_si128(c, _mm_andnot_si128(a, b));
        b = ROL32in128(b, 1);
        c = _mm_shuffle_epi8(c, rhoEast2);
    }
    _mm_storeu_si128((__m128i *) (void *) &st[0], a);
    _mm_storeu_si128((__m128i *) (void *) &st[4], b);
    _mm_storeu_si128((__m128i *) (void *) &st[8], c);
}
#elif defined(__ARM_NEON) || defined(__aarch64__)
#define ROL32in128(x, b) vsriq_n_u32(vshlq_n_u32((x), (b)), (x), 32 - (b))

static void permute(uint32_t st[12])
{
    uint32x4_t a, b, c, d, e, f;
    int        r;

    a = vld1q_u32((const uint32_t *) (const void *) &st[0]);
    b = vld1q_u32((const uint32_t *) (const void *) &st[4]);
    c = vld1q_u32((const uint32_t *) (const void *) &st[8]);
    for (r = 0; r < XOODOO_ROUNDS; r++) {
        d = veorq_u32(veorq_u32(a, b), c);
        d = vextq_u32(d, d, 3);
        e = ROL32in128(d, 5);
        f = ROL32in128(d, 14);
        e = veorq_u32(e, f);
        a = veorq_u32(a, e);
        b = veorq_u32(b, e);
        f = veorq_u32(c, e);
        c = ROL32in128(f, 11);
        b = vextq_u32(b, b, 3);
        a = veorq_u32(a, vsetq_lane_u32(RK[r], vmovq_n_u32(0), 0));
        e = vbicq_u32(c, b);
        d = vbicq_u32(a, c);
        f = vbicq_u32(b, a);
        a = veorq_u32(a, e);
        d = veorq_u32(b, d);
        c = veorq_u32(c, f);
        f = vextq_u32(c, c, 2);
        b = ROL32in128(d, 1);
        c = ROL32in128(f, 8);
    }
    vst1q_u32((uint32_t *) (void *) &st[0], a);
    vst1q_u32((uint32_t *) (void *) &st[4], b);
    vst1q_u32((uint32_t *) (void *) &st[8], c);
}
#else
#define ROTR32(x, b) (uint32_t)(((x) >> (b)) | ((x) << (32 - (b))))
#define SWAP32(s, u, v)              \
    do {                             \
        t      = (s)[u];             \
        (s)[u] = (s)[v], (s)[v] = t; \
    } while (0)

static void permute(uint32_t st[12])
{
    uint32_t e[4], a, b, c, t, r, i;

    for (r = 0; r < XOODOO_ROUNDS; r++) {
        for (i = 0; i < 4; i++) {
            e[i] = ROTR32(st[i] ^ st[i + 4] ^ st[i + 8], 18);
            e[i] ^= ROTR32(e[i], 9);
        }
        for (i = 0; i < 12; i++) {
            st[i] ^= e[(i - 1) & 3];
        }
        SWAP32(st, 7, 4);
        SWAP32(st, 7, 5);
        SWAP32(st, 7, 6);
        st[0] ^= RK[r];
        for (i = 0; i < 4; i++) {
            a         = st[i];
            b         = st[i + 4];
            c         = ROTR32(st[i + 8], 21);
            st[i + 8] = ROTR32((b & ~a) ^ c, 24);
            st[i + 4] = ROTR32((a & ~c) ^ b, 31);
            st[i] ^= c & ~b;
        }
        SWAP32(st, 8, 10);
        SWAP32(st, 9, 11);
    }
}
#endif

static inline void endian_swap_rate(uint32_t st[12])
{
    (void) st;
#ifdef NATIVE_BIG_ENDIAN
    size_t i;
    for (i = 0; i < 4; i++) {
        st[i] = __builtin_bswap32(st[i]);
    }
#endif
}

static inline void endian_swap_all(uint32_t st[12])
{
    (void) st;
#ifdef NATIVE_BIG_ENDIAN
    size_t i;
    for (i = 0; i < 12; i++) {
        st[i] = __builtin_bswap32(st[i]);
    }
#endif
}

static inline void xor128(void *out, const void *in)
{
#ifdef __SSSE3__
    _mm_storeu_si128((__m128i *) out,
                     _mm_xor_si128(_mm_loadu_si128((const __m128i *) out),
                                   _mm_loadu_si128((const __m128i *) in)));
#else
    unsigned char *      out_ = (unsigned char *) out;
    const unsigned char *in_  = (const unsigned char *) in;
    size_t               i;

    for (i = 0; i < 16; i++) {
        out_[i] ^= in_[i];
    }
#endif
}

static inline int equals(const unsigned char a[16], const unsigned char b[16], size_t len)
{
    unsigned char d = 0;
    size_t        i;

    for (i = 0; i < len; i++) {
        d |= a[i] ^ b[i];
    }
    return 1 & ((d - 1) >> 8);
}

static inline void squeeze_permute(uint32_t st[12], unsigned char dst[16])
{
    endian_swap_rate(st);
    memcpy(dst, st, 16);
    endian_swap_rate(st);
    permute(st);
}

void uc_state_init(uint32_t st[12], const unsigned char key[32], const unsigned char iv[16])
{
    memcpy(&st[0], iv, 16);
    memcpy(&st[4], key, 32);
    endian_swap_all(st);
    permute(st);
}

void uc_encrypt(uint32_t st[12], unsigned char *msg, size_t msg_len, unsigned char tag[16])
{
    unsigned char squeezed[16];
    unsigned char padded[16 + 1];
    size_t        off = 0;
    size_t        leftover;

    if (msg_len > 16) {
        for (; off < msg_len - 16; off += 16) {
            endian_swap_rate(st);
            memcpy(squeezed, st, 16);
            xor128(st, &msg[off]);
            endian_swap_rate(st);
            xor128(&msg[off], squeezed);
            permute(st);
        }
    }
    leftover = msg_len - off;
    memset(padded, 0, 16);
    mem_cpy(padded, &msg[off], leftover);
    padded[leftover] = 0x80;
    endian_swap_rate(st);
    memcpy(squeezed, st, 16);
    xor128(st, padded);
    endian_swap_rate(st);
    st[11] ^= (1UL << 24 | (uint32_t) leftover >> 4 << 25 | 1UL << 26);
    xor128(padded, squeezed);
    mem_cpy(&msg[off], padded, leftover);
    permute(st);
    squeeze_permute(st, tag);
}

int uc_decrypt(uint32_t st[12], unsigned char *msg, size_t msg_len,
               const unsigned char *expected_tag, size_t expected_tag_len)
{
    unsigned char tag[16];
    unsigned char squeezed[16];
    unsigned char padded[16 + 1];
    size_t        off = 0;
    size_t        leftover;

    if (msg_len > 16) {
        for (; off < msg_len - 16; off += 16) {
            endian_swap_rate(st);
            memcpy(squeezed, st, 16);
            xor128(&msg[off], squeezed);
            xor128(st, &msg[off]);
            endian_swap_rate(st);
            permute(st);
        }
    }
    leftover = msg_len - off;
    memset(padded, 0, 16);
    mem_cpy(padded, &msg[off], leftover);
    endian_swap_rate(st);
    memset(squeezed, 0, 16);
    mem_cpy(squeezed, (const unsigned char *) (const void *) st, leftover);
    xor128(&padded, squeezed);
    padded[leftover] = 0x80;
    xor128(st, padded);
    endian_swap_rate(st);
    st[11] ^= (1UL << 24 | (uint32_t) leftover >> 4 << 25 | 1UL << 26);
    mem_cpy(&msg[off], padded, leftover);
    permute(st);
    squeeze_permute(st, tag);
    if (equals(expected_tag, tag, expected_tag_len) == 0) {
        memset(msg, 0, msg_len);
        return -1;
    }
    return 0;
}

void uc_hash(uint32_t st[12], unsigned char h[32], const unsigned char *msg, size_t len)
{
    unsigned char padded[16 + 1];
    size_t        off = 0;
    size_t        leftover;

    if (len > 16) {
        for (; off < len - 16; off += 16) {
            endian_swap_rate(st);
            xor128(st, &msg[off]);
            endian_swap_rate(st);
            permute(st);
        }
    }
    leftover = len - off;
    memset(padded, 0, 16);
    mem_cpy(padded, &msg[off], leftover);
    padded[leftover] = 0x80;
    endian_swap_rate(st);
    xor128(st, padded);
    endian_swap_rate(st);
    st[11] ^= (1UL << 24 | (uint32_t) leftover >> 4 << 25);
    permute(st);
    squeeze_permute(st, &h[0]);
    squeeze_permute(st, &h[16]);
}

void uc_memzero(void *buf, size_t len)
{
    volatile unsigned char *volatile buf_ = (volatile unsigned char *volatile) buf;
    size_t i                              = (size_t) 0U;

    while (i < len) {
        buf_[i++] = 0U;
    }
}

void uc_randombytes_buf(void *buf, size_t len)
{
#ifdef __linux__
    if ((size_t) syscall(SYS_getrandom, buf, (int) len, 0) != len) {
        abort();
    }
#else
    arc4random_buf(buf, len);
#endif
}
