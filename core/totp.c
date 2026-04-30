/*
 * totp.c — RFC 6238 TOTP implementation for LinuxAuthGuard
 *
 * Uses HMAC-SHA1 as specified in RFC 4226 (HOTP), extended with a
 * time-based counter per RFC 6238.  No external crypto library required —
 * SHA-1 and HMAC are implemented inline.
 *
 * Compile flags: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
 */

#include "include/totp.h"
#include "include/buffer_safe.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
 * SHA-1 (RFC 3174)
 * ---------------------------------------------------------------------- */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buf[64];
} sha1_ctx_t;

#define ROL32(v,n)  (((v)<<(n))|((v)>>(32-(n))))

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t blk[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, t;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i*4]   << 24)
             | ((uint32_t)blk[i*4+1] << 16)
             | ((uint32_t)blk[i*4+2] <<  8)
             |  (uint32_t)blk[i*4+3];
    }
    for (i = 16; i < 80; i++)
        w[i] = ROL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3]; e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        if      (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999u; }
        else if (i < 40) { f =  b ^ c ^ d;          k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c)|(b & d)|(c & d); k = 0x8f1bbcdcu; }
        else             { f =  b ^ c ^ d;          k = 0xca62c1d6u; }
        t = ROL32(a,5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b,30); b = a; a = t;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d; ctx->state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xc3d2e1f0u;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t j = (ctx->count[0] >> 3) & 63;
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (uint32_t)(len << 3))
        ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);

    size_t i;
    if ((j + len) > 63) {
        memcpy(ctx->buf + j, data, (i = 64 - j));
        sha1_transform(ctx, ctx->buf);
        for (; i + 63 < len; i += 64)
            sha1_transform(ctx, data + i);
        j = 0;
    } else {
        i = 0;
    }
    memcpy(ctx->buf + j, data + i, len - i);
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20])
{
    uint8_t pad[64];
    uint8_t bits[8];
    uint32_t i, j;

    for (i = 0; i < 8; i++)
        bits[i] = (uint8_t)(ctx->count[i < 4 ? 1 : 0] >>
                            (24 - 8 * (i & 3)));

    sha1_update(ctx, (const uint8_t *)"\x80", 1);
    while ((ctx->count[0] >> 3 & 63) != 56) {
        memset(pad, 0, sizeof(pad));
        sha1_update(ctx, pad, 1);
    }
    sha1_update(ctx, bits, 8);

    for (i = 0; i < 20; i++)
        digest[i] = (uint8_t)(ctx->state[i >> 2] >> (24 - 8 * (i & 3)));

    lag_secure_zero(ctx, sizeof(*ctx));
    (void)j;
}

/* -------------------------------------------------------------------------
 * HMAC-SHA1
 * ---------------------------------------------------------------------- */

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t mac[20])
{
    uint8_t k[64];
    uint8_t ko[64], ki[64];
    sha1_ctx_t ctx;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < 64; i++) {
        ko[i] = k[i] ^ 0x5cu;
        ki[i] = k[i] ^ 0x36u;
    }

    /* inner */
    sha1_init(&ctx);
    sha1_update(&ctx, ki, 64);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, mac);

    /* outer */
    sha1_init(&ctx);
    sha1_update(&ctx, ko, 64);
    sha1_update(&ctx, mac, 20);
    sha1_final(&ctx, mac);

    lag_secure_zero(k,  sizeof(k));
    lag_secure_zero(ko, sizeof(ko));
    lag_secure_zero(ki, sizeof(ki));
}

/* -------------------------------------------------------------------------
 * Base32 decode
 * ---------------------------------------------------------------------- */

int base32_decode(const char *in, uint8_t *out, size_t out_max)
{
    static const int8_t tbl[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['2']=26,['3']=27,['4']=28,['5']=29,['6']=30,['7']=31,
        ['a']=0,['b']=1,['c']=2,['d']=3,['e']=4,['f']=5,['g']=6,['h']=7,
        ['i']=8,['j']=9,['k']=10,['l']=11,['m']=12,['n']=13,['o']=14,['p']=15,
        ['q']=16,['r']=17,['s']=18,['t']=19,['u']=20,['v']=21,['w']=22,['x']=23,
        ['y']=24,['z']=25,
    };

    size_t out_pos = 0;
    uint32_t buf   = 0;
    int      bits  = 0;

    for (const char *p = in; *p && *p != '='; p++) {
        int8_t v = tbl[(unsigned char)*p];
        if (v < 0) continue; /* skip unknowns */
        buf  = (buf << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (out_pos >= out_max) return -1;
            out[out_pos++] = (uint8_t)((buf >> bits) & 0xff);
        }
    }
    return (int)out_pos;
}

/* -------------------------------------------------------------------------
 * HOTP counter → code
 * ---------------------------------------------------------------------- */

static uint32_t hotp(const uint8_t *key, size_t key_len, uint64_t counter)
{
    uint8_t msg[8];
    uint8_t mac[20];

    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(counter & 0xff);
        counter >>= 8;
    }

    hmac_sha1(key, key_len, msg, 8, mac);

    int offset = mac[19] & 0x0f;
    uint32_t code = (((uint32_t)mac[offset]   & 0x7f) << 24)
                  | (((uint32_t)mac[offset+1] & 0xff) << 16)
                  | (((uint32_t)mac[offset+2] & 0xff) <<  8)
                  |  ((uint32_t)mac[offset+3] & 0xff);

    /* modulus for TOTP_DIGITS digits */
    static const uint32_t pow10[8] = {
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000
    };
    return code % pow10[TOTP_DIGITS];
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int totp_generate(const char *secret, uint64_t ts,
                  char *out, size_t out_len)
{
    if (!secret || !out || out_len < (size_t)(TOTP_DIGITS + 1))
        return -1;

    uint8_t key[TOTP_SECRET_MAX];
    int key_len = base32_decode(secret, key, sizeof(key));
    if (key_len <= 0) return -1;

    if (ts == 0) ts = (uint64_t)time(NULL);
    uint64_t counter = ts / TOTP_STEP_SECONDS;

    uint32_t code = hotp(key, (size_t)key_len, counter);
    snprintf(out, out_len, "%0*u", TOTP_DIGITS, code);

    lag_secure_zero(key, sizeof(key));
    return 0;
}

int totp_verify(const char *secret, const char *code, uint64_t ts)
{
    if (!secret || !code) return -1;

    /* Validate code: must be exactly TOTP_DIGITS decimal digits */
    size_t code_len = strnlen(code, TOTP_DIGITS + 2);
    if (code_len != TOTP_DIGITS) return 0;
    for (size_t i = 0; i < code_len; i++)
        if (!isdigit((unsigned char)code[i])) return 0;

    uint8_t key[TOTP_SECRET_MAX];
    int key_len = base32_decode(secret, key, sizeof(key));
    if (key_len <= 0) return -1;

    if (ts == 0) ts = (uint64_t)time(NULL);
    uint64_t T = ts / TOTP_STEP_SECONDS;

    char generated[TOTP_DIGITS + 1];
    for (int delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
        uint32_t c = hotp(key, (size_t)key_len, (uint64_t)((int64_t)T + delta));
        snprintf(generated, sizeof(generated), "%0*u", TOTP_DIGITS, c);
        if (strncmp(generated, code, TOTP_DIGITS) == 0) {
            lag_secure_zero(key, sizeof(key));
            lag_secure_zero(generated, sizeof(generated));
            return 1;
        }
    }

    lag_secure_zero(key, sizeof(key));
    lag_secure_zero(generated, sizeof(generated));
    return 0;
}
