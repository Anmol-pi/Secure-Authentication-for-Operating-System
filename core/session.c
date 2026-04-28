/*
 * session.c — Secure session token management for LinuxAuthGuard
 *
 * - Tokens are 256-bit random values from /dev/urandom
 * - Stored SHA-256 hashed in SQLite
 * - Returned to caller as 64-character hex strings
 *
 * Depends on libsqlite3.
 * Compile flags: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
 */

#include "include/session.h"
#include "include/pam_linuxauthguard.h"
#include "include/buffer_safe.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>

/* -------------------------------------------------------------------------
 * Minimal SHA-256 (no dependency on OpenSSL for the session module)
 * ---------------------------------------------------------------------- */

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buf[64];
    size_t   buf_len;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(v,n) (((v)>>(n))|((v)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x)    (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define SIG1(x)    (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define sig0(x)    (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define sig1(x)    (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t *blk)
{
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++)
        w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)
            |((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for (int i=16;i<64;i++)
        w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (int i=0;i<64;i++){
        t1=h+SIG1(e)+CH(e,f,g)+K256[i]+w[i];
        t2=SIG0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx_t *c){
    c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f;c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;
    c->bit_count=0;c->buf_len=0;
}

static void sha256_update(sha256_ctx_t *c, const uint8_t *data, size_t len){
    for (size_t i=0;i<len;i++){
        c->buf[c->buf_len++]=data[i];
        if(c->buf_len==64){sha256_transform(c,c->buf);c->buf_len=0;}
    }
    c->bit_count+=(uint64_t)len*8;
}

static void sha256_final(sha256_ctx_t *c, uint8_t digest[32]){
    uint8_t pad[64]={0x80};
    size_t pad_len=(c->buf_len<56)?56-c->buf_len:120-c->buf_len;
    sha256_update(c,pad,pad_len);
    uint8_t bits[8];
    for(int i=7;i>=0;i--){bits[i]=(uint8_t)(c->bit_count&0xff);c->bit_count>>=8;}
    sha256_update(c,bits,8);
    for(int i=0;i<32;i++)
        digest[i]=(uint8_t)(c->state[i>>2]>>(24-8*(i&3)));
    lag_secure_zero(c,sizeof(*c));
}

/* -------------------------------------------------------------------------
 * DB helpers
 * ---------------------------------------------------------------------- */

static sqlite3            *_db  = NULL;
static pthread_mutex_t     _mtx = PTHREAD_MUTEX_INITIALIZER;

static int _db_open(void)
{
    if (_db) return 0;

    if (sqlite3_open_v2(LAG_LOCKOUT_DB,
                        &_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                        SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK)
        return -1;

    sqlite3_exec(_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    sqlite3_exec(_db,
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username   TEXT    NOT NULL,"
        "  token_hash TEXT    NOT NULL,"
        "  expires_at INTEGER NOT NULL"
        ");",
        NULL, NULL, NULL);
    return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int lag_session_create(const char *username, lag_session_t *sess)
{
    if (!username || !sess) return -1;

    /* Generate 256-bit random token */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t raw[LAG_TOKEN_BYTES];
    ssize_t rd = read(fd, raw, sizeof(raw));
    close(fd);
    if (rd != (ssize_t)sizeof(raw)) return -1;

    /* Hex encode */
    for (int i = 0; i < LAG_TOKEN_BYTES; i++)
        snprintf(sess->token_hex + i*2, 3, "%02x", raw[i]);
    sess->token_hex[LAG_TOKEN_HEX_LEN] = '\0';

    lag_strlcpy(sess->username, username, sizeof(sess->username));
    sess->expires_at = (long long)time(NULL) + LAG_SESSION_TTL;

    /* SHA-256 hash for storage */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, raw, sizeof(raw));
    uint8_t digest[32];
    sha256_final(&ctx, digest);

    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i*2, 3, "%02x", digest[i]);
    hash_hex[64] = '\0';

    pthread_mutex_lock(&_mtx);
    if (_db_open() < 0) { pthread_mutex_unlock(&_mtx); return -1; }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO sessions (username, token_hash, expires_at) "
        "VALUES (?, ?, ?)";
    int rc = sqlite3_prepare_v2(_db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, sess->expires_at);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&_mtx);

    lag_secure_zero(raw,      sizeof(raw));
    lag_secure_zero(digest,   sizeof(digest));
    lag_secure_zero(hash_hex, sizeof(hash_hex));

    return (rc == SQLITE_OK) ? 0 : -1;
}

int lag_session_verify(const char *username, const char *token_hex)
{
    if (!username || !token_hex) return -1;
    size_t tlen = strnlen(token_hex, LAG_TOKEN_HEX_LEN + 2);
    if (tlen != LAG_TOKEN_HEX_LEN) return 0;

    /* Decode hex → bytes */
    uint8_t raw[LAG_TOKEN_BYTES];
    for (int i = 0; i < LAG_TOKEN_BYTES; i++) {
        unsigned int b;
        if (sscanf(token_hex + i*2, "%02x", &b) != 1) return 0;
        raw[i] = (uint8_t)b;
    }

    /* SHA-256 */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, raw, sizeof(raw));
    uint8_t digest[32];
    sha256_final(&ctx, digest);

    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i*2, 3, "%02x", digest[i]);
    hash_hex[64] = '\0';

    long long now = (long long)time(NULL);
    int valid = 0;

    pthread_mutex_lock(&_mtx);
    if (_db_open() == 0) {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT COUNT(*) FROM sessions "
            "WHERE username=? AND token_hash=? AND expires_at>?";
        if (sqlite3_prepare_v2(_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username,  -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, hash_hex,  -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, now);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                valid = sqlite3_column_int(stmt, 0) > 0;
            sqlite3_finalize(stmt);
        }
    }
    pthread_mutex_unlock(&_mtx);

    lag_secure_zero(raw,      sizeof(raw));
    lag_secure_zero(digest,   sizeof(digest));
    lag_secure_zero(hash_hex, sizeof(hash_hex));

    return valid;
}

int lag_session_revoke(const char *username)
{
    if (!username) return -1;
    pthread_mutex_lock(&_mtx);
    if (_db_open() < 0) { pthread_mutex_unlock(&_mtx); return -1; }
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(_db,
        "DELETE FROM sessions WHERE username=?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&_mtx);
    return (rc == SQLITE_OK) ? 0 : -1;
}

void lag_session_purge_expired(void)
{
    long long now = (long long)time(NULL);
    pthread_mutex_lock(&_mtx);
    if (_db_open() == 0) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(_db,
            "DELETE FROM sessions WHERE expires_at<=?",
            -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, now);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    pthread_mutex_unlock(&_mtx);
}
