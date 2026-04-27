#ifndef SESSION_H
#define SESSION_H

/*
 * session.h — Secure session token management for LinuxAuthGuard
 *
 * Tokens are 256-bit random values from /dev/urandom, stored SHA-256 hashed
 * in SQLite.  They are returned to the caller as 64-character hex strings.
 */

#include <stddef.h>

#define LAG_TOKEN_BYTES    32   /* 256 bits */
#define LAG_TOKEN_HEX_LEN  64  /* hex representation */
#define LAG_SESSION_TTL  3600  /* default session lifetime in seconds */

typedef struct {
    char token_hex[LAG_TOKEN_HEX_LEN + 1]; /* NUL-terminated hex token   */
    long long expires_at;                   /* Unix timestamp of expiry   */
    char username[64];
} lag_session_t;

/**
 * lag_session_create() — Generate a new session token for username.
 *
 * Writes the token into *sess and stores a hashed copy in SQLite.
 * Returns 0 on success, -1 on error.
 */
int lag_session_create(const char *username, lag_session_t *sess);

/**
 * lag_session_verify() — Verify that token_hex belongs to an active session
 * for username.
 *
 * Returns 1 if valid, 0 if invalid/expired, -1 on error.
 */
int lag_session_verify(const char *username, const char *token_hex);

/**
 * lag_session_revoke() — Revoke all active sessions for username.
 * Returns 0 on success.
 */
int lag_session_revoke(const char *username);

/**
 * lag_session_purge_expired() — Remove expired session rows from the DB.
 */
void lag_session_purge_expired(void);

#endif /* SESSION_H */
