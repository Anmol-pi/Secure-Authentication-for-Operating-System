#ifndef TOTP_H
#define TOTP_H

/*
 * totp.h — RFC 6238 TOTP interface for LinuxAuthGuard
 */

#include <stdint.h>
#include <stddef.h>

/* TOTP parameters */
#define TOTP_STEP_SECONDS   30
#define TOTP_DIGITS          6
#define TOTP_WINDOW          1   /* ±1 step tolerance */
#define TOTP_SECRET_MAX    128   /* Base32 secret max length */

/**
 * totp_verify() — Verify a TOTP code against a Base32-encoded secret.
 *
 * @param secret    Base32-encoded TOTP secret (NUL-terminated).
 * @param code      6-digit code string from user (NUL-terminated).
 * @param ts        Unix timestamp to verify against (0 = use current time).
 *
 * Returns 1 if valid, 0 if invalid, -1 on error.
 */
int totp_verify(const char *secret, const char *code, uint64_t ts);

/**
 * totp_generate() — Generate a TOTP code for testing/enrollment.
 *
 * @param secret    Base32-encoded TOTP secret.
 * @param ts        Unix timestamp (0 = use current time).
 * @param out       Buffer to receive NUL-terminated digit string.
 * @param out_len   Size of output buffer (must be >= TOTP_DIGITS+1).
 *
 * Returns 0 on success, -1 on error.
 */
int totp_generate(const char *secret, uint64_t ts,
                  char *out, size_t out_len);

/**
 * base32_decode() — Decode a Base32 string into raw bytes.
 *
 * Returns number of bytes written, or -1 on error.
 */
int base32_decode(const char *in, uint8_t *out, size_t out_max);

#endif /* TOTP_H */
