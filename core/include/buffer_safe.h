#ifndef BUFFER_SAFE_H
#define BUFFER_SAFE_H

/*
 * buffer_safe.h — Safe string/buffer utilities for LinuxAuthGuard
 */

#include <stddef.h>

/**
 * lag_strlcpy() — Safe strcpy: always NUL-terminates, returns bytes written.
 * Returns 0 on NULL inputs.
 */
size_t lag_strlcpy(char *dst, const char *src, size_t dst_size);

/**
 * lag_strlcat() — Safe strcat: always NUL-terminates, returns total length.
 */
size_t lag_strlcat(char *dst, const char *src, size_t dst_size);

/**
 * lag_secure_zero() — Zero memory in a way the compiler cannot optimise away.
 */
void lag_secure_zero(void *buf, size_t len);

/**
 * lag_validate_username() — Returns 1 if username contains only [a-z0-9_.-]
 * and is within LAG_MAX_USERNAME length. Returns 0 otherwise.
 */
int lag_validate_username(const char *username);

/**
 * lag_sanitize_path() — Copies path to dst, stripping NUL bytes and
 * ensuring the result is within dst_size. Returns 0 on success, -1 on error.
 */
int lag_sanitize_path(char *dst, const char *src, size_t dst_size);

#endif /* BUFFER_SAFE_H */
