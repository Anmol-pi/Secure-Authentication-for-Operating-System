/*
 * buffer_safe.c — Safe string/buffer utilities for LinuxAuthGuard
 *
 * Compile flags: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
 */

#include "include/buffer_safe.h"
#include "include/pam_linuxauthguard.h"  /* for LAG_MAX_USERNAME */

#include <stddef.h>
#include <string.h>
#include <ctype.h>

/* -------------------------------------------------------------------------
 * lag_strlcpy — NUL-safe strcpy; always terminates dst.
 * Returns number of bytes written (excluding NUL), 0 on error.
 * ---------------------------------------------------------------------- */

size_t lag_strlcpy(char *dst, const char *src, size_t dst_size)
{
    if (!dst || !src || dst_size == 0) return 0;

    size_t i;
    for (i = 0; i < dst_size - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
    return i;
}

/* -------------------------------------------------------------------------
 * lag_strlcat — NUL-safe strcat; always terminates dst.
 * Returns total length that would have been written (for truncation check).
 * ---------------------------------------------------------------------- */

size_t lag_strlcat(char *dst, const char *src, size_t dst_size)
{
    if (!dst || !src || dst_size == 0) return 0;

    size_t dst_len = strnlen(dst, dst_size);
    if (dst_len >= dst_size - 1)
        return dst_size; /* already full */

    size_t i;
    for (i = 0; (dst_len + i) < dst_size - 1 && src[i] != '\0'; i++)
        dst[dst_len + i] = src[i];
    dst[dst_len + i] = '\0';

    return dst_len + i;
}

/* -------------------------------------------------------------------------
 * lag_secure_zero — Wipe memory that the optimiser cannot elide.
 * ---------------------------------------------------------------------- */

void lag_secure_zero(void *buf, size_t len)
{
    if (!buf || len == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
}

/* -------------------------------------------------------------------------
 * lag_validate_username — Accepts [a-z A-Z 0-9 _ . -] within length limit.
 * Returns 1 if valid, 0 otherwise.
 * ---------------------------------------------------------------------- */

int lag_validate_username(const char *username)
{
    if (!username) return 0;

    size_t len = strnlen(username, LAG_MAX_USERNAME + 1);
    if (len == 0 || len > LAG_MAX_USERNAME) return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!isalnum(c) && c != '_' && c != '.' && c != '-')
            return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * lag_sanitize_path — Copy path, strip embedded NULs, ensure termination.
 * Returns 0 on success, -1 if src is NULL or dst_size is 0.
 * ---------------------------------------------------------------------- */

int lag_sanitize_path(char *dst, const char *src, size_t dst_size)
{
    if (!dst || !src || dst_size == 0) return -1;

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dst_size - 1; i++) {
        /* Skip embedded NUL bytes and non-printable control chars */
        unsigned char c = (unsigned char)src[i];
        if (c < 0x20 && c != '\t') continue; /* strip control chars */
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return 0;
}
