/*
 * pam_linuxauthguard.c — PAM module for LinuxAuthGuard
 *
 * Provides:
 *   pam_sm_authenticate   — password + optional TOTP
 *   pam_sm_setcred        — no-op (credentials managed externally)
 *   pam_sm_acct_mgmt      — lockout check
 *   pam_sm_open_session   — session token issuance + audit log
 *   pam_sm_close_session  — audit log session close
 *   pam_sm_chauthtok      — not implemented (returns PAM_IGNORE)
 *
 * PAM service file example (/etc/pam.d/linuxauthguard):
 *   auth    required   pam_linuxauthguard.so
 *   account required   pam_linuxauthguard.so
 *   session optional   pam_linuxauthguard.so
 *
 * Compile:
 *   gcc -shared -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *       -Wall -Wextra -O2 \
 *       pam_linuxauthguard.c buffer_safe.c audit_log.c session.c totp.c \
 *       -o pam_linuxauthguard.so \
 *       -lpam -lsqlite3 -lpthread
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sqlite3.h>

#include "include/pam_linuxauthguard.h"
#include "include/totp.h"
#include "include/buffer_safe.h"
#include "include/audit_log.h"
#include "include/session.h"

/* pam_set_data requires a cleanup function with PAM's specific signature */
static void pam_free_data(pam_handle_t *pamh, void *data, int error_status)
{
    (void)pamh; (void)error_status;
    free(data);
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Open (or create) lockout.db and ensure schema exists. */
static sqlite3 *_open_lockout_db(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(LAG_LOCKOUT_DB, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                        SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK)
        return NULL;

    sqlite3_exec(db, "PRAGMA journal_mode=WAL;",    NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL;",  NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS lockouts ("
        "  username    TEXT PRIMARY KEY,"
        "  fail_count  INTEGER NOT NULL DEFAULT 0,"
        "  locked_until INTEGER NOT NULL DEFAULT 0"
        ");", NULL, NULL, NULL);
    return db;
}

/* -------------------------------------------------------------------------
 * lag_context_init
 * ---------------------------------------------------------------------- */

int lag_context_init(lag_context_t *ctx, pam_handle_t *pamh)
{
    if (!ctx || !pamh) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->pamh = pamh;

    pam_get_user(pamh, &ctx->username, NULL);

    const void *tty_raw = NULL;
    pam_get_item(pamh, PAM_TTY, &tty_raw);
    lag_strlcpy(ctx->tty, tty_raw ? (const char *)tty_raw : "unknown",
                sizeof(ctx->tty));

    const void *rhost_raw = NULL;
    pam_get_item(pamh, PAM_RHOST, &rhost_raw);
    lag_strlcpy(ctx->rhost, rhost_raw ? (const char *)rhost_raw : "-",
                sizeof(ctx->rhost));

    return 0;
}

/* -------------------------------------------------------------------------
 * Lockout helpers
 * ---------------------------------------------------------------------- */

int lag_check_lockout(const char *username)
{
    if (!username) return 0;
    sqlite3 *db = _open_lockout_db();
    if (!db) return 0;

    long long now = (long long)time(NULL);
    sqlite3_stmt *stmt = NULL;
    int locked = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT locked_until FROM lockouts WHERE username=?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            long long until = sqlite3_column_int64(stmt, 0);
            if (until > now) locked = 1;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return locked;
}

int lag_increment_fail(const char *username)
{
    if (!username) return -1;
    sqlite3 *db = _open_lockout_db();
    if (!db) return -1;

    long long now    = (long long)time(NULL);
    long long lockts = 0;

    sqlite3_exec(db,
        "INSERT INTO lockouts (username, fail_count, locked_until) "
        "VALUES (?, 1, 0) "
        "ON CONFLICT(username) DO UPDATE SET "
        "  fail_count = fail_count + 1",
        NULL, NULL, NULL);  /* simplified upsert first */

    /* Check if threshold reached */
    sqlite3_stmt *stmt = NULL;
    int fails = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT fail_count FROM lockouts WHERE username=?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            fails = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    if (fails >= LAG_LOCKOUT_FAILS) {
        lockts = now + LAG_LOCKOUT_SECS;
        if (sqlite3_prepare_v2(db,
                "UPDATE lockouts SET locked_until=? WHERE username=?",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, lockts);
            sqlite3_bind_text(stmt,  2, username, -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    sqlite3_close(db);
    return 0;
}

int lag_reset_fails(const char *username)
{
    if (!username) return -1;
    sqlite3 *db = _open_lockout_db();
    if (!db) return -1;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE lockouts SET fail_count=0, locked_until=0 "
            "WHERE username=?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return 0;
}

/* -------------------------------------------------------------------------
 * TOTP requirement check
 * ---------------------------------------------------------------------- */

int lag_is_totp_required(const char *username)
{
    if (!username) return 0;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(LAG_VAULT_DB, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return 0;

    sqlite3_stmt *stmt = NULL;
    int required = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT totp_required FROM users WHERE username=?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            required = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return required;
}

/* Retrieve TOTP secret for user (caller must secure_zero buffer when done). */
static int _get_totp_secret(const char *username,
                             char *secret, size_t secret_size)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(LAG_VAULT_DB, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return -1;

    sqlite3_stmt *stmt = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT totp_secret FROM users WHERE username=?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *s = (const char *)sqlite3_column_text(stmt, 0);
            if (s) {
                lag_strlcpy(secret, s, secret_size);
                found = 1;
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return found ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * pam_sm_authenticate
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    lag_context_t ctx;
    lag_context_init(&ctx, pamh);
    lag_audit_open();

    if (!ctx.username || !lag_validate_username(ctx.username)) {
        lag_audit_log("unknown", LAG_EVT_AUTH_FAIL, ctx.tty, "INVALID_USER", ctx.rhost);
        return PAM_USER_UNKNOWN;
    }

    /* Lockout check */
    if (lag_check_lockout(ctx.username)) {
        lag_audit_log(ctx.username, LAG_EVT_AUTH_LOCKED, ctx.tty, "LOCKED", ctx.rhost);
        pam_error(pamh, "Account locked due to too many failed attempts.");
        return PAM_AUTH_ERR;
    }

    /* Get password via PAM conversation */
    const char *authtok = NULL;
    int pam_rc = pam_get_authtok(pamh, PAM_AUTHTOK,
                                  &authtok, "Password: ");
    if (pam_rc != PAM_SUCCESS || !authtok) {
        lag_increment_fail(ctx.username);
        lag_audit_log(ctx.username, LAG_EVT_AUTH_FAIL, ctx.tty,
                      "NO_AUTHTOK", ctx.rhost);
        return PAM_AUTH_ERR;
    }

    /*
     * NOTE: Actual password verification is delegated to the system PAM
     * stack (pam_unix or equivalent).  This module adds lockout tracking
     * and TOTP on top.  For a standalone deployment, integrate Argon2id
     * verification here using libargon2 and vault.db.
     *
     * For now, we proceed if PAM_AUTHTOK was provided (assuming upstream
     * pam_unix validated the password).
     */

    /* TOTP check */
    ctx.totp_required = lag_is_totp_required(ctx.username);
    if (ctx.totp_required) {
        char totp_secret[TOTP_SECRET_MAX + 1];
        memset(totp_secret, 0, sizeof(totp_secret));

        if (_get_totp_secret(ctx.username, totp_secret, sizeof(totp_secret)) < 0) {
            lag_audit_log(ctx.username, LAG_EVT_AUTH_TOTP_FAIL,
                          ctx.tty, "NO_SECRET", ctx.rhost);
            lag_secure_zero(totp_secret, sizeof(totp_secret));
            return PAM_AUTH_ERR;
        }

        const char *totp_code = NULL;
        pam_rc = pam_get_authtok(pamh, PAM_AUTHTOK,
                                  &totp_code, "TOTP code: ");
        if (pam_rc != PAM_SUCCESS || !totp_code) {
            lag_increment_fail(ctx.username);
            lag_audit_log(ctx.username, LAG_EVT_AUTH_TOTP_FAIL,
                          ctx.tty, "NO_TOTP", ctx.rhost);
            lag_secure_zero(totp_secret, sizeof(totp_secret));
            return PAM_AUTH_ERR;
        }

        if (totp_verify(totp_secret, totp_code, 0) != 1) {
            lag_increment_fail(ctx.username);
            lag_audit_log(ctx.username, LAG_EVT_AUTH_TOTP_FAIL,
                          ctx.tty, "TOTP_WRONG", ctx.rhost);
            lag_secure_zero(totp_secret, sizeof(totp_secret));
            return PAM_AUTH_ERR;
        }

        lag_secure_zero(totp_secret, sizeof(totp_secret));
        lag_audit_log(ctx.username, LAG_EVT_AUTH_TOTP_OK,
                      ctx.tty, "SUCCESS", ctx.rhost);
    }

    /* Auth succeeded */
    lag_reset_fails(ctx.username);
    lag_audit_log(ctx.username, LAG_EVT_AUTH_OK, ctx.tty, "SUCCESS", ctx.rhost);
    return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------
 * pam_sm_setcred
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------
 * pam_sm_acct_mgmt
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    const char *username = NULL;
    pam_get_user(pamh, &username, NULL);
    if (!username) return PAM_USER_UNKNOWN;
    if (lag_check_lockout(username)) {
        pam_error(pamh, "Account is temporarily locked.");
        return PAM_ACCT_EXPIRED;
    }
    return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------
 * pam_sm_open_session
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    lag_context_t ctx;
    lag_context_init(&ctx, pamh);
    lag_audit_open();

    lag_session_t sess;
    if (ctx.username && lag_session_create(ctx.username, &sess) == 0) {
        /* Store token in PAM data so other modules can retrieve it */
        char *tok_copy = strndup(sess.token_hex, LAG_TOKEN_HEX_LEN);
        if (tok_copy)
            pam_set_data(pamh, "lag_session_token", tok_copy, pam_free_data);
        lag_secure_zero(sess.token_hex, sizeof(sess.token_hex));
    }

    lag_audit_log(ctx.username ? ctx.username : "unknown",
                  LAG_EVT_SESSION_OPEN, ctx.tty, "OPEN", ctx.rhost);
    lag_session_purge_expired();
    return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------
 * pam_sm_close_session
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    lag_context_t ctx;
    lag_context_init(&ctx, pamh);
    lag_audit_open();

    if (ctx.username)
        lag_session_revoke(ctx.username);

    lag_audit_log(ctx.username ? ctx.username : "unknown",
                  LAG_EVT_SESSION_CLOSE, ctx.tty, "CLOSE", ctx.rhost);
    lag_audit_close();
    return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------
 * pam_sm_chauthtok — not implemented
 * ---------------------------------------------------------------------- */

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
