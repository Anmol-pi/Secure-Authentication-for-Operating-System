/*
 * audit_log.c — Audit logging for LinuxAuthGuard
 *
 * Writes ISO-8601 timestamped log lines to /var/log/linuxauthguard/auth.log.
 * Thread-safe via pthread_mutex.
 *
 * Format:
 *   [2025-01-15T14:22:01Z] [alice] [AUTH_FAIL] [tty1] [FAILURE] [-]
 *
 * Compile flags: -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
 */

#include "include/audit_log.h"
#include "include/pam_linuxauthguard.h"
#include "include/buffer_safe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Internal state
 * ---------------------------------------------------------------------- */

static int            _log_fd  = -1;
static pthread_mutex_t _log_mtx = PTHREAD_MUTEX_INITIALIZER;

static const char * const _event_names[] = {
    [LAG_EVT_AUTH_OK]        = "AUTH_OK",
    [LAG_EVT_AUTH_FAIL]      = "AUTH_FAIL",
    [LAG_EVT_AUTH_LOCKED]    = "AUTH_LOCKED",
    [LAG_EVT_AUTH_TOTP_OK]   = "TOTP_OK",
    [LAG_EVT_AUTH_TOTP_FAIL] = "TOTP_FAIL",
    [LAG_EVT_SESSION_OPEN]   = "SESSION_OPEN",
    [LAG_EVT_SESSION_CLOSE]  = "SESSION_CLOSE",
    [LAG_EVT_LOCKOUT_RESET]  = "LOCKOUT_RESET",
};

/* -------------------------------------------------------------------------
 * lag_audit_open
 * ---------------------------------------------------------------------- */

int lag_audit_open(void)
{
    pthread_mutex_lock(&_log_mtx);

    if (_log_fd >= 0) {
        pthread_mutex_unlock(&_log_mtx);
        return 0;
    }

    /* Ensure log directory exists */
    if (mkdir("/var/log/linuxauthguard", 0750) < 0 && errno != EEXIST) {
        pthread_mutex_unlock(&_log_mtx);
        return -1;
    }

    _log_fd = open(LAG_AUDIT_LOG,
                   O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                   0640);
    pthread_mutex_unlock(&_log_mtx);
    return (_log_fd >= 0) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * lag_audit_close
 * ---------------------------------------------------------------------- */

void lag_audit_close(void)
{
    pthread_mutex_lock(&_log_mtx);
    if (_log_fd >= 0) {
        close(_log_fd);
        _log_fd = -1;
    }
    pthread_mutex_unlock(&_log_mtx);
}

/* -------------------------------------------------------------------------
 * lag_audit_log
 * ---------------------------------------------------------------------- */

int lag_audit_log(const char *username,
                  lag_event_type_t event,
                  const char *tty,
                  const char *result,
                  const char *ip)
{
    if (lag_audit_open() < 0) return -1;

    /* ISO 8601 timestamp */
    char ts[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    /* Sanitise fields */
    char user_s[LAG_MAX_USERNAME + 1];
    char tty_s[LAG_MAX_TTY + 1];
    char ip_s[LAG_MAX_IP + 1];
    char result_s[64];

    lag_strlcpy(user_s,   username ? username : "unknown",    sizeof(user_s));
    lag_strlcpy(tty_s,    tty      ? tty      : "-",          sizeof(tty_s));
    lag_strlcpy(ip_s,     ip       ? ip       : "-",          sizeof(ip_s));
    lag_strlcpy(result_s, result   ? result   : "-",          sizeof(result_s));

    /* Validate event range */
    int max_evt = (int)(sizeof(_event_names) / sizeof(_event_names[0]));
    const char *evt_name = ((int)event >= 0 && (int)event < max_evt
                            && _event_names[(int)event])
                           ? _event_names[(int)event]
                           : "UNKNOWN";

    /* Build log line */
    char line[LAG_MAX_LOG_LINE];
    int  n = snprintf(line, sizeof(line),
                      "[%s] [%s] [%s] [%s] [%s] [%s]\n",
                      ts, user_s, evt_name, tty_s, result_s, ip_s);

    if (n <= 0 || (size_t)n >= sizeof(line)) {
        /* Truncated — still write what we have, but cap it */
        n = (int)sizeof(line) - 1;
        line[n - 1] = '\n';
        line[n]     = '\0';
    }

    pthread_mutex_lock(&_log_mtx);
    ssize_t written = write(_log_fd, line, (size_t)n);
    pthread_mutex_unlock(&_log_mtx);

    return (written == n) ? 0 : -1;
}
