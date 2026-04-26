#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

/*
 * audit_log.h — Audit logging interface for LinuxAuthGuard
 *
 * Log format:
 *   [ISO8601] [username] [event_type] [tty] [result] [ip_or_dash]
 */

/* Event types */
typedef enum {
    LAG_EVT_AUTH_OK      = 0,
    LAG_EVT_AUTH_FAIL    = 1,
    LAG_EVT_AUTH_LOCKED  = 2,
    LAG_EVT_AUTH_TOTP_OK = 3,
    LAG_EVT_AUTH_TOTP_FAIL = 4,
    LAG_EVT_SESSION_OPEN = 5,
    LAG_EVT_SESSION_CLOSE = 6,
    LAG_EVT_LOCKOUT_RESET = 7,
} lag_event_type_t;

/**
 * lag_audit_log() — Write one event to the audit log.
 *
 * @param username   Account name (may be NULL → "unknown").
 * @param event      Event type.
 * @param tty        Terminal identifier (may be NULL → "-").
 * @param result     Short result string, e.g. "SUCCESS" or "FAILURE".
 * @param ip         Remote IP for SSH sessions (may be NULL → "-").
 *
 * Returns 0 on success, -1 on error.
 */
int lag_audit_log(const char *username,
                  lag_event_type_t event,
                  const char *tty,
                  const char *result,
                  const char *ip);

/**
 * lag_audit_open() — Open (or create) the audit log file. Called once at
 * module load. Returns 0 on success.
 */
int lag_audit_open(void);

/**
 * lag_audit_close() — Flush and close the audit log file descriptor.
 */
void lag_audit_close(void);

#endif /* AUDIT_LOG_H */
