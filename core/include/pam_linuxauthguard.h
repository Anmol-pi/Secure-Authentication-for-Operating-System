#ifndef PAM_LINUXAUTHGUARD_H
#define PAM_LINUXAUTHGUARD_H

/*
 * pam_linuxauthguard.h — PAM module interface for LinuxAuthGuard
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Version */
#define LAG_VERSION_MAJOR 1
#define LAG_VERSION_MINOR 0
#define LAG_VERSION_PATCH 0

/* Paths */
#define LAG_LOCKOUT_DB      "/var/lib/linuxauthguard/lockout.db"
#define LAG_VAULT_DB        "/var/lib/linuxauthguard/vault.db"
#define LAG_AUDIT_LOG       "/var/log/linuxauthguard/auth.log"
#define LAG_CONFIG_FILE     "/etc/linuxauthguard/linuxauthguard.conf"

/* Limits */
#define LAG_MAX_USERNAME    64
#define LAG_MAX_PASSWORD   256
#define LAG_MAX_TOTP_CODE   16
#define LAG_MAX_TTY         64
#define LAG_MAX_IP          46
#define LAG_MAX_LOG_LINE   512

/* Lockout policy */
#define LAG_LOCKOUT_FAILS   5
#define LAG_LOCKOUT_SECS  1800   /* 30 minutes */

/* Auth result codes */
typedef enum {
    LAG_AUTH_OK        =  0,
    LAG_AUTH_FAIL      =  1,
    LAG_AUTH_LOCKED    =  2,
    LAG_AUTH_TOTP_FAIL =  3,
    LAG_AUTH_ERROR     = -1,
} lag_auth_result_t;

/* Module context passed between functions */
typedef struct {
    pam_handle_t *pamh;
    const char   *username;
    char          tty[LAG_MAX_TTY];
    char          rhost[LAG_MAX_IP];
    int           totp_required;
} lag_context_t;

/* Function prototypes */
int lag_context_init(lag_context_t *ctx, pam_handle_t *pamh);
int lag_check_lockout(const char *username);
int lag_increment_fail(const char *username);
int lag_reset_fails(const char *username);
int lag_is_totp_required(const char *username);

#endif /* PAM_LINUXAUTHGUARD_H */
