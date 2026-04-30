/*
 * LinuxAuthGuard - FUSE Vault Daemon (fuse_vault.c)
 *
 * A FUSE filesystem overlay that intercepts file/directory access on
 * protected paths and requires per-item authentication before allowing
 * reads or writes. Uses inotify for access detection and Argon2 for
 * password hashing.
 *
 * Compile:
 *   gcc -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *       -o fuse_vault fuse_vault.c \
 *       $(pkg-config --cflags --libs fuse3) \
 *       -lsqlite3 -largon2 -lpthread
 */

#define FUSE_USE_VERSION 35
#define _GNU_SOURCE

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/inotify.h>
#include <sys/xattr.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <sqlite3.h>
#include <argon2.h>
#include <syslog.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define LAG_VAULT_DB     "/var/lib/linuxauthguard/vault.db"
#define LAG_AUTH_SOCKET  "/run/linuxauthguard/vault_auth.sock"
#define LAG_LOG_FILE     "/var/log/linuxauthguard/file_auth.log"
#define INOTIFY_BUF_LEN  (32 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define MAX_PATH_LEN     4096
#define ARGON2_TIMECOST  3
#define ARGON2_MEMORYCOST (65536)  /* 64 MiB */
#define ARGON2_PARALLELISM 2
#define ARGON2_HASHLEN   32
#define ARGON2_SALTLEN   16
#define MAX_PASSWORD_LEN 512
#define SESSION_TIMEOUT_SEC 300   /* 5 minutes per-file session */

/* ── Data structures ────────────────────────────────────────────────────── */

typedef struct {
    char path[MAX_PATH_LEN];
    time_t unlocked_at;
    uid_t  unlocked_by;
} session_entry_t;

typedef struct {
    session_entry_t *entries;
    size_t           count;
    size_t           capacity;
    pthread_mutex_t  lock;
} session_table_t;

typedef struct {
    char  source_path[MAX_PATH_LEN];  /* Real filesystem path being overlaid */
    char  mount_path[MAX_PATH_LEN];   /* FUSE mount point */
    int   inotify_fd;
    pthread_t inotify_thread;
    sqlite3 *db;
    session_table_t sessions;
} vault_ctx_t;

/* ── Globals ────────────────────────────────────────────────────────────── */

static vault_ctx_t g_vault;
static volatile sig_atomic_t g_running = 1;

/* ── Logging ────────────────────────────────────────────────────────────── */

static void lag_log(int priority, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    time_t now = time(NULL);
    char ts[32];
    struct tm *tm_info = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    FILE *f = fopen(LAG_LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] ", ts);
        vfprintf(f, fmt, ap);
        fprintf(f, "\n");
        fclose(f);
    }

    vsyslog(priority, fmt, ap);
    va_end(ap);
}

/* ── Database helpers ───────────────────────────────────────────────────── */

static int db_open(sqlite3 **db) {
    int rc = sqlite3_open(LAG_VAULT_DB, db);
    if (rc != SQLITE_OK) {
        lag_log(LOG_ERR, "Cannot open vault DB: %s", sqlite3_errmsg(*db));
        return -1;
    }
    /* Enable WAL mode for concurrent reads */
    sqlite3_exec(*db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(*db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    return 0;
}

static int db_init_schema(sqlite3 *db) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS protected_items ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  path        TEXT NOT NULL UNIQUE,"
        "  password_hash TEXT NOT NULL,"
        "  salt        TEXT NOT NULL,"
        "  totp_required INTEGER NOT NULL DEFAULT 0,"
        "  owner_uid   INTEGER NOT NULL,"
        "  recursive   INTEGER NOT NULL DEFAULT 1,"
        "  created_at  INTEGER NOT NULL,"
        "  updated_at  INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS access_log ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  item_path   TEXT NOT NULL,"
        "  accessed_by INTEGER NOT NULL,"
        "  access_type TEXT NOT NULL,"
        "  granted     INTEGER NOT NULL,"
        "  timestamp   INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_items_path ON protected_items(path);"
        "CREATE INDEX IF NOT EXISTS idx_log_path   ON access_log(item_path);";

    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        lag_log(LOG_ERR, "Schema init failed: %s", errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

/* ── Session management ─────────────────────────────────────────────────── */

static void session_init(session_table_t *st) {
    st->entries  = NULL;
    st->count    = 0;
    st->capacity = 0;
    pthread_mutex_init(&st->lock, NULL);
}

static int session_is_valid(session_table_t *st, const char *path, uid_t uid) {
    pthread_mutex_lock(&st->lock);
    time_t now = time(NULL);
    int found = 0;
    for (size_t i = 0; i < st->count; i++) {
        if (strncmp(st->entries[i].path, path, MAX_PATH_LEN) == 0 &&
            st->entries[i].unlocked_by == uid &&
            (now - st->entries[i].unlocked_at) < SESSION_TIMEOUT_SEC) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&st->lock);
    return found;
}

static void session_grant(session_table_t *st, const char *path, uid_t uid) {
    pthread_mutex_lock(&st->lock);
    /* Overwrite existing entry for same path+uid */
    for (size_t i = 0; i < st->count; i++) {
        if (strncmp(st->entries[i].path, path, MAX_PATH_LEN) == 0 &&
            st->entries[i].unlocked_by == uid) {
            st->entries[i].unlocked_at = time(NULL);
            pthread_mutex_unlock(&st->lock);
            return;
        }
    }
    /* Add new entry */
    if (st->count >= st->capacity) {
        size_t new_cap = st->capacity == 0 ? 16 : st->capacity * 2;
        session_entry_t *tmp = realloc(st->entries,
                                       new_cap * sizeof(session_entry_t));
        if (!tmp) {
            pthread_mutex_unlock(&st->lock);
            return;
        }
        st->entries  = tmp;
        st->capacity = new_cap;
    }
    snprintf(st->entries[st->count].path, MAX_PATH_LEN, "%s", path);
    st->entries[st->count].unlocked_at = time(NULL);
    st->entries[st->count].unlocked_by = uid;
    st->count++;
    pthread_mutex_unlock(&st->lock);
}

/* ── Argon2 helpers ─────────────────────────────────────────────────────── */

static int argon2_hash_password(
    const char *password,
    uint8_t    *salt,
    size_t      salt_len,
    uint8_t    *hash_out,
    size_t      hash_len)
{
    size_t pwd_len = strnlen(password, MAX_PASSWORD_LEN);
    int rc = argon2id_hash_raw(
        ARGON2_TIMECOST,
        ARGON2_MEMORYCOST,
        ARGON2_PARALLELISM,
        password, pwd_len,
        salt, salt_len,
        hash_out, hash_len
    );
    return (rc == ARGON2_OK) ? 0 : -1;
}

static int argon2_verify_password(
    const char *password,
    const char *hash_b64,
    const char *salt_b64)
{
    /* Decode base64 salt and hash from DB storage */
    uint8_t salt[ARGON2_SALTLEN];
    uint8_t expected_hash[ARGON2_HASHLEN];
    uint8_t actual_hash[ARGON2_HASHLEN];

    /* Simple hex decode (DB stores hex-encoded values) */
    for (int i = 0; i < ARGON2_SALTLEN; i++) {
        unsigned int byte;
        if (sscanf(salt_b64 + 2 * i, "%02x", &byte) != 1) return -1;
        salt[i] = (uint8_t)byte;
    }
    for (int i = 0; i < ARGON2_HASHLEN; i++) {
        unsigned int byte;
        if (sscanf(hash_b64 + 2 * i, "%02x", &byte) != 1) return -1;
        expected_hash[i] = (uint8_t)byte;
    }

    if (argon2_hash_password(password, salt, ARGON2_SALTLEN,
                             actual_hash, ARGON2_HASHLEN) != 0) {
        return -1;
    }

    /* Constant-time compare */
    int diff = 0;
    for (int i = 0; i < ARGON2_HASHLEN; i++) {
        diff |= (actual_hash[i] ^ expected_hash[i]);
    }
    return diff == 0 ? 0 : -1;
}

/* ── Protected path lookup ──────────────────────────────────────────────── */

typedef struct {
    char password_hash[128];
    char salt[64];
    int  totp_required;
    int  owner_uid;
    int  recursive;
} item_info_t;

static int db_lookup_path(sqlite3 *db, const char *path, item_info_t *info) {
    /* Try exact match first */
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT password_hash, salt, totp_required, owner_uid, recursive "
        "FROM protected_items WHERE path = ? LIMIT 1";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *h = (const char *)sqlite3_column_text(stmt, 0);
        const char *s = (const char *)sqlite3_column_text(stmt, 1);
        if (h) snprintf(info->password_hash, sizeof(info->password_hash), "%s", h);
        if (s) snprintf(info->salt,          sizeof(info->salt),          "%s", s);
        info->totp_required = sqlite3_column_int(stmt, 2);
        info->owner_uid     = sqlite3_column_int(stmt, 3);
        info->recursive     = sqlite3_column_int(stmt, 4);
        found = 1;
    }
    sqlite3_finalize(stmt);
    if (found) return 0;

    /* Try recursive parent match */
    char parent[MAX_PATH_LEN];
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    while (slash && slash != parent) {
        *slash = '\0';
        const char *sql2 =
            "SELECT password_hash, salt, totp_required, owner_uid, recursive "
            "FROM protected_items WHERE path = ? AND recursive = 1 LIMIT 1";

        sqlite3_stmt *stmt2 = NULL;
        if (sqlite3_prepare_v2(db, sql2, -1, &stmt2, NULL) != SQLITE_OK) break;
        sqlite3_bind_text(stmt2, 1, parent, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt2) == SQLITE_ROW) {
            const char *h = (const char *)sqlite3_column_text(stmt2, 0);
            const char *s = (const char *)sqlite3_column_text(stmt2, 1);
            if (h) snprintf(info->password_hash, sizeof(info->password_hash), "%s", h);
            if (s) snprintf(info->salt,          sizeof(info->salt),          "%s", s);
            info->totp_required = sqlite3_column_int(stmt2, 2);
            info->owner_uid     = sqlite3_column_int(stmt2, 3);
            info->recursive     = sqlite3_column_int(stmt2, 4);
            found = 1;
        }
        sqlite3_finalize(stmt2);
        if (found) return 0;

        slash = strrchr(parent, '/');
    }
    return -1;
}

/* ── Access log ─────────────────────────────────────────────────────────── */

static void db_log_access(
    sqlite3    *db,
    const char *path,
    uid_t       uid,
    const char *access_type,
    int         granted)
{
    const char *sql =
        "INSERT INTO access_log(item_path, accessed_by, access_type, granted, timestamp)"
        " VALUES(?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
    sqlite3_bind_text(stmt, 1, path,        -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 2, (int)uid);
    sqlite3_bind_text(stmt, 3, access_type, -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 4, granted);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)time(NULL));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* ── IPC: request password from GUI ────────────────────────────────────── */

static int request_password_via_socket(
    const char *path,
    char       *password_out,
    size_t      password_max)
{
    /*
     * Connects to the UNIX socket served by vault_gui.py / prompt_dialog.py.
     * Sends: "AUTH_REQUEST:<path>\n"
     * Receives: "PASSWORD:<secret>\n"  or  "DENIED\n"
     */
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", LAG_AUTH_SOCKET);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Send request */
    char req[MAX_PATH_LEN + 32];
    int req_len = snprintf(req, sizeof(req), "AUTH_REQUEST:%s\n", path);
    if (write(fd, req, (size_t)req_len) != req_len) {
        close(fd);
        return -1;
    }

    /* Read response */
    char resp[MAX_PASSWORD_LEN + 16];
    memset(resp, 0, sizeof(resp));
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);

    if (n <= 0) return -1;
    resp[n] = '\0';

    if (strncmp(resp, "PASSWORD:", 9) == 0) {
        /* Strip trailing newline */
        size_t plen = strnlen(resp + 9, MAX_PASSWORD_LEN);
        if (plen > 0 && resp[9 + plen - 1] == '\n') {
            resp[9 + plen - 1] = '\0';
            plen--;
        }
        snprintf(password_out, password_max, "%s", resp + 9);
        /* Zero the response buffer */
        explicit_bzero(resp, sizeof(resp));
        return 0;
    }

    explicit_bzero(resp, sizeof(resp));
    return -1;  /* DENIED or unknown */
}

/* ── Auth check (the core gate) ─────────────────────────────────────────── */

static int check_access(const char *real_path) {
    struct fuse_context *ctx = fuse_get_context();
    uid_t  caller_uid = ctx ? ctx->uid : getuid();

    /* Already have a valid session? Log the access and allow. */
    if (session_is_valid(&g_vault.sessions, real_path, caller_uid)) {
        db_log_access(g_vault.db, real_path, caller_uid, "session", 1);
        return 0;
    }

    item_info_t info;
    memset(&info, 0, sizeof(info));
    if (db_lookup_path(g_vault.db, real_path, &info) != 0) {
        return 0;  /* Not protected */
    }

    lag_log(LOG_INFO, "Protected path accessed: %s by uid=%d", real_path, caller_uid);

    /* Request password via IPC to GUI */
    char password[MAX_PASSWORD_LEN];
    memset(password, 0, sizeof(password));

    if (request_password_via_socket(real_path, password, sizeof(password)) != 0) {
        lag_log(LOG_WARNING, "Password request denied/failed for: %s", real_path);
        db_log_access(g_vault.db, real_path, caller_uid, "open", 0);
        explicit_bzero(password, sizeof(password));
        return -EACCES;
    }

    int verified = argon2_verify_password(password, info.password_hash, info.salt);
    explicit_bzero(password, sizeof(password));

    if (verified != 0) {
        lag_log(LOG_WARNING, "Wrong password for protected path: %s", real_path);
        db_log_access(g_vault.db, real_path, caller_uid, "open", 0);
        return -EACCES;
    }

    lag_log(LOG_INFO, "Access granted to: %s for uid=%d", real_path, caller_uid);
    db_log_access(g_vault.db, real_path, caller_uid, "open", 1);
    session_grant(&g_vault.sessions, real_path, caller_uid);
    return 0;
}

/* ── FUSE operations ────────────────────────────────────────────────────── */

static char *get_real_path(const char *path) {
    static __thread char buf[MAX_PATH_LEN];
    snprintf(buf, sizeof(buf), "%s%s", g_vault.source_path, path);
    return buf;
}

static int vault_getattr(const char *path, struct stat *st,
                         struct fuse_file_info *fi) {
    (void)fi;
    int res = lstat(get_real_path(path), st);
    return res == -1 ? -errno : 0;
}

static int vault_readdir(const char *path, void *buf,
                         fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;

    const char *rpath = get_real_path(path);
    int rc = check_access(rpath);
    if (rc != 0) return rc;

    DIR *dp = opendir(rpath);
    if (!dp) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino  = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}

static int vault_open(const char *path, struct fuse_file_info *fi) {
    const char *rpath = get_real_path(path);
    int rc = check_access(rpath);
    if (rc != 0) return rc;

    int fd = open(rpath, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = (uint64_t)fd;
    return 0;
}

static int vault_read(const char *path, char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
    (void)path;
    ssize_t res = pread((int)fi->fh, buf, size, offset);
    return res == -1 ? -errno : (int)res;
}

static int vault_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    (void)path;
    ssize_t res = pwrite((int)fi->fh, buf, size, offset);
    return res == -1 ? -errno : (int)res;
}

static int vault_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    close((int)fi->fh);
    return 0;
}

static int vault_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi) {
    const char *rpath = get_real_path(path);
    int fd = open(rpath, fi->flags, mode);
    if (fd == -1) return -errno;
    fi->fh = (uint64_t)fd;
    return 0;
}

static int vault_unlink(const char *path) {
    int rc = unlink(get_real_path(path));
    return rc == -1 ? -errno : 0;
}

static int vault_mkdir(const char *path, mode_t mode) {
    int rc = mkdir(get_real_path(path), mode);
    return rc == -1 ? -errno : 0;
}

static int vault_rmdir(const char *path) {
    int rc = rmdir(get_real_path(path));
    return rc == -1 ? -errno : 0;
}

static int vault_rename(const char *from, const char *to, unsigned int flags) {
    int rc = renameat2(AT_FDCWD, get_real_path(from),
                       AT_FDCWD, get_real_path(to), flags);
    return rc == -1 ? -errno : 0;
}

static int vault_truncate(const char *path, off_t size,
                          struct fuse_file_info *fi) {
    if (fi) {
        int rc = ftruncate((int)fi->fh, size);
        return rc == -1 ? -errno : 0;
    }
    int rc = truncate(get_real_path(path), size);
    return rc == -1 ? -errno : 0;
}

static int vault_chmod(const char *path, mode_t mode,
                       struct fuse_file_info *fi) {
    (void)fi;
    int rc = chmod(get_real_path(path), mode);
    return rc == -1 ? -errno : 0;
}

static int vault_chown(const char *path, uid_t uid, gid_t gid,
                       struct fuse_file_info *fi) {
    (void)fi;
    int rc = lchown(get_real_path(path), uid, gid);
    return rc == -1 ? -errno : 0;
}

static int vault_symlink(const char *from, const char *to) {
    int rc = symlink(from, get_real_path(to));
    return rc == -1 ? -errno : 0;
}

static int vault_readlink(const char *path, char *buf, size_t size) {
    ssize_t rc = readlink(get_real_path(path), buf, size - 1);
    if (rc == -1) return -errno;
    buf[rc] = '\0';
    return 0;
}

static int vault_statfs(const char *path, struct statvfs *stbuf) {
    int rc = statvfs(get_real_path(path), stbuf);
    return rc == -1 ? -errno : 0;
}

static int vault_utimens(const char *path, const struct timespec ts[2],
                         struct fuse_file_info *fi) {
    (void)fi;
    int rc = utimensat(AT_FDCWD, get_real_path(path), ts, AT_SYMLINK_NOFOLLOW);
    return rc == -1 ? -errno : 0;
}

static const struct fuse_operations vault_ops = {
    .getattr  = vault_getattr,
    .readdir  = vault_readdir,
    .open     = vault_open,
    .read     = vault_read,
    .write    = vault_write,
    .release  = vault_release,
    .create   = vault_create,
    .unlink   = vault_unlink,
    .mkdir    = vault_mkdir,
    .rmdir    = vault_rmdir,
    .rename   = vault_rename,
    .truncate = vault_truncate,
    .chmod    = vault_chmod,
    .chown    = vault_chown,
    .symlink  = vault_symlink,
    .readlink = vault_readlink,
    .statfs   = vault_statfs,
    .utimens  = vault_utimens,
};

/* ── Signal handling ────────────────────────────────────────────────────── */

static void sig_handler(int signum) {
    (void)signum;
    g_running = 0;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <source_path> <mount_point> [fuse_options]\n"
        "  Mounts a FUSE overlay over <source_path> at <mount_point>\n"
        "  that requires per-file authentication for protected items.\n",
        prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    openlog("fuse_vault", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* Resolve source path */
    if (!realpath(argv[1], g_vault.source_path)) {
        fprintf(stderr, "Error: cannot resolve source path '%s': %s\n",
                argv[1], strerror(errno));
        return 1;
    }

    snprintf(g_vault.mount_path, sizeof(g_vault.mount_path), "%s", argv[2]);

    /* Open database */
    if (db_open(&g_vault.db) != 0) {
        fprintf(stderr, "Error: cannot open vault database\n");
        return 1;
    }
    if (db_init_schema(g_vault.db) != 0) {
        fprintf(stderr, "Error: cannot initialise vault schema\n");
        return 1;
    }

    /* Initialise session table */
    session_init(&g_vault.sessions);

    lag_log(LOG_INFO, "Vault daemon starting: %s -> %s",
            g_vault.source_path, g_vault.mount_path);

    /* Build FUSE argv — skip our own args, pass the rest to FUSE */
    char *fuse_argv[64];
    int   fuse_argc = 0;
    fuse_argv[fuse_argc++] = argv[0];
    fuse_argv[fuse_argc++] = g_vault.mount_path;
    /* Default: run in foreground for systemd */
    fuse_argv[fuse_argc++] = "-f";
    /* Pass remaining args */
    for (int i = 3; i < argc && fuse_argc < 63; i++) {
        fuse_argv[fuse_argc++] = argv[i];
    }
    fuse_argv[fuse_argc] = NULL;

    int ret = fuse_main(fuse_argc, fuse_argv, &vault_ops, NULL);

    sqlite3_close(g_vault.db);
    closelog();
    lag_log(LOG_INFO, "Vault daemon stopped");
    return ret;
}
