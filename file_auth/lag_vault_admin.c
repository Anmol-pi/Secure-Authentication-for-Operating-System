/*
 * lag_vault_admin.c — Privileged launcher for LinuxAuthGuard Vault GUI
 *
 * This binary is the pkexec target registered in the polkit policy.
 * pkexec elevates it to root, it sets LAG_ADMIN_MODE=1, restores the
 * display environment from argv, then execs vault_gui.py under python3.
 *
 * Compile:
 *   gcc -Wall -Wextra -o lag-vault-admin lag_vault_admin.c
 *
 * Install to /usr/lib/linuxauthguard/file_auth/lag-vault-admin (mode 755)
 * The polkit policy must annotate exec.path to this binary's installed path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PYTHON      "/usr/bin/python3"
#define VAULT_GUI   "/usr/lib/linuxauthguard/file_auth/vault_gui.py"

int main(int argc, char *argv[]) {
    /*
     * argv[1] = DISPLAY value   (passed by vault_gui_sudo_launcher.sh)
     * argv[2] = XAUTHORITY value
     * argv[3] = DBUS_SESSION_BUS_ADDRESS value
     * All three are optional — we just skip missing ones gracefully.
     */
    if (argc >= 2 && strlen(argv[1]) < 256)
        setenv("DISPLAY", argv[1], 1);

    if (argc >= 3 && strlen(argv[2]) < 512)
        setenv("XAUTHORITY", argv[2], 1);

    if (argc >= 4 && strlen(argv[3]) < 512)
        setenv("DBUS_SESSION_BUS_ADDRESS", argv[3], 1);

    setenv("LAG_ADMIN_MODE", "1", 1);

    /* Ensure runtime dir exists */
    if (access("/run/linuxauthguard", F_OK) != 0)
        system("mkdir -p /run/linuxauthguard");

    char *args[] = { PYTHON, VAULT_GUI, NULL };
    execv(PYTHON, args);

    /* execv only returns on failure */
    perror("execv python3");
    return 1;
}
