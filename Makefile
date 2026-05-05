# LinuxAuthGuard — Makefile
#
# Targets:
#   make            — build PAM module and FUSE daemon
#   make install    — install everything (run as root)
#   make uninstall  — remove installed files
#   make clean      — remove build artefacts
#   make test       — run Python unit tests

CC       := gcc
CFLAGS   := -O2 -Wall -Wextra -fPIC \
            -fstack-protector-strong \
            -D_FORTIFY_SOURCE=2 \
            -I core/include
LDFLAGS  :=

# fuse3 cflags/libs: use pkg-config if available, else hard-coded fallback
# (libfuse3-dev on Ubuntu/Debian installs headers under /usr/include/fuse3)
FUSE3_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null || echo -I/usr/include/fuse3)
FUSE3_LIBS   := $(shell pkg-config --libs   fuse3 2>/dev/null || echo -lfuse3)

# -------------------------------------------------------------------------
# Paths
# -------------------------------------------------------------------------
PREFIX        := /usr
LIB_DIR       := $(PREFIX)/lib/linuxauthguard
PAM_LIB_DIR   := /lib/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)/security
SYSTEMD_DIR   := /etc/systemd/system
CONFIG_DIR    := /etc/linuxauthguard
DATA_DIR      := /var/lib/linuxauthguard
LOG_DIR       := /var/log/linuxauthguard
RUN_DIR       := /run/linuxauthguard

# -------------------------------------------------------------------------
# Sources
# -------------------------------------------------------------------------
CORE_SRCS := core/buffer_safe.c \
             core/audit_log.c   \
             core/session.c     \
             core/totp.c

PAM_SRCS  := core/pam_linuxauthguard.c $(CORE_SRCS)
PAM_OBJ   := $(PAM_SRCS:.c=.o)
PAM_SO    := pam_linuxauthguard.so

FUSE_SRC  := file_auth/fuse_vault.c
FUSE_BIN  := fuse_vault

# -------------------------------------------------------------------------
# Default target
# -------------------------------------------------------------------------
.PHONY: all
all: $(PAM_SO) $(FUSE_BIN)

# -------------------------------------------------------------------------
# PAM shared library
# -------------------------------------------------------------------------
$(PAM_SO): $(PAM_OBJ)
	$(CC) -shared -o $@ $^ \
	    -lpam -lsqlite3 -lpthread \
	    $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# -------------------------------------------------------------------------
# FUSE daemon
# -------------------------------------------------------------------------
$(FUSE_BIN): $(FUSE_SRC) $(CORE_SRCS)
	$(CC) $(CFLAGS) $(FUSE3_CFLAGS) -o $@ $^ \
	    $(FUSE3_LIBS) -lsqlite3 -lsodium -largon2 -lpthread \
	    $(LDFLAGS)

# -------------------------------------------------------------------------
# Install
# -------------------------------------------------------------------------
.PHONY: install
install: all install-dirs install-pam install-fuse install-python install-config install-systemd

install-dirs:
	install -d $(DESTDIR)$(LIB_DIR)
	install -d $(DESTDIR)$(PAM_LIB_DIR)
	install -d $(DESTDIR)$(CONFIG_DIR)
	install -d $(DESTDIR)$(DATA_DIR)
	install -d $(DESTDIR)$(LOG_DIR)
	install -d $(DESTDIR)$(RUN_DIR)
	install -d $(DESTDIR)$(LIB_DIR)/ml
	install -d $(DESTDIR)$(LIB_DIR)/sudo_tracker
	install -d $(DESTDIR)$(LIB_DIR)/file_auth

install-pam: $(PAM_SO)
	install -m 644 $(PAM_SO) $(DESTDIR)$(PAM_LIB_DIR)/
	# Install PAM service file
	install -d $(DESTDIR)/etc/pam.d
	printf 'auth    required   pam_linuxauthguard.so\naccount required   pam_linuxauthguard.so\nsession optional   pam_linuxauthguard.so\n' \
	    > $(DESTDIR)/etc/pam.d/linuxauthguard

install-fuse: $(FUSE_BIN)
	install -m 755 $(FUSE_BIN) $(DESTDIR)$(LIB_DIR)/

install-python:
	# ML service
	install -m 755 ml/ml_service.py    $(DESTDIR)$(LIB_DIR)/ml/
	install -m 644 ml/classifier.py    $(DESTDIR)$(LIB_DIR)/ml/
	install -m 644 ml/feature_extractor.py $(DESTDIR)$(LIB_DIR)/ml/
	install -m 644 ml/trainer.py       $(DESTDIR)$(LIB_DIR)/ml/
	install -m 644 ml/notifier.py      $(DESTDIR)$(LIB_DIR)/ml/
	install -m 644 ml/seed_dataset.csv $(DESTDIR)$(LIB_DIR)/ml/
	# Sudo tracker
	install -m 755 sudo_tracker/sudo_logger.py    $(DESTDIR)$(LIB_DIR)/sudo_tracker/
	install -m 755 sudo_tracker/dashboard.py      $(DESTDIR)$(LIB_DIR)/sudo_tracker/
	install -m 644 sudo_tracker/sudo_db.py        $(DESTDIR)$(LIB_DIR)/sudo_tracker/
	install -m 644 sudo_tracker/anomaly_detector.py $(DESTDIR)$(LIB_DIR)/sudo_tracker/
	install -m 755 sudo_tracker/pam_exec_hook.sh  $(DESTDIR)$(LIB_DIR)/
	# File auth GUI
	install -m 755 file_auth/vault_gui.py     $(DESTDIR)$(LIB_DIR)/file_auth/
	install -m 755 file_auth/vault_cli.py     $(DESTDIR)$(LIB_DIR)/file_auth/
	install -m 644 file_auth/vault_db.py      $(DESTDIR)$(LIB_DIR)/file_auth/
	install -m 644 file_auth/prompt_dialog.py $(DESTDIR)$(LIB_DIR)/file_auth/
	# Nautilus encryption extension
	install -d /usr/share/nautilus-python/extensions
	install -m 644 file_auth/lag_encrypt_extension.py \
	    /usr/share/nautilus-python/extensions/

install-config:
	install -m 640 config/linuxauthguard.conf $(DESTDIR)$(CONFIG_DIR)/

install-systemd:
	install -m 644 systemd/linuxauthguard-file-auth.service \
	    $(DESTDIR)$(SYSTEMD_DIR)/
	install -m 644 systemd/linuxauthguard-ml.service \
	    $(DESTDIR)$(SYSTEMD_DIR)/
	install -m 644 systemd/linuxauthguard-sudo-tracker.service \
	    $(DESTDIR)$(SYSTEMD_DIR)/
	@echo "Run: systemctl daemon-reload && systemctl enable --now linuxauthguard-file-auth linuxauthguard-ml linuxauthguard-sudo-tracker"

# -------------------------------------------------------------------------
# Uninstall
# -------------------------------------------------------------------------
.PHONY: uninstall
uninstall:
	systemctl stop linuxauthguard-file-auth linuxauthguard-ml linuxauthguard-sudo-tracker 2>/dev/null || true
	systemctl disable linuxauthguard-file-auth linuxauthguard-ml linuxauthguard-sudo-tracker 2>/dev/null || true
	rm -f $(PAM_LIB_DIR)/$(PAM_SO)
	rm -f /etc/pam.d/linuxauthguard
	rm -rf $(LIB_DIR)
	rm -f $(SYSTEMD_DIR)/linuxauthguard-*.service
	systemctl daemon-reload 2>/dev/null || true
	@echo "Config and data directories preserved. Remove manually if desired:"
	@echo "  rm -rf $(CONFIG_DIR) $(DATA_DIR) $(LOG_DIR)"

# -------------------------------------------------------------------------
# Clean
# -------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -f $(PAM_OBJ) $(PAM_SO) $(FUSE_BIN)
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# -------------------------------------------------------------------------
# Test
# -------------------------------------------------------------------------
.PHONY: test
test:
	python3 -m pytest tests/ -v 2>/dev/null || \
	    python3 -m unittest discover -s tests -v
