#!/usr/bin/env bash
#
# 18-ssh-hardening.sh
#
# Two small sshd hardening tweaks on top of Debian 13's already-strong
# OpenSSH 10 defaults (ChaCha20-Poly1305/AES-GCM ciphers, post-quantum
# hybrid KEX, ed25519/ECDSA-preferred host and pubkey algorithms, no
# legacy ssh-rsa/SHA-1, PasswordAuthentication+KbdInteractiveAuthentication
# both off) - found live 2026-11-05 reviewing the whole crypto config,
# with the explicit goal of improving on an already-strong baseline
# rather than changing anything that was already fine:
#
#   - MACs restricted to ETM (encrypt-then-MAC) variants with SHA-2/256+
#     only. Low practical impact on its own - AEAD ciphers
#     (chacha20-poly1305, aes-gcm) don't use a separate MAC at all and
#     are preferred first by any modern client - this only closes a
#     fallback path for a hypothetical old client forcing a CTR cipher
#     (removes umac-64-etm's 64-bit tag, hmac-sha1-etm, and the
#     non-ETM/non-SHA2 legacy entries that were still accepted).
#   - X11Forwarding off: this is a headless mail server, X11 is never
#     used here. AllowTcpForwarding deliberately stays ON - needed for
#     SSH tunnelling use cases that are unrelated to X11.
#
# Raised but NOT applied (no urgency): RequiredRSASize (OpenSSH's own
# default of 1024 could be raised), LogLevel VERBOSE (would also log the
# key fingerprint per login), Compression off (negligible impact either
# way on a fast link).
#
# Idempotent: always (re)writes the same drop-in file and reloads - safe
# to run again on a replay.

step_ssh_hardening()
{
require_cmd sshd

local DROPIN="/etc/ssh/sshd_config.d/60-ssh-hardening.conf"

backup_file "$DROPIN"
cat > "$DROPIN" <<'EOF'
# Restricts MACs to ETM (encrypt-then-MAC) variants with SHA-2/256+ only.
# In practice AEAD ciphers (chacha20-poly1305, aes-gcm) don't use a
# separate MAC at all and are preferred first by any modern client, so
# this only closes the fallback path for a hypothetical old client that
# forces a CTR cipher - removes umac-64-etm (64-bit tag), hmac-sha1-etm,
# and the non-ETM legacy entries (umac-64, umac-128, hmac-sha2-256,
# hmac-sha2-512, hmac-sha1) that were still listed as acceptable.
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Headless mail server - X11 forwarding is never used here. AllowTcpForwarding
# stays on (needed for SSH tunnelling use cases), only X11Forwarding is disabled.
X11Forwarding no
EOF
chmod 644 "$DROPIN"
finalize_backup "$DROPIN"

sshd -t || die "sshd -t rejected $DROPIN - reverted nothing, check the file by hand."
systemctl reload ssh || die "Could not reload ssh after writing $DROPIN."
log "[ OK ] Wrote $DROPIN (MACs restricted to ETM-only, X11Forwarding off) and reloaded sshd."
}
