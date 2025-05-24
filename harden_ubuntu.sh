#!/usr/bin/env bash
#
# harden-ubuntu-24.04.sh
# Quick-start hardening for a new Cloudfanatic Ubuntu 24.04 LTS server.
# Run as **root** (or with sudo) once, right after the VM boots.
# ---------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# ---------- CONFIGURABLE SETTINGS ----------
NEW_USER="ubuntu"
# If you already have an SSH pubkey on the box (root’s ~/.ssh/authorized_keys),
# it will be copied to the new user automatically. Otherwise paste one below:
USER_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID7JTXf7DIPOJpo9nYVxN9b3xrrBYY5mLbsZBdVTQSt/ quinten@lemmalegal.com"

SSH_PORT=22               # Change if you move SSH to a different port
ALLOW_IPV6="no"           # set to "yes" if you *need* IPv6
MAINT_REBOOT_TIME="03:00" # unattended-upgrades auto-reboot time (HH:MM, 24-hour)
# -------------------------------------------

echo "### 1. Creating user '$NEW_USER' and granting sudo…"
if ! id "$NEW_USER" &>/dev/null; then
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

echo "### 2. Installing baseline packages…"
apt-get update -qq
apt-get install -y -qq ufw fail2ban unattended-upgrades \
  auditd audispd-plugins curl vim

echo "### 3. Copying SSH keys to $NEW_USER (if any)…"
install -o "$NEW_USER" -g "$NEW_USER" -m 0700 -d /home/"$NEW_USER"/.ssh
if [[ -f /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys /home/"$NEW_USER"/.ssh/
  chown "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.ssh/authorized_keys
elif [[ -n "$USER_PUBKEY" ]]; then
  echo "$USER_PUBKEY" > /home/"$NEW_USER"/.ssh/authorized_keys
  chown "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.ssh/authorized_keys
else
  echo "!! No existing root key found and USER_PUBKEY is empty. You will be locked out of SSH!"
  exit 1
fi
chmod 600 /home/"$NEW_USER"/.ssh/authorized_keys

echo "### 4. Hardening SSH daemon…"
SSHD_CFG="/etc/ssh/sshd_config.d/99-hardening.conf"
cp /etc/ssh/sshd_config "${SSHD_CFG}.bak.$(date +%s)" || true
cat > "$SSHD_CFG" <<EOF
# Hardening overrides
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UseDNS no
MaxAuthTries 3
AllowUsers $NEW_USER
EOF
systemctl restart ssh || systemctl restart sshd

echo "### 5. Configuring UFW firewall…"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp comment 'SSH'
ufw limit "$SSH_PORT"/tcp comment 'SSH rate-limit'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

echo "### 6. Enabling fail2ban (SSH jail)…"
systemctl enable --now fail2ban

echo "### 7. Setting up unattended-upgrades…"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades-hardened <<EOF
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "$MAINT_REBOOT_TIME";
EOF
systemctl reload unattended-upgrades.service || true

echo "### 8. Installing minimal auditd rules…"
cat > /etc/audit/rules.d/hardening.rules <<'EOF'
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d -p wa -k sudo_changes
-w /var/log/auth.log -k authlog
-w /var/log/faillog -k faillog
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF
augenrules --load

echo "### 9. Kernel sysctl hardening…"
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
cat > "$SYSCTL_FILE" <<EOF
# IPv4 hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
# Optional: disable IPv6 completely
net.ipv6.conf.all.disable_ipv6 = $([[ "$ALLOW_IPV6" == "no" ]] && echo 1 || echo 0)
EOF
sysctl --system >/dev/null

echo "### 10. Disabling unneeded services…"
for svc in avahi-daemon cups; do
  systemctl disable --now "$svc" 2>/dev/null || true
done

echo "### 11. Verifying time sync…"
systemctl enable --now systemd-timesyncd

echo "### 12. All done!"
echo "You can now log in as '$NEW_USER' using your SSH key on port $SSH_PORT."
echo "Firewall: UFW active (in: deny, out: allow).  Ports open → $SSH_PORT / 80 / 443"
echo "Automatic security updates & reboots are scheduled nightly at $MAINT_REBOOT_TIME."
