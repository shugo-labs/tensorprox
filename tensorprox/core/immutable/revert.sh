#!/bin/bash

# Revert script to restore system access after lockdown
#
# Arguments:
#   ip (str): The IP address of the system being reverted.
#   authorized_keys_bak (str): The path to the backup authorized_keys file.
#   authorized_keys_path (str): The path to the authorized_keys file.
#   revert_log (str): The path to the revert log file.
#
# Usage:
#   ./revert.sh <ip> <authorized_keys_bak_path> <authorized_keys_path> <revert_log_path>

set -e  # Exit on error

# Assign arguments to variables
ip="$1"
authorized_keys_bak="$2"
authorized_keys_path="$3"
revert_log="$4"

if [ -z "$ip" ] || [ -z "$authorized_keys_path" ] || [ -z "$revert_log" ]; then
    echo "Missing required arguments"
    echo "Usage: $0 <ip> <authorized_keys_bak_path> <authorized_keys_path> <revert_log_path>"
    exit 1
fi

# Set up logging
exec > >(tee -a "$revert_log") 2>&1
echo "=== Revert started for $ip at $(date) ==="

# Create a function for error handling
function handle_error {
    echo "ERROR: Command failed with exit status $?. Continuing..."
}

# --- Step 1: Restore critical services ---
echo "Restoring critical services..."
systemctl unmask console-getty.service 2>/dev/null || handle_error
systemctl enable console-getty.service 2>/dev/null || handle_error
systemctl start console-getty.service 2>/dev/null || handle_error

systemctl unmask serial-getty@ttyS0.service 2>/dev/null || handle_error
systemctl enable serial-getty@ttyS0.service 2>/dev/null || handle_error
systemctl start serial-getty@ttyS0.service 2>/dev/null || handle_error

# Unmask important services
important_services="atd.service cron.service rsyslog.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service"
for service in $important_services; do
    echo "Enabling $service"
    systemctl unmask $service 2>/dev/null || handle_error
    systemctl enable $service 2>/dev/null || handle_error
    systemctl restart $service 2>/dev/null || handle_error
done

# --- Step 2: Reset firewall rules ---
echo "Resetting firewall rules..."
if [ -f "/tmp/iptables.bak" ]; then
    echo "Restoring firewall rules from backup"
    iptables-restore < /tmp/iptables.bak || handle_error
else
    echo "No firewall backup found. Setting default permissive rules."
    # Nuclear Firewall Flush - flush all tables
    iptables -F || handle_error
    iptables -X || handle_error
    iptables -t nat -F || handle_error
    iptables -t nat -X || handle_error
    iptables -t mangle -F || handle_error
    iptables -t mangle -X || handle_error
    iptables -t raw -F || handle_error
    iptables -t raw -X || handle_error
    iptables -t security -F || handle_error
    iptables -t security -X || handle_error
    
    # Set default policies to ACCEPT
    iptables -P INPUT ACCEPT || handle_error
    iptables -P FORWARD ACCEPT || handle_error
    iptables -P OUTPUT ACCEPT || handle_error
fi

# --- Step 3: Restore authorized_keys ---
echo "Restoring SSH authorized keys..."
if [ -f "${authorized_keys_path}.bak" ]; then
    echo "Restoring from backup: ${authorized_keys_path}.bak"
    cp "${authorized_keys_path}.bak" "$authorized_keys_path" || handle_error
    chmod 600 "$authorized_keys_path" || handle_error
    rm -f "${authorized_keys_path}.bak" || handle_error
elif [ -f "$authorized_keys_bak" ]; then
    echo "Restoring from provided backup: $authorized_keys_bak"
    cp "$authorized_keys_bak" "$authorized_keys_path" || handle_error
    chmod 600 "$authorized_keys_path" || handle_error
    rm -f "$authorized_keys_bak" || handle_error
else
    echo "No backup file found; removing session key block if present."
    sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' "$authorized_keys_path" || handle_error
fi

# --- Step 4: Restore sshd configuration ---
echo "Restoring SSH server configuration..."
if [ -f "/etc/ssh/sshd_config.bak" ]; then
    cp "/etc/ssh/sshd_config.bak" "/etc/ssh/sshd_config" || handle_error
    chmod 644 "/etc/ssh/sshd_config" || handle_error
    rm -f "/etc/ssh/sshd_config.bak" || handle_error
    echo "SSH config restored from backup."
else
    echo "No SSH config backup found. Setting default values."
    # Set default permissive values
    sed -i '/^Protocol 2$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^PubkeyAuthentication yes$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^PasswordAuthentication no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^ChallengeResponseAuthentication no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^UsePAM no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^X11Forwarding no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^AllowTcpForwarding no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^PermitTunnel no$/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^AllowUsers/d' /etc/ssh/sshd_config || handle_error
    sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config || handle_error
    echo 'PermitRootLogin yes' | tee -a /etc/ssh/sshd_config >/dev/null || handle_error
    echo 'PasswordAuthentication yes' | tee -a /etc/ssh/sshd_config >/dev/null || handle_error
fi

# Restart SSH service to apply changes
systemctl restart sshd || handle_error

# --- Step 5: Unlock accounts ---
echo "Unlocking user accounts..."
# Unlock root account
passwd -u root 2>/dev/null || handle_error

# Unlock all user accounts
for u in $(cut -f1 -d: /etc/passwd); do
    usermod -U "$u" 2>/dev/null || handle_error
done

# --- Step 6: Restore system settings ---
echo "Restoring system settings..."
sysctl -w kernel.kptr_restrict=0 2>/dev/null || handle_error
sysctl -w kernel.dmesg_restrict=0 2>/dev/null || handle_error
sysctl -w kernel.perf_event_paranoid=2 2>/dev/null || handle_error
sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || handle_error
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || handle_error
sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || handle_error
sysctl -w net.ipv4.conf.all.send_redirects=1 2>/dev/null || handle_error
sysctl -w net.ipv4.conf.all.accept_source_route=1 2>/dev/null || handle_error
sysctl -w net.ipv4.conf.all.rp_filter=1 2>/dev/null || handle_error
sysctl -p 2>/dev/null || handle_error

# --- Step 7: Restore services ---
echo "Restoring system services..."
systemctl daemon-reload || handle_error

# Unmask masked services
for s in $(systemctl list-unit-files --type=service --state=masked | grep -v '\@' | awk '{print $1}'); do
    echo "Unmasking service: $s"
    systemctl unmask $s 2>/dev/null || handle_error
done

# Start some key services
key_services="sshd systemd-networkd systemd-resolved atd cron rsyslog"
for s in $key_services; do
    echo "Ensuring $s is enabled and running"
    systemctl enable $s 2>/dev/null || handle_error
    systemctl start $s 2>/dev/null || handle_error
done

# Enable loading kernel modules
echo 0 | tee /proc/sys/kernel/modules_disabled >/dev/null 2>/dev/null || handle_error

echo "=== Revert completed for $ip at $(date) ==="
echo "System should now be accessible with original credentials."