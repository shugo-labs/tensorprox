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

# --- Step 4: Restore sshd_config ---
echo "Restoring SSH configuration..."
if [ -f "/etc/ssh/sshd_config.bak" ]; then
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config || handle_error
    systemctl restart sshd || handle_error
else
    echo "No backup of sshd_config found"
fi

echo "Revert procedure completed at $(date)"
