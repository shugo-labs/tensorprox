#!/bin/bash

# Fast revert script to restore system access after lockdown
#
# Arguments:
#   ip (str): The IP address of the system being reverted.
#   authorized_keys_bak (str): The path to the backup authorized_keys file.
#   authorized_keys_path (str): The path to the authorized_keys file.
#   revert_log (str): The path to the revert log file.

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

# Helper function to execute commands with a timeout
# Usage: run_cmd "command description" timeout_seconds command arg1 arg2...
run_cmd() {
    description=$1
    timeout=$2
    shift 2
    
    echo "Starting: $description"
    timeout $timeout "$@" &>/dev/null || echo "Warning: $description failed"
    echo "Completed: $description"
}

# Set up logging
exec > >(tee -a "$revert_log") 2>&1
echo "=== Revert started for $ip at $(date) ==="

# --- Step 1: Reset firewall rules ---
echo "Resetting firewall rules"
if [ -f "/tmp/iptables.bak" ]; then
    echo "Restoring from backup"
    iptables-restore < /tmp/iptables.bak 2>/dev/null || iptables -F
else
    echo "No backup found, using defaults"
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
fi

# --- Step 2: Restore authorized_keys ---
echo "Restoring SSH authorized keys"
if [ -f "${authorized_keys_path}.bak" ]; then
    echo "Restoring from local backup"
    cp "${authorized_keys_path}.bak" "$authorized_keys_path" 2>/dev/null
    chmod 600 "$authorized_keys_path" 2>/dev/null
elif [ -f "$authorized_keys_bak" ] && [ "$authorized_keys_bak" != "none" ]; then
    echo "Restoring from provided backup"
    cp "$authorized_keys_bak" "$authorized_keys_path" 2>/dev/null
    chmod 600 "$authorized_keys_path" 2>/dev/null
else
    echo "No backup found, removing session keys"
    sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' "$authorized_keys_path" 2>/dev/null
fi

# --- Step 3: Restore sshd configuration ---
echo "Restoring SSH configuration"
if [ -f "/etc/ssh/sshd_config.bak" ]; then
    cp "/etc/ssh/sshd_config.bak" "/etc/ssh/sshd_config" 2>/dev/null
    chmod 644 "/etc/ssh/sshd_config" 2>/dev/null
else
    # Set permissive SSH config
    cat > /etc/ssh/sshd_config << EOF
Protocol 2
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
AllowTcpForwarding yes
PermitTunnel yes
PermitRootLogin yes
EOF
fi

# --- Step 4: Unlock accounts ---
echo "Unlocking root account"
passwd -u root 2>/dev/null

# --- Step 5: Restart SSH service ---
echo "Restarting SSH service"
run_cmd "SSH restart" 10 systemctl restart sshd

# --- Step 6: Restore system settings ---
echo "Restoring system settings"
sysctl -w net.ipv4.ip_forward=1 2>/dev/null
echo 0 > /proc/sys/kernel/modules_disabled 2>/dev/null

echo "=== Revert completed for $ip at $(date) ==="