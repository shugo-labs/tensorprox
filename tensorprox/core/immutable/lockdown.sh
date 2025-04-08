#!/bin/bash

# Lock down the system while maintaining core functionality for gre_setup
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').

set -e  # Exit on error

# Set variables based on script arguments
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path>"
    exit 1
fi

# Log file for debugging
LOCKDOWN_LOG="/tmp/lockdown_$(date +%s).log"
exec > >(tee -a "$LOCKDOWN_LOG") 2>&1

echo "Starting lockdown procedure at $(date)"
echo "Parameters: ssh_user=$ssh_user, ssh_dir=$ssh_dir, validator_ip=$validator_ip, authorized_keys_path=$authorized_keys_path"

############################################################
# 0) Create backup files for restoration
############################################################
echo "Creating backup files for later restoration"
# Backup authorized_keys
cp "$authorized_keys_path" "${authorized_keys_path}.bak" || echo "Failed to backup authorized_keys"
# Backup sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || echo "Failed to backup sshd_config"

############################################################
# 1) Minimal services - avoid stopping critical networking services
############################################################
echo "Limiting services to essential ones only"
essential_services="apparmor.service dbus.service networkd-dispatcher.service polkit.service rsyslog.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service cron.service"

for s in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    if echo "$essential_services" | grep -wq "$s"; then
        echo "Keeping essential service: $s"
    else
        # Only disable non-essential services, don't mask them
        echo "Stopping+disabling $s"
        systemctl stop "$s" 2>/dev/null || echo "Failed to stop $s"
        systemctl disable "$s" 2>/dev/null || echo "Failed to disable $s"
    fi
done

############################################################
# 2) Disable console TTY but keep serial access for debugging
############################################################
echo "Restricting console access"
if [ -f "/etc/securetty" ]; then
    sed -i '/^tty[0-9]/d' "/etc/securetty" 2>/dev/null || echo "Failed to modify /etc/securetty"
    sed -i '/^ttyS/d' "/etc/securetty" 2>/dev/null || echo "Failed to modify /etc/securetty"
fi

# Stop but don't mask these services (to allow restoration)
systemctl stop console-getty.service 2>/dev/null || echo "Failed to stop console-getty"
systemctl disable console-getty.service 2>/dev/null || echo "Failed to disable console-getty"
systemctl stop serial-getty@ttyS0.service 2>/dev/null || echo "Failed to stop serial-getty@ttyS0"
systemctl disable serial-getty@ttyS0.service 2>/dev/null || echo "Failed to disable serial-getty@ttyS0"

############################################################
# 3) Secure root account but don't lock completely
############################################################
echo "Securing root account"
passwd -l root 2>/dev/null || echo "Failed to lock root account"

############################################################
# 4) Configure Firewall => allow validator_ip and established connections
############################################################
echo "Setting up firewall rules"
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected network interface: $NIC"

# Save current iptables rules for restoration
iptables-save > /tmp/iptables.bak

# Set up new rules
iptables -F
iptables -X

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow localhost traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow SSH from validator IP
iptables -A INPUT -i "$NIC" -p tcp --dport 22 -s "$validator_ip" -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p tcp --sport 22 -d "$validator_ip" -j ACCEPT

# Allow DNS for hostname resolution (needed for some tools)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Allow common network protocols needed for tunnel setup
iptables -A INPUT -p gre -j ACCEPT
iptables -A OUTPUT -p gre -j ACCEPT
iptables -A INPUT -p ipip -j ACCEPT
iptables -A OUTPUT -p ipip -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Default policies - reject rather than drop (more friendly for debugging)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

############################################################
# 5) Keep only session keys in authorized_keys file
############################################################
echo "Configuring SSH keys"
if [ -f "$authorized_keys_path" ]; then
    echo "Cleaning authorized_keys to keep only session keys"
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    
    # Extract session key block
    awk '/# START SESSION KEY/,/# END SESSION KEY/' "$authorized_keys_path" > "$TMPDIR/session_only" || {
        echo "Error extracting session keys. Keeping original file."
        cp "$authorized_keys_path" "$TMPDIR/session_only"
    }
    
    # If extraction succeeded and file is not empty
    if [ -s "$TMPDIR/session_only" ]; then
        cp "$TMPDIR/session_only" "$authorized_keys_path"
        echo "Session key extraction successful"
    else
        echo "WARNING: No session keys found or extraction failed. Keeping original keys."
    fi
    
    # Set proper permissions
    chown -R "$ssh_user:$ssh_user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$authorized_keys_path"
fi

############################################################
# 6) Configure SSH server securely
############################################################
echo "Hardening SSH configuration"
# Backup original config if not already done
cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Update SSH config
cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration
Protocol 2
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
PermitTunnel yes
AllowUsers $ssh_user
PermitRootLogin no
StrictModes yes
UsePrivilegeSeparation yes
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Restart SSH service to apply changes
systemctl restart sshd || echo "Failed to restart sshd"

echo "Lockdown procedure completed at $(date)"
echo "Log saved to $LOCKDOWN_LOG"