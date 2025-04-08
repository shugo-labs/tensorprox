#!/bin/bash

# Faster lockdown script that avoids common hang issues
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').

# Set variables based on script arguments
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path>"
    exit 1
fi

# Helper function to execute commands with a timeout
# Usage: run_cmd "command description" timeout_seconds command arg1 arg2...
run_cmd() {
    description=$1
    timeout=$2
    shift 2
    
    echo "Starting: $description"
    timeout $timeout "$@" &>/dev/null || echo "Warning: $description may not have completed successfully"
    echo "Completed: $description"
}

# Log file for debugging
LOCKDOWN_LOG="/tmp/lockdown_$(date +%s).log"
exec > >(tee -a "$LOCKDOWN_LOG") 2>&1

echo "Starting lockdown procedure at $(date)"
echo "Parameters: ssh_user=$ssh_user, ssh_dir=$ssh_dir, validator_ip=$validator_ip, authorized_keys_path=$authorized_keys_path"

############################################################
# 0) Create backup files for restoration
############################################################
echo "Creating backup files"
cp "$authorized_keys_path" "${authorized_keys_path}.bak" 2>/dev/null || echo "Warning: Could not backup authorized_keys"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || echo "Warning: Could not backup sshd_config"

############################################################
# 1) Lock non-system accounts but keep root accessible
############################################################
echo "Securing user accounts"
passwd -l root 2>/dev/null || echo "Warning: Could not lock root account"

############################################################
# 2) Set up minimal firewall rules (focus on SSH access)
############################################################
echo "Setting up firewall"

# Save current iptables rules for restoration
iptables-save > /tmp/iptables.bak 2>/dev/null || echo "Warning: Could not backup iptables rules"

# Get primary interface
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
[ -z "$NIC" ] && NIC="eth0" # Fallback if detection fails

echo "Using network interface: $NIC"

# Fast firewall setup focused only on essential rules
iptables -F 2>/dev/null
iptables -X 2>/dev/null

# Only allow SSH from validator IP and allow all tunnel traffic
iptables -A INPUT -i "$NIC" -p tcp --dport 22 -s "$validator_ip" -j ACCEPT 2>/dev/null
iptables -A OUTPUT -o "$NIC" -p tcp --sport 22 -d "$validator_ip" -j ACCEPT 2>/dev/null

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null

# Allow GRE and IPIP tunneling protocols
iptables -A INPUT -p gre -j ACCEPT 2>/dev/null
iptables -A OUTPUT -p gre -j ACCEPT 2>/dev/null
iptables -A INPUT -p ipip -j ACCEPT 2>/dev/null
iptables -A OUTPUT -p ipip -j ACCEPT 2>/dev/null

# Allow ICMP for diagnostics
iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
iptables -A OUTPUT -p icmp -j ACCEPT 2>/dev/null

# Set default policies
iptables -P INPUT DROP 2>/dev/null
iptables -P FORWARD DROP 2>/dev/null
iptables -P OUTPUT DROP 2>/dev/null

############################################################
# 3) Configure SSH to allow only validator access
############################################################
echo "Configuring SSH"

# Only keep session keys in authorized_keys file
if [ -f "$authorized_keys_path" ]; then
    echo "Processing authorized_keys"
    TMPDIR=$(mktemp -d)
    
    # Extract session key block
    awk '/# START SESSION KEY/,/# END SESSION KEY/' "$authorized_keys_path" > "$TMPDIR/session_only" 2>/dev/null
    
    # If extraction succeeded and file is not empty
    if [ -s "$TMPDIR/session_only" ]; then
        cp "$TMPDIR/session_only" "$authorized_keys_path" 2>/dev/null
    else
        echo "Warning: No session keys found"
    fi
    
    # Set proper permissions
    chown -R "$ssh_user:$ssh_user" "$ssh_dir" 2>/dev/null
    chmod 700 "$ssh_dir" 2>/dev/null
    chmod 600 "$authorized_keys_path" 2>/dev/null
    
    rm -rf "$TMPDIR" 2>/dev/null
fi

# Update SSH config with minimal changes
cat > /etc/ssh/sshd_config << EOF
# Minimal SSH Server Configuration
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
EOF

# Restart SSH service with timeout
run_cmd "Restarting SSH" 10 systemctl restart sshd

echo "Lockdown procedure completed at $(date)"
echo "Log saved to $LOCKDOWN_LOG"