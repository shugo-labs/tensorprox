#!/bin/bash
# Lockdown script with automatic revert functionality
#
# Usage:
#   ./lockdown.sh <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path> [revert_timeout_seconds]
#
# Arguments:
#   ssh_user            - SSH username allowed during lockdown
#   ssh_dir             - SSH directory path (e.g., /home/user/.ssh)
#   validator_ip        - IP allowed for SSH access
#   authorized_keys_path- Path to authorized_keys file
#   revert_timeout      - Timeout in seconds before automatic revert (default: 180 seconds)

set -euo pipefail

ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"
authorized_keys_bak="$5"
revert_timeout="$6"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments."
    echo "Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path> [revert_timeout_seconds]"
    exit 1
fi

log_dir="/var/log/security"
mkdir -p "$log_dir"
lockdown_log="$log_dir/lockdown_$(date +%Y%m%d_%H%M%S).log"
revert_log="$log_dir/revert_$(date +%Y%m%d_%H%M%S).log"

# Backup sshd_config
if [ -f "/etc/ssh/sshd_config" ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    chmod 600 /etc/ssh/sshd_config.bak
fi

# Redirect lockdown logging
exec > >(tee -a "$lockdown_log") 2>&1
echo "=== Lockdown started at $(date) ==="
echo "Auto-revert scheduled after $revert_timeout seconds"

# Create revert script dynamically
setup_revert_script() {
    local revert_script="/tmp/revert_script_$(date +%s).sh"
    cat > "$revert_script" << 'EOF'
#!/bin/bash
ssh_user="$1"
ip="$2"
authorized_keys_bak="$3"
authorized_keys_path="$4"
revert_log="$5"

exec > "$revert_log" 2>&1
echo "=== Revert started for $ip at $(date) ==="

# Restore critical services
for svc in getty@tty1.service console-getty.service serial-getty@ttyS0.service atd.service cron.service fwupd.service haveged.service udisks2.service unattended-upgrades.service upower.service user@0.service user@999.service; do
    systemctl unmask "$svc" || echo "Failed to unmask $svc"
    systemctl enable "$svc" || echo "Failed to enable $svc"
    systemctl start "$svc" || echo "Failed to start $svc"
done

# Flush firewall rules and reset to ACCEPT all
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables -t security -F
iptables -t security -X
cat <<IPTABLES_EOF | iptables-restore
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
IPTABLES_EOF

# Unlock root and non-valiops users
passwd -u root || echo "Failed to unlock root"
usermod -s /bin/bash root || echo "Failed to restore shell for root"

for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    if [ "$user" != "$ssh_user" ]; then
        passwd -u "$user" || echo "Failed to unlock $user"
        usermod -s /bin/bash "$user" || echo "Failed to restore shell for $user"
    fi
done

# Restore authorized_keys
if [ -f "$authorized_keys_bak" ]; then
    cp "$authorized_keys_bak" "$authorized_keys_path"
    chmod 600 "$authorized_keys_path"
    rm -f "$authorized_keys_bak"
    echo "Restored authorized_keys from backup"
else
    echo "No authorized_keys backup found"
fi

# Restore sshd_config and restart sshd
if [ -f /etc/ssh/sshd_config.bak ]; then
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config || echo "Failed to restore sshd_config"
    systemctl restart sshd.service || echo "Failed to restart sshd"
else
    echo "No sshd_config backup found"
fi

# Unmask and start essential masked services
for s in $(systemctl list-units --type=service --state=masked --no-pager --no-legend | awk '{print $1}'); do
    if [[ "$s" =~ ^(systemd-|dbus.|polkit.|rsyslog.|snapd.) ]]; then
        systemctl unmask "$s" || echo "Failed to unmask $s"
        systemctl start "$s" || echo "Failed to start $s"
    fi
done

echo "=== Revert completed for $ip at $(date) ==="
EOF
    chmod +x "$revert_script"
    echo "$revert_script"
}

# Schedule revert using systemd timer
schedule_revert_systemd() {
    local revert_script="$1"
    local timeout="$2"
    local svc_name="autorevert-$(date +%s)"

    cat > "/etc/systemd/system/${svc_name}.service" << EOF
[Unit]
Description=Automatic revert of security lockdown
After=network.target

[Service]
Type=oneshot
ExecStart=$revert_script "$ssh_user" "$validator_ip" "$authorized_keys_bak" "$authorized_keys_path" "$revert_log"
User=root

[Install]
WantedBy=multi-user.target
EOF

    cat > "/etc/systemd/system/${svc_name}.timer" << EOF
[Unit]
Description=Timer for automatic revert of security lockdown

[Timer]
OnActiveSec=${timeout}
Unit=${svc_name}.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable "${svc_name}.timer"
    systemctl start "${svc_name}.timer"

    echo "Systemd timer ${svc_name}.timer created and started"
    echo "Revert scheduled in $timeout seconds"
}

# Schedule revert using at command
schedule_revert_at() {
    local revert_script="$1"
    local timeout="$2"

    systemctl start atd.service || echo "Failed to start atd"
    echo "$revert_script \"$ssh_user\" \"$validator_ip\" \"$authorized_keys_bak\" \"$authorized_keys_path\" \"$revert_log\"" | at now + "$timeout" seconds
    echo "Revert scheduled with at command in $timeout seconds"
}

# Schedule revert using sleep fallback
schedule_revert_sleep() {
    local revert_script="$1"
    local timeout="$2"

    nohup bash -c "sleep $timeout && $revert_script \"$ssh_user\" \"$validator_ip\" \"$authorized_keys_bak\" \"$authorized_keys_path\" \"$revert_log\"" >/dev/null 2>&1 &
    echo "Revert scheduled with sleep fallback in $timeout seconds"
}

# Create revert script
revert_script=$(setup_revert_script)
echo "Created revert script at $revert_script"

# Schedule revert
if command -v systemctl &> /dev/null; then
    schedule_revert_systemd "$revert_script" "$revert_timeout"
elif command -v at &> /dev/null; then
    schedule_revert_at "$revert_script" "$revert_timeout"
else
    echo "WARNING: Neither systemd nor at found, using sleep fallback"
    schedule_revert_sleep "$revert_script" "$revert_timeout"
fi

############################################################
# LOCKDOWN PROCEDURES START HERE
############################################################

echo "Stopping and masking non-essential services..."

allowed_services="apparmor.service dbus.service networkd-dispatcher.service acpid.service polkit.service rsyslog.service snapd.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service packagekit.service"
for svc in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    if ! echo "$allowed_services" | grep -qw "$svc"; then
        echo "Stopping and masking $svc"
        systemctl stop "$svc" || echo "Failed to stop $svc"
        systemctl disable "$svc" || echo "Failed to disable $svc"
        systemctl mask "$svc" || echo "Failed to mask $svc"
    fi
done

echo "Disabling console TTYs..."
if [ -f /etc/securetty ]; then
    sed -i '/^tty[0-9]/d' /etc/securetty || echo "Failed to modify /etc/securetty"
    sed -i '/^ttyS/d' /etc/securetty || echo "Failed to modify /etc/securetty"
fi
for tty_svc in console-getty.service serial-getty@ttyS0.service; do
    systemctl stop "$tty_svc" || echo "Failed to stop $tty_svc"
    systemctl disable "$tty_svc" || echo "Failed to disable $tty_svc"
    systemctl mask "$tty_svc" || echo "Failed to mask $tty_svc"
done

echo "Configuring firewall to allow only SSH from $validator_ip..."

NIC=$(ip route | grep default | awk '{print $5}' | head -1)

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i "$NIC" -p tcp -s "$validator_ip" --dport 22 -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p tcp --sport 22 -d "$validator_ip" -j ACCEPT

iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

iptables -A INPUT -p 47 -j ACCEPT  # GRE
iptables -A OUTPUT -p 47 -j ACCEPT
iptables -A INPUT -p 4 -j ACCEPT   # IPIP
iptables -A OUTPUT -p 4 -j ACCEPT

iptables -A INPUT -p tcp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p udp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p udp -d 10.0.0.0/8 -j ACCEPT

iptables -A INPUT -p tcp ! -s 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -p tcp ! -d 10.0.0.0/8 -j REJECT
iptables -A INPUT -p udp ! -s 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -p udp ! -d 10.0.0.0/8 -j REJECT

echo "Locking root and non-$ssh_user accounts..."

passwd -l root || echo "Failed to lock root"
usermod -s /sbin/nologin root || echo "Failed to set nologin for root"

for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    if [ "$user" != "$ssh_user" ]; then
        passwd -l "$user" || echo "Failed to lock $user"
        usermod -s /sbin/nologin "$user" || echo "Failed to set nologin for $user"
    fi
done

echo "Disabling packet capture tools and promiscuous mode..."

pkill -9 tcpdump || true
pkill -9 wireshark || true
pkill -9 tshark || true
pkill -9 dumpcap || true
pkill -9 ettercap || true

for tool in /usr/bin/tcpdump /usr/sbin/tcpdump /usr/bin/dumpcap /usr/sbin/dumpcap; do
    if [ -f "$tool" ]; then
        chmod -s "$tool" || echo "Failed to remove setuid from $tool"
    fi
done

for iface in $(ip link show | grep -o '^[0-9]\+: [^:]\+' | cut -d' ' -f2); do
    if ip link show "$iface" | grep -q PROMISC; then
        ip link set "$iface" promisc off
        echo "Promiscuous mode disabled on $iface"
    fi
done

echo "=== Lockdown completed at $(date) ==="