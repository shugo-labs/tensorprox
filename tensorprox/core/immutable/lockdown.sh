#!/bin/bash

# Lock down the system and configure services securely.
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').

# Set variables based on script arguments (you can modify or provide these values).
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path>"
    exit 1
fi

############################################################
# 1) Minimal services
############################################################
allowed="apparmor.service dbus.service networkd-dispatcher.service polkit.service rsyslog.service snapd.service ssh.service systemd-journald.service systemd-logind.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service systemd-udevd.service atd.service"
for s in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    if echo "$allowed" | grep -wq "$s"; then
        :
    else
        echo "Stopping+masking $s"
        systemctl stop "$s" || echo "Failed to stop $s"
        systemctl disable "$s" || echo "Failed to disable $s"
        systemctl mask "$s" || echo "Failed to mask $s"
    fi
done

############################################################
# 2) Disable console TTY if /etc/securetty
############################################################
if [ -f "/etc/securetty" ]; then
    sed -i '/^tty[0-9]/d' "/etc/securetty" || echo "Failed to modify /etc/securetty"
    sed -i '/^ttyS/d' "/etc/securetty" || echo "Failed to modify /etc/securetty"
fi
systemctl stop console-getty.service || echo "Failed to stop console-getty"
systemctl disable console-getty.service || echo "Failed to disable console-getty"
systemctl mask console-getty.service || echo "Failed to mask console-getty"
systemctl stop serial-getty@ttyS0.service || echo "Failed to stop serial-getty@ttyS0"
systemctl disable serial-getty@ttyS0.service || echo "Failed to disable serial-getty@ttyS0"
systemctl mask serial-getty@ttyS0.service || echo "Failed to mask serial-getty@ttyS0"

############################################################
# 3) Configure Firewall => only allow $validator_ip
############################################################
NIC=$(ip route | grep default | awk '{print $5}' | head -1)

# Flush existing rules
iptables -F
iptables -X

# Set default policies to DROP (safer)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from validator
iptables -A INPUT -i "$NIC" -p tcp -s "$validator_ip" --dport 22 -j ACCEPT
iptables -A OUTPUT -o "$NIC" -p tcp --sport 22 -d "$validator_ip" -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Allow GRE and IPIP
iptables -A INPUT -p 47 -j ACCEPT  # GRE
iptables -A OUTPUT -p 47 -j ACCEPT
iptables -A INPUT -p 4 -j ACCEPT   # IPIP
iptables -A OUTPUT -p 4 -j ACCEPT

# Allow TCP from overlay (entire 10.0.0.0/8 range)
iptables -A INPUT  -p tcp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT

# Allow UDP from overlay
iptables -A INPUT  -p udp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p udp -d 10.0.0.0/8 -j ACCEPT

# Ensure rules persist across reboots if using iptables
# This might require additional setup depending on your system.

############################################################
# 4) Lock non-valiops users (including root)
############################################################
echo "Locking the root account (passwd + no shell)."
passwd -l root || echo "Failed to lock root account"
usermod -s /sbin/nologin root || echo "Failed to set nologin shell for root"

echo "Locking all non-valiops users (passwd + no shell)."
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    if [ "$user" != "$ssh_user" ]; then
        echo "Locking user: $user"
        passwd -l "$user" || echo "Failed to lock $user"
        usermod -s /sbin/nologin "$user" || echo "Failed to set nologin shell for $user"
    fi
done

############################################################
# 5) Kill non-essential processes
############################################################
echo "Killing non-essential processes."
ps -ef \
| grep -v systemd \
| grep -v '\[.*\]' \
| grep -v sshd \
| grep -v bash \
| grep -v ps \
| grep -v grep \
| grep -v awk \
| grep -v nohup \
| grep -v revert_launcher \
| grep -v revert_privacy \
| grep -v paramiko \
| awk '{print $2}' \
| while read pid; do
    kill "$pid" 2>/dev/null || echo "Failed to kill $pid"
done

############################################################
# 6) Disable network monitoring and packet capture
############################################################
echo "Disabling packet capture capabilities"

# Find and kill common packet capture tools
pkill -9 tcpdump || true
pkill -9 wireshark || true
pkill -9 tshark || true
pkill -9 dumpcap || true
pkill -9 ettercap || true

# Remove the setuid bit from packet capture tools
for tool in /usr/bin/tcpdump /usr/sbin/tcpdump /usr/bin/dumpcap /usr/sbin/dumpcap; do
    if [ -f "$tool" ]; then
        chmod -s "$tool" || echo "Failed to remove setuid from $tool"
    fi
done

# Check for interfaces in promiscuous mode
for iface in $(ip link show | grep -o '^[0-9]\+: [^:]\+' | cut -d' ' -f2); do
    if ip link show "$iface" | grep -q PROMISC; then
        echo "Resetting interface $iface (was in promiscuous mode)"
        ip link set "$iface" promisc off
    fi
done

# Disable BPF JIT compiler which can be used for snooping
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    echo 0 > /proc/sys/net/core/bpf_jit_enable
fi

############################################################
# 7) Find and kill hidden processes
############################################################
echo "Detecting and killing hidden processes"

# Install unhide if not present (may need network access during setup phase)
if ! command -v unhide &> /dev/null; then
    echo "unhide not found, skipping hidden process detection"
else
    # Run unhide to find hidden processes
    unhide_output=$(unhide proc 2>/dev/null)
    hidden_pids=$(echo "$unhide_output" | grep -oP 'Found hidden pid: \K[0-9]+')
    
    if [ -n "$hidden_pids" ]; then
        echo "Found hidden processes, terminating them..."
        echo "$hidden_pids" | while read pid; do
            echo "Killing hidden PID $pid"
            kill -9 "$pid" 2>/dev/null || echo "Failed to kill hidden PID $pid"
        done
    fi
fi

# Alternative method to find disparities in process listings
ps_pids=$(ps -eo pid | grep -v PID)
proc_pids=$(find /proc -maxdepth 1 -regex '/proc/[0-9]+' | grep -o '[0-9]\+$')
for pid in $proc_pids; do
    if ! echo "$ps_pids" | grep -q "$pid"; then
        echo "Found potentially hidden process with PID $pid"
        kill -9 "$pid" 2>/dev/null || echo "Failed to kill potentially hidden PID $pid"
    fi
done

# Check for common rootkit modules
rootkit_patterns="kisni|suckit|rkit|adore|knark|modhide|ipsecs|hidemod|heroin|synapsis|volc|optic|ramen|lok|maru"
suspicious_modules=$(lsmod | grep -E "$rootkit_patterns" | awk '{print $1}')
if [ -n "$suspicious_modules" ]; then
    echo "Potentially malicious kernel modules detected:"
    echo "$suspicious_modules"
    echo "$suspicious_modules" | while read module; do
        echo "Attempting to unload malicious module $module"
        rmmod "$module" 2>/dev/null || echo "Failed to unload module $module"
    done
fi

# Prevent loading of new modules
if [ -w /proc/sys/kernel/modules_disabled ]; then
    echo 1 > /proc/sys/kernel/modules_disabled || echo "Failed to disable module loading"
fi

############################################################
# 8) Apply seccomp filters to prevent network monitoring
############################################################
echo "Applying seccomp filters to critical processes"

# Install necessary tools if not already present
if ! command -v systemd-run &> /dev/null; then
    echo "systemd-run not found, skipping seccomp filtering"
else
    # The systemd service already running should have seccomp filters applied
    # in its service configuration, but we can apply system-wide restrictions
    
    # Create a seccomp filter that restricts network monitoring syscalls
    if [ -d /etc/systemd/system.conf.d ]; then
        cat > /etc/systemd/system.conf.d/10-seccomp.conf << EOF
[Manager]
SystemCallFilter=~@debug @mount @raw-io bpf perf_event_open
EOF
        # Reload systemd configuration
        systemctl daemon-reload || echo "Failed to reload systemd configuration"
    else
        echo "Directory /etc/systemd/system.conf.d not found, skipping seccomp configuration"
    fi
fi

############################################################
# 9) Additional anti-sniffing measures
############################################################
echo "Setting up additional anti-sniffing measures"

# Create a tmpfs for sensitive files to avoid disk access
if ! mountpoint -q /tmp; then
    mount -t tmpfs tmpfs /tmp
fi

# Restrict /dev/mem and /dev/kmem access
if [ -f /dev/mem ]; then
    chmod 0000 /dev/mem || echo "Failed to restrict access to /dev/mem"
fi

if [ -f /dev/kmem ]; then
    chmod 0000 /dev/kmem || echo "Failed to restrict access to /dev/kmem"
fi

# Create a list of potentially dangerous capabilities and restrict them
if command -v capsh &> /dev/null; then
    for cap in cap_net_admin cap_net_raw cap_sys_admin cap_sys_ptrace cap_sys_module; do
        setcap -r $cap /usr/bin/* 2>/dev/null || true
        setcap -r $cap /usr/sbin/* 2>/dev/null || true
        setcap -r $cap /bin/* 2>/dev/null || true
        setcap -r $cap /sbin/* 2>/dev/null || true
    done
fi

############################################################
# 10) Detect and disable rootkits
############################################################
echo "Checking for common rootkits"

# Check for common rootkit files
rootkit_files=(
    "/dev/.."; "/bin/.login"; "/etc/rc.d/rc.local."; "/usr/man/man1/..."; "/usr/man/man1/..";
    "/usr/lib/.lib"; "/usr/bin/.x11"; "/var/lib/games/.pacman"; "/usr/include/..."
)

for file in "${rootkit_files[@]}"; do
    if [ -e "$file" ]; then
        echo "Suspicious rootkit file detected: $file"
        rm -rf "$file" 2>/dev/null || echo "Failed to remove $file"
    fi
done

# Check for common rootkit signatures in /proc
for proc_file in /proc/*/; do
    if grep -q "Ebury\|esdee\|/dev/xmx\|/dev/shm/ldcc" "$proc_file/maps" 2>/dev/null; then
        pid=$(basename "$proc_file")
        echo "Detected rootkit signature in PID $pid"
        kill -9 "$pid" 2>/dev/null || echo "Failed to kill rootkit process $pid"
    fi
done

echo "Lockdown completed successfully."

############################################################
# 11) Keep only session keys in authorized_keys file
############################################################
echo "Cleaning up authorized_keys file to keep only session keys."
if [ -f "$authorized_keys_path" ]; then
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    chown "$ssh_user:$ssh_user" "$TMPDIR"
    awk '/# START SESSION KEY/,/# END SESSION KEY/' "$authorized_keys_path" > "$TMPDIR/session_only"
    chown "$ssh_user:$ssh_user" "$TMPDIR/session_only"
    chmod 600 "$TMPDIR/session_only"
    mv "$TMPDIR/session_only" "$authorized_keys_path"
    chown -R "$ssh_user:$ssh_user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$authorized_keys_path"
fi

echo "Lockdown completed successfully."
