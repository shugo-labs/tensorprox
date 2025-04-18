#!/bin/bash
# Lockdown script with automatic revert functionality
#
# Arguments:
#   ssh_user - The SSH username (e.g., 'user').
#   ssh_dir  - The SSH directory path (e.g., '/home/user/.ssh').
#   validator_ip - The IP address allowed for SSH access (e.g., '192.168.1.100').
#   authorized_keys_path - The path to the authorized_keys file (e.g., '/home/user/.ssh/authorized_keys').
#   revert_timeout - Time in seconds before automatic revert (default: 1500 seconds = 25 minutes).

# Set variables based on script arguments
ssh_user="$1"
ssh_dir="$2"
validator_ip="$3"
authorized_keys_path="$4"
revert_timeout="${5:-500}"  # Default to 1500 seconds (25 minutes) if not specified

if [ -z "$ssh_user" ] || [ -z "$ssh_dir" ] || [ -z "$validator_ip" ] || [ -z "$authorized_keys_path" ]; then
    echo "Missing required arguments. Usage: $0 <ssh_user> <ssh_dir> <validator_ip> <authorized_keys_path> [revert_timeout_seconds]"
    exit 1
fi

# Create a log directory if it doesn't exist
log_dir="/var/log/security"
mkdir -p "$log_dir"
lockdown_log="$log_dir/lockdown_$(date +%Y%m%d_%H%M%S).log"
revert_log="$log_dir/revert_$(date +%Y%m%d_%H%M%S).log"

# Create a backup of authorized_keys
authorized_keys_bak="/tmp/authorized_keys.bak.$(date +%s)"
cp "$authorized_keys_path" "$authorized_keys_bak"
chmod 600 "$authorized_keys_bak"

# Create a backup of sshd_config
if [ -f "/etc/ssh/sshd_config" ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    chmod 600 /etc/ssh/sshd_config.bak
fi

# Function to set up the revert script
setup_revert_script() {
    local revert_script="/tmp/revert_script_$(date +%s).sh"
    
    cat > "$revert_script" << 'REVERT_SCRIPT'
#!/bin/bash

# Arguments
ssh_user="$1"
ip="$2"
authorized_keys_bak="$3"
authorized_keys_path="$4"
revert_log="$5"

# Revert script for $ip
# Logging to $revert_log
exec > "$revert_log" 2>&1
echo "=== Revert started for $ip at $(date) ==="

# --- Restore critical services ---
systemctl unmask getty@tty1.service || echo "Failed to unmask getty@tty1"
systemctl enable getty@tty1.service || echo "Failed to enable getty@tty1"
systemctl start getty@tty1.service || echo "Failed to start getty@tty1"

systemctl unmask console-getty.service || echo "Failed to unmask console-getty"
systemctl enable console-getty.service || echo "Failed to enable console-getty"
systemctl start console-getty.service || echo "Failed to start console-getty"

systemctl unmask serial-getty@ttyS0.service || echo "Failed to unmask serial-getty@ttyS0"
systemctl enable serial-getty@ttyS0.service || echo "Failed to enable serial-getty@ttyS0"
systemctl start serial-getty@ttyS0.service || echo "Failed to start serial-getty@ttyS0"

systemctl unmask atd.service || echo "Failed to unmask atd"
systemctl enable atd.service || echo "Failed to enable atd"
systemctl restart atd.service || echo "Failed to restart atd"

# --- Nuclear Firewall Flush ---
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
cat <<EOF | iptables-restore
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF

# --- Unlock root account and non-valiops users ---
echo "Unlocking root and non-valiops users."

# Unlock root account and set shell back to default
passwd -u root || echo "Failed to unlock root account"
usermod -s /bin/bash root || echo "Failed to restore bash shell for root"

# Unlock non-valiops users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    if [ "$user" != "$ssh_user" ]; then
        echo "Unlocking user: $user"
        passwd -u "$user" || echo "Failed to unlock $user"
        usermod -s /bin/bash "$user" || echo "Failed to restore bash shell for $user"
    fi
done

# --- Restore authorized_keys ---
if [ -f "$authorized_keys_bak" ]; then
    cp "$authorized_keys_bak" "$authorized_keys_path"
    chmod 600 "$authorized_keys_path"
    rm -f "$authorized_keys_bak"
    echo "Authorized_keys restored from backup."
else
    echo "No backup file found; skipping authorized_keys restoration."
fi

# --- Restore sshd configuration ---
if [ -f /etc/ssh/sshd_config.bak ]; then
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config || echo "Failed to restore sshd_config"
    systemctl restart sshd.service || echo "Failed to restart SSH service"
else
    echo "No backup for sshd_config found."
fi

# --- Start any disabled essential services ---
for s in $(systemctl list-units --type=service --state=masked --no-pager --no-legend | awk '{print $1}'); do
    if [[ "$s" =~ ^(systemd-|dbus.|polkit.|rsyslog.|snapd.) ]]; then
        echo "Unmasking and starting essential service: $s"
        systemctl unmask "$s" || echo "Failed to unmask $s"
        systemctl start "$s" || echo "Failed to start $s"
    fi
done

echo "=== Revert completed for $ip at $(date) ==="
REVERT_SCRIPT

    chmod +x "$revert_script"
    echo "$revert_script"
}

# Function to schedule revert using systemd timer
schedule_revert_systemd() {
    local revert_script="$1"
    local timeout_seconds="$2"
    
    echo "Setting up auto-revert with systemd timer (will revert in $timeout_seconds seconds)"
    
    # Create a unique service name
    local service_name="autorevert-$(date +%s)"
    
    # Create systemd service
    cat > "/etc/systemd/system/${service_name}.service" << EOF
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

    # Create systemd timer
    cat > "/etc/systemd/system/${service_name}.timer" << EOF
[Unit]
Description=Timer for automatic revert of security lockdown

[Timer]
OnBootSec=60
OnActiveSec=${timeout_seconds}
Unit=${service_name}.service

[Install]
WantedBy=timers.target
EOF

    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable "${service_name}.timer"
    systemctl start "${service_name}.timer"
    
    echo "Systemd timer ${service_name}.timer created and started"
    echo "Automatic revert will occur in approximately $timeout_seconds seconds"
}

# Function to schedule revert using at command
schedule_revert_at() {
    local revert_script="$1"
    local timeout_seconds="$2"
    
    echo "Setting up auto-revert with at command (will revert in $timeout_seconds seconds)"
    
    # Make sure atd service is running
    systemctl start atd.service || echo "Failed to start atd service"
    
    # Schedule the revert script
    echo "$revert_script \"$ssh_user\" \"$validator_ip\" \"$authorized_keys_bak\" \"$authorized_keys_path\" \"$revert_log\"" | at now + "$timeout_seconds" seconds
    
    echo "Auto-revert scheduled with 'at' for $timeout_seconds seconds from now"
}

# Function to schedule revert using sleep command (fallback method)
schedule_revert_sleep() {
    local revert_script="$1"
    local timeout_seconds="$2"
    
    echo "Setting up auto-revert with sleep command (will revert in $timeout_seconds seconds)"
    
    # Create background process that will wait then execute revert
    nohup bash -c "sleep $timeout_seconds && $revert_script \"$ssh_user\" \"$validator_ip\" \"$authorized_keys_bak\" \"$authorized_keys_path\" \"$revert_log\"" > /dev/null 2>&1 &
    
    echo "Auto-revert scheduled with 'sleep' for $timeout_seconds seconds from now"
}

# Log the start of lockdown
exec > >(tee -a "$lockdown_log") 2>&1
echo "=== Lockdown started at $(date) ==="
echo "Auto-revert will be scheduled for $revert_timeout seconds"

# Setup the revert script first
revert_script=$(setup_revert_script)
echo "Revert script created at $revert_script"

# Try to schedule the revert using systemd timer first, fall back to at command, then to sleep
if command -v systemctl &> /dev/null; then
    schedule_revert_systemd "$revert_script" "$revert_timeout"
elif command -v at &> /dev/null; then
    schedule_revert_at "$revert_script" "$revert_timeout"
else
    echo "WARNING: Neither systemd nor at command available. Using sleep as fallback."
    schedule_revert_sleep "$revert_script" "$revert_timeout" 
fi

############################################################
# LOCKDOWN PROCEDURES START HERE
############################################################
echo "Starting lockdown procedures..."

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

# Allow UDP/TCP from overlay
iptables -A INPUT  -p tcp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
iptables -A INPUT  -p udp -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p udp -d 10.0.0.0/8 -j ACCEPT

# Block all public IP addresses for UDP/TCP
iptables -A INPUT -p tcp ! -s 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -p tcp ! -d 10.0.0.0/8 -j REJECT
iptables -A INPUT -p udp ! -s 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -p udp ! -d 10.0.0.0/8 -j REJECT

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
| grep -v "$revert_script" \
| grep -v at \
| grep -v sleep \
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

# Print information about the scheduled revert
echo ""
echo "=================================================================="
echo "LOCKDOWN COMPLETE - AUTO-REVERT SCHEDULED"
echo "=================================================================="
echo "The system will automatically revert in $revert_timeout seconds."
echo "Lockdown log: $lockdown_log"
echo "Revert log will be: $revert_log"
echo ""
echo "To manually cancel the auto-revert:"
if command -v systemctl &> /dev/null; then
    echo "  systemctl list-timers | grep autorevert"
    echo "  systemctl stop autorevert-*.timer"
    echo "  systemctl disable autorevert-*.timer"
elif command -v at &> /dev/null; then
    echo "  atq                  # List pending jobs"
    echo "  atrm <job_number>    # Remove the revert job"
else
    echo "  ps aux | grep sleep  # Find the sleep process"
    echo "  kill <pid>           # Kill the sleep process"
fi
echo "=================================================================="