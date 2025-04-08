#!/bin/bash

# Generates the revert script content to restore SSH and system configurations.
#
# Arguments:
#   ip (str): The IP address of the system being reverted.
#   authorized_keys_bak (str): The path to the backup authorized_keys file.
#   authorized_keys_path (str): The path to the authorized_keys file.
#   revert_log (str): The path to the revert log file.
#
# Returns:
#   str: The shell script for reverting security changes, including restoring services,
#        clearing firewall settings, restoring SSH configurations, and system settings.
#
# Usage:
#   ./revert_script.sh <ip> <authorized_keys_bak_path> <authorized_keys_path> <revert_log_path>
# Example:
#   ./revert_script.sh 192.168.1.100 /path/to/authorized_keys.bak /path/to/authorized_keys /path/to/revert.log

# Assign arguments to variables
ip="$1"
authorized_keys_bak="$2"
authorized_keys_path="$3"
revert_log="$4"

# Revert script for $ip
# Logging to $revert_log
exec > $revert_log 2>&1
echo "=== Revert started for $ip ==="

# --- Restore critical services ---
sudo systemctl unmask getty@tty1.service || echo "Failed to unmask getty@tty1"
sudo systemctl enable getty@tty1.service || echo "Failed to enable getty@tty1"
sudo systemctl start getty@tty1.service || echo "Failed to start getty@tty1"

sudo systemctl unmask console-getty.service || echo "Failed to unmask console-getty"
sudo systemctl enable console-getty.service || echo "Failed to enable console-getty"
sudo systemctl start console-getty.service || echo "Failed to start console-getty"

sudo systemctl unmask serial-getty@ttyS0.service || echo "Failed to unmask serial-getty@ttyS0"
sudo systemctl enable serial-getty@ttyS0.service || echo "Failed to enable serial-getty@ttyS0"
sudo systemctl start serial-getty@ttyS0.service || echo "Failed to start serial-getty@ttyS0"

sudo systemctl unmask atd.service || echo "Failed to unmask atd"
sudo systemctl enable atd.service || echo "Failed to enable atd"
sudo systemctl restart atd.service || echo "Failed to restart atd"

# --- Nuclear Firewall Flush: flush all tables ---
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t raw -F
sudo iptables -t raw -X
sudo iptables -t security -F
sudo iptables -t security -X
cat <<EOF | sudo iptables-restore
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF

# --- Restore authorized_keys ---
if [ -f $authorized_keys_bak ]; then
    sudo cp $authorized_keys_bak $authorized_keys_path
    sudo chmod 600 $authorized_keys_path
    rm -f $authorized_keys_bak
    echo "Authorized_keys restored from backup."
else
    sudo sed -i '/^# START SESSION KEY/,/^# END SESSION KEY/d' $authorized_keys_path || echo "Failed to remove session key block."
    echo "No backup file found; removed session key block."
fi

# --- Restore sshd configuration ---
if [ -f /etc/ssh/sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config || echo "Failed to restore sshd_config"
    sudo systemctl restart sshd.service || echo "Failed to restart SSH service"
else
    echo "No backup for sshd_config found."
fi

echo "=== Revert completed for $ip ==="
