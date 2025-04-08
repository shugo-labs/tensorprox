#!/bin/bash

# Arguments
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

# --- Nuclear Firewall Flush ---
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

# --- Unlock root account and non-valiops users ---
echo "Unlocking root and non-valiops users."

# Unlock root account and set shell back to default
sudo passwd -u root || echo "Failed to unlock root account"
sudo usermod -s /bin/bash root || echo "Failed to restore bash shell for root"

# Unlock non-valiops users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    if [ "$user" != "valiops" ]; then
        echo "Unlocking user: $user"
        sudo passwd -u "$user" || echo "Failed to unlock $user"
        sudo usermod -s /bin/bash "$user" || echo "Failed to restore bash shell for $user"
    fi
done

# --- Restore authorized_keys ---
if [ -f $authorized_keys_bak ]; then
    sudo cp $authorized_keys_bak $authorized_keys_path
    sudo chmod 600 $authorized_keys_path
    rm -f $authorized_keys_bak
    echo "Authorized_keys restored from backup."
else
    echo "No backup file found; skipping authorized_keys restoration."
fi

# --- Restore sshd configuration ---
if [ -f /etc/ssh/sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config || echo "Failed to restore sshd_config"
    sudo systemctl restart sshd.service || echo "Failed to restart SSH service"
else
    echo "No backup for sshd_config found."
fi

echo "=== Revert completed for $ip ==="
