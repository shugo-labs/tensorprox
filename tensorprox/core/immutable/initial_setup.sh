#!/bin/bash

# Install missing packages
echo "Checking and installing missing packages..."
needed=("net-tools" "iptables-persistent" "psmisc" "python3" "python3-pip" "tcpdump" "jq" "ethtool")

# Update package list first
DEBIAN_FRONTEND=noninteractive apt-get update -qq

for pkg in "${needed[@]}"; do
    dpkg -s $pkg >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Package '$pkg' missing. Installing..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg -qq || echo "Failed to install package $pkg"
    fi
done

# Upgrade pip and install Python libraries quietly
pip3 install --upgrade pip --quiet
pip3 install faker scapy pycryptodome --quiet