#!/bin/bash
# Complete setup script for whitelist-agent configuration

# Check if username argument is provided
if [ -z "$1" ]; then
    echo "Error: Username argument required."
    echo "Usage: $0 <username>"
    exit 1
fi

restricted_user="$1"

# Exit on any error
set -e

echo "Starting setup process..."

# Main Task 1: Prepare the Environment
echo "Creating dedicated system user (if not exists)..."
if ! id -u $restricted_user &>/dev/null; then
    sudo useradd --system --shell /bin/bash --create-home $restricted_user || { echo "Failed to create user $restricted_user. Exiting."; exit 1; }
else
    echo "User $restricted_user already exists, skipping creation."
fi

echo "Creating SSH directory..."
sudo mkdir -p "/home/$restricted_user/.ssh"
sudo chown -R $restricted_user:$restricted_user "/home/$restricted_user/.ssh"
sudo chmod 700 "/home/$restricted_user/.ssh"

sudo touch "/home/$restricted_user/.ssh/authorized_keys"
sudo chown $restricted_user:$restricted_user "/home/$restricted_user/.ssh/authorized_keys"
sudo chmod 600 "/home/$restricted_user/.ssh/authorized_keys"

echo "Restricting password authentication..."
sudo passwd -l "$restricted_user" || echo "Password already locked or error occurred, continuing..."

# Check if SSH server is already installed and running
echo "Checking if SSH server is already installed..."
if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
    echo "SSH server is already running. Skipping installation."
else
    echo "Installing SSH server in non-interactive mode..."
    
    # Pre-configure openssh-server to avoid prompts
    sudo debconf-set-selections <<EOF
openssh-server openssh-server/permit-root-login boolean true
openssh-server openssh-server/password-authentication boolean true
EOF
    
    # Kill any stalled dpkg or apt processes
    sudo pkill -9 dpkg || true
    sudo pkill -9 apt || true
    
    # Wait for apt/dpkg locks to be released
    echo "Waiting for apt/dpkg locks to be released..."
    for i in {1..60}; do
        if ! sudo lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && ! sudo lsof /var/lib/apt/lists/lock >/dev/null 2>&1; then
            break
        fi
        echo "Waiting for locks to be released... ($i/60)"
        sleep 1
    done
    
    # Clean up and fix any interrupted installations
    sudo rm -f /var/lib/dpkg/lock-frontend
    sudo rm -f /var/lib/apt/lists/lock
    sudo dpkg --configure -a
    
    # Install OpenSSH with maximum non-interactive settings
    export DEBIAN_FRONTEND=noninteractive
    sudo -E apt-get update -qq
    sudo -E apt-get -o Dpkg::Options::="--force-confdef" \
                   -o Dpkg::Options::="--force-confold" \
                   -o Dpkg::Options::="--force-confnew" \
                   -y --allow-downgrades --allow-remove-essential --allow-change-held-packages \
                   install -qq openssh-server </dev/null >/dev/null 2>&1
    
    # Check if the installation was successful
    if ! systemctl is-active --quiet sshd && ! systemctl is-active --quiet ssh; then
        echo "SSH server installation may have failed. Attempting alternative method..."
        
        # Alternative installation method (bare minimum to get SSH working)
        sudo -E apt-get -qq install -y openssh-server --no-install-recommends </dev/null
        
        # Ensure configuration directory exists
        sudo mkdir -p /etc/ssh/sshd_config.d
    fi
fi

# Define the sudoers file name (use a fixed name for simplicity)
sudoers_file="/etc/sudoers.d/90-$restricted_user"

# Create the sudoers file with proper syntax
sudo bash -c "cat <<EOF > '$sudoers_file'
Defaults!/usr/local/bin/whitelist-agent !requiretty
$restricted_user ALL=(ALL) NOPASSWD: /usr/local/bin/whitelist-agent
EOF"

sudo chmod 440 $sudoers_file

# Main Task 2: Install and Configure the Whitelist Agent
echo "Creating audit log directory..."
sudo mkdir -p /var/log/whitelist-agent

echo "Writing the agent script..."
cat << 'EOF_BASE' | sudo tee /usr/local/bin/whitelist-agent
#!/usr/bin/env bash

EOF_BASE

# Append the user-specific allowed commands to the whitelist-agent script
cat << EOF_COMMANDS | sudo tee -a /usr/local/bin/whitelist-agent
# Define allowed commands directly in the script
declare -a ALLOWED_COMMANDS=(
    "/usr/bin/ssh"
    "/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/initial_setup.sh"
    "/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/challenge.sh"
    "/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/lockdown.sh"
    "/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/gre_setup.py"
    "/usr/bin/sha256sum /home/$restricted_user/tensorprox/tensorprox/core/immutable/traffic_generator.py"
    "/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/initial_setup.sh"
    "/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/challenge.sh"
    "/usr/bin/bash /home/$restricted_user/tensorprox/tensorprox/core/immutable/lockdown.sh"
    "/usr/bin/python3.10 /home/$restricted_user/tensorprox/tensorprox/core/immutable/gre_setup.py"
)
EOF_COMMANDS

# Append the rest of the script
cat << 'EOF_REST' | sudo tee -a /usr/local/bin/whitelist-agent

# Function to normalize path
normalize_path() {
    local path="$1"
    # Convert to absolute path and resolve symlinks
    if [[ -e "$path" ]]; then
        readlink -f "$path"
    else
        echo "$path"
    fi
}

is_command_allowed() {
    local full_cmd="$1"
    
    # Extract the base command and its arguments
    read -ra cmd_parts <<< "$full_cmd"

    # Extract main parts
    local base_cmd="${cmd_parts[0]}"   # bash or python3
    local script_path="${cmd_parts[1]}"  # The actual script being executed

    # Convert base command and paths to absolute form
    if command -v "$base_cmd" &> /dev/null; then
        base_cmd=$(command -v "$base_cmd")
    fi
    if [[ -f "$script_path" ]]; then
        script_path=$(realpath "$script_path")
    fi

    # Validate command against allowed commands array (ignoring additional arguments)
    for allowed_cmd in "${ALLOWED_COMMANDS[@]}"; do
        # Compare with base commands
        if [[ "$allowed_cmd" == "$base_cmd $script_path"* ]]; then
            return 0  # Allowed
        fi
    done

    return 1  # Not allowed
}

# Execute the command safely
execute_command() {
    local cmd="$1"

    # Execute the command with sudo
    sudo bash -c "$cmd"
    return $?
}

# The command passed by SSH will be the first argument to this script
cmd="$1"

# Check if a command was provided
if [[ -z "$cmd" ]]; then
    echo "No command provided."
    exit 1
fi

# Extract the base command and check if it exists
base_cmd=$(command -v ${cmd%% *} 2>/dev/null)
if [[ -z "$base_cmd" ]]; then
    echo "Command not found: ${cmd%% *}"
    exit 1
fi

# Normalize the base command path
base_cmd=$(normalize_path "$base_cmd")

# Replace base command with full path
if [[ "$cmd" == *" "* ]]; then
    full_cmd="$base_cmd ${cmd#* }"
else
    full_cmd="$base_cmd"
fi

# Check if command is allowed
if is_command_allowed "$full_cmd"; then
    execute_command "$full_cmd"
    exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        exit $exit_code
    else
        echo "Command '$full_cmd' executed with errors. Exit code: $exit_code"
        exit 1
    fi
else
    echo "Command '$full_cmd' not allowed."
    exit 1
fi
EOF_REST

echo "Writing the agent wrapper..."
cat << 'EOF' | sudo tee /usr/local/bin/whitelist-agent-wrapper
#!/bin/bash

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    /usr/local/bin/whitelist-agent "$SSH_ORIGINAL_COMMAND"
else
    /usr/local/bin/whitelist-agent
fi
EOF

echo "Setting proper permissions for the agent script..."
sudo chmod 755 /usr/local/bin/whitelist-agent
sudo chown root:root /usr/local/bin/whitelist-agent

sudo chmod 755 /usr/local/bin/whitelist-agent-wrapper
sudo chown root:root /usr/local/bin/whitelist-agent-wrapper

echo "Configuring SSH to use the agent..."
sudo mkdir -p /etc/ssh/sshd_config.d
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.conf << 'EOF'
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

echo "Creating active/inactive mode configurations..."
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.active.conf << 'EOF'
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.inactive.conf << 'EOF'
# No ForceCommand line, so the user gets a normal shell
EOF"

echo "Reloading SSH to apply changes..."
if systemctl list-unit-files | grep -q "ssh.service"; then
    sudo systemctl reload ssh || sudo systemctl restart ssh
elif systemctl list-unit-files | grep -q "sshd.service"; then
    sudo systemctl reload sshd || sudo systemctl restart sshd
else
    # Fallback for older Ubuntu versions
    sudo service ssh reload || sudo service ssh restart || 
    sudo service sshd reload || sudo service sshd restart ||
    echo "Could not reload SSH service, please restart it manually."
fi

echo "Setup complete!"
echo ""
echo "To activate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.active.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""
echo "To deactivate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.inactive.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""