from requests import get
from tensorprox import *
import tensorprox
import sys
import numpy as np
from datetime import datetime
import subprocess
import re
import logging
import os
import asyncio
import random
import time
import asyncssh
from typing import Tuple, Dict, Union, List
from loguru import logger
import string
import hashlib
import psutil
import ipaddress
import json
import pickle

def get_remaining_time(duration):
    current_time = time.time()
    next_event_time = ((current_time // duration) + 1) * duration
    remaining_time = next_event_time - current_time
    remaining_minutes = int(remaining_time // 60)
    remaining_seconds = int(remaining_time % 60)

    return f"{remaining_minutes}m {remaining_seconds}s"

def is_valid_ip(ip: str) -> bool:
    """
    Validates whether the given string is a valid IPv4 address.

    Args:
        ip (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """

    if not isinstance(ip, str):  # Check if ip is None or not a string
        return False
    pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?\d?\d?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?\d?\d?)$"
    return re.match(pattern, ip) is not None

def get_public_ip() -> str:
    """
    Retrieves the external machine's public IP address if available.
    Falls back to all IPs if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "0.0.0.0" if unavailable.
    """

    try:
        public_ip = get('https://api.ipify.org').text.strip()
        if is_valid_ip(public_ip):
            return public_ip
    except Exception:
        pass
    return "0.0.0.0"

def get_local_ip() -> str:
    """
    Retrieves the local machine's private IP address if available.
    Falls back to the default localhost IP if the public IP cannot be retrieved.

    Returns:
        str: The detected IP address, or "127.0.0.1" if unavailable.
    """

    try:
        local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        if is_valid_ip(local_ip):
            return local_ip
    except:
        pass
    return "127.0.0.1"


def get_subnet(interface):
    interfaces = psutil.net_if_addrs()
    if interface not in interfaces:
        return None  # Interface not found
    for addr in interfaces[interface]:
        if addr.family == 2:  # AF_INET (IPv4)
            ip_network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            return str(ip_network)
    return None  # No IPv4 address found

def generate_ips(num_ips=1000000, benign_percentage=0.1, excluded_ips=None, save_to="ips_data.pkl", seed=None):
    if excluded_ips is None:
        excluded_ips = [KING_OVERLAY_IP]

    # Use the provided seed or generate one
    if seed is None:
        seed = random.randint(0, 2**32 - 1)

    np.random.seed(seed)
    random.seed(seed)

    start = int(ipaddress.IPv4Address("10.0.0.0"))
    end = int(ipaddress.IPv4Address("10.255.255.255"))

    all_ips = np.arange(start, end + 1, dtype=np.uint32)

    excluded_set = set(int(ipaddress.IPv4Address(ip)) for ip in excluded_ips)
    allowed_ips = np.setdiff1d(all_ips, list(excluded_set), assume_unique=False)

    try:
        if len(allowed_ips) < num_ips:
            sampled_ips = allowed_ips
            num_ips = len(sampled_ips)
        else:
            sampled_ips = np.random.choice(allowed_ips, size=num_ips, replace=False)
    except Exception as e:
        sampled_ips = allowed_ips[:num_ips]
    
    ip_strs = [str(ipaddress.IPv4Address(int(ip))) for ip in sampled_ips]

    random.shuffle(ip_strs)
    benign_count = int(num_ips * benign_percentage)
    benign_ips = ip_strs[:benign_count]
    attack_ips = ip_strs[benign_count:]

    ip_data = {
        "benign": benign_ips,
        "attack": attack_ips,
        "seed": seed  # Include the seed in the returned data
    }

    if save_to is not None:
        with open(save_to, 'wb') as f:
            pickle.dump(ip_data, f)

    return ip_data

def load_ips_from_file(filename="ips_data.pkl"):
    try:
        if not os.path.exists(filename):
            # print(f"[load_ips_from_file] Warning: {filename} does not exist. Returning empty IP data.")
            return {"benign": [], "attack": [], "seed": 0}
        with open(filename, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        # print(f"[load_ips_from_file] Exception occurred while loading: {e}")
        return {"benign": [], "attack": [], "seed": 0}

def log_message(level: str, message: str):
    """
    Logs a message with the specified logging level.

    Args:
        level (str): The logging level (INFO, WARNING, ERROR, DEBUG).
        message (str): The message to log.
    """

    if level.upper() == "INFO":
        logging.info(message)
    elif level.upper() == "WARNING":
        logging.warning(message)
    elif level.upper() == "ERROR":
        logging.error(message)
    else:
        logging.debug(message)

def get_authorized_keys_dir(ssh_user: str) -> str:
    """
    Retrieves the correct .ssh directory path based on the SSH user.

    Args:
        ssh_user (str): The username of the SSH user.

    Returns:
        str: The absolute path to the .ssh directory.
    """

    return "/root/.ssh" if ssh_user == "root" else f"/home/{ssh_user}/.ssh"

def get_default_dir(ssh_user: str) -> str:
    """
    Retrieves the correct default directory path based on the SSH user.

    Args:
        ssh_user (str): The username of the SSH user.

    Returns:
        str: The absolute path to the default directory.
    """

    return "/root" if ssh_user == "root" else f"/home/{ssh_user}"


def create_session_key_dir(path = SESSION_KEY_DIR) :

    if not os.path.exists(path):
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
        except PermissionError as e:
            #log_message("ERROR", f"Permission denied while creating {SESSION_KEY_DIR}: {e}")
            raise
        except Exception as e:
            #log_message("ERROR", f"Unexpected error while creating {SESSION_KEY_DIR}: {e}")
            raise

# Define a helper function to generate file paths
def get_immutable_path(base_directory: str, filename: str) -> str:
    """
    Generates an absolute path by joining the base directory with the given relative path.

    Args:
        base_directory (str): The path of the the base directory.
        filename (str): The name of the file.

    Returns:
        str: The absolute path.
    """
    return os.path.join(base_directory, "tensorprox/core/immutable", filename)


def save_file_with_permissions(priv_key_str: str, path: str):
    """
    Saves a private SSH key to a specified file with secure permissions.

    Args:
        priv_key_str (str): The private key content.
        path (str): The file path where the private key should be stored.
    """

    try:
        with open(path, "w") as f:
            f.write(priv_key_str)
        os.chmod(path, 0o600)
        # log_message("INFO", f"Saved private key to {path}")
    except Exception as e:
        # log_message("ERROR", f"Error saving private key: {e}")
        pass

    
def get_attack_classes() -> Dict[str, list]:
    """Get all available attack classes.
    
    Returns:
        Dictionary mapping internal labels with the traffic vectors.
    """
    return {
        "BENIGN": ['udp_traffic', 'tcp_traffic'],

        "TCP_SYN_FLOOD": [
            'tcp_variable_window_syn_flood',
            'tcp_amplified_syn_flood_reflection',
            'tcp_async_slow_syn_flood',
            'tcp_batch_syn_flood',
            'tcp_randomized_syn_flood',
            'tcp_variable_ttl_syn_flood',
            'tcp_targeted_syn_flood_common_ports',
            'tcp_adaptive_flood',
            'tcp_batch_flood',
            'tcp_variable_syn_flood',
            'tcp_max_randomized_flood'
        ],

        "UDP_FLOOD": [
            'udp_malformed_packet',
            'udp_multi_protocol_amplification_attack',
            'udp_adaptive_payload_flood',
            'udp_compressed_encrypted_flood',
            'udp_max_randomized_flood',
            'udp_and_tcp_flood',
            'udp_single_ip_flood',
            'udp_ip_packet',
            'udp_reflection_attack',
            'udp_memcached_amplification_attack',
            'udp_hybrid_flood',
            'udp_dynamic_payload_flood',
            'udp_encrypted_payload_flood'
        ]
    }


def create_random_playlist(total_seconds, label_hashes, role=None, seed=None):
    """
    Create a random playlist totaling a specified duration with separate benign and attack playlists.
    
    The new structure provides:
    - A benign playlist that runs continuously for the full challenge duration with both TCP and UDP traffic in parallel
    - An attack playlist that contains intermittent attacks and pauses (60-180 seconds each) in alternating pattern
    
    Each traffic generator gets independent attack sequences while maintaining the same benign traffic structure.
    
    Args:
        total_seconds (int): The total duration of the playlist in seconds.
        label_hashes (dict): Dictionary of labels and corresponding lists of random hashes.
        role (str, optional): The role for the playlist ('attacker' or 'benign'). Defaults to None.
        seed (int, optional): The seed for the random number generator. If None, the seed is not set.

    Returns:
        dict: A dictionary containing 'benign_playlist' and 'attack_playlist' with their respective structures.
    """

    if seed is not None:
        random.seed(seed)

    type_class_map = get_attack_classes()
    attack_labels = [key for key in type_class_map.keys() if key != "BENIGN"]
    
    # Create the new playlist structure
    # Use the same label hash for both TCP and UDP benign traffic
    benign_hash = random.choice(label_hashes["BENIGN"])
    
    playlist = {
        "benign_playlist": {
            "name": "BENIGN",
            "duration": total_seconds,  # Full challenge duration
            "classes": [
                {
                    "class_vector": "tcp_traffic",
                    "label_identifier": benign_hash,  # Same hash for TCP
                    "duration": total_seconds  # Full duration for TCP
                },
                {
                    "class_vector": "udp_traffic", 
                    "label_identifier": benign_hash,  # Same hash for UDP
                    "duration": total_seconds  # Full duration for UDP
                }
            ]
        },
        "attack_playlist": []
    }
    
    # Generate attack playlist with alternating attacks and pauses
    # Each traffic generator will have different attack sequences due to different seeds
    current_time = 0
    
    # Start with either attack or pause (random choice)
    start_with_attack = random.choice([True, False])
    is_attack_turn = start_with_attack
    
    while current_time < total_seconds:
        if is_attack_turn:
            # Add attack
            attack_type = random.choice(attack_labels)
            class_vector = random.choice(type_class_map[attack_type])
            label_identifier = random.choice(label_hashes[attack_type])
            
            # Random duration between 60-180 seconds
            duration = min(random.randint(60, 180), total_seconds - current_time)
            
            if duration > 0:
                attack_entry = {
                    "name": attack_type,
                    "class_vector": class_vector,
                    "label_identifier": label_identifier,
                    "duration": duration
                }
                playlist["attack_playlist"].append(attack_entry)
                current_time += duration
            
            # Next will be pause
            is_attack_turn = False
        else:
            # Add pause
            pause_duration = min(random.randint(60, 180), total_seconds - current_time)
            if pause_duration > 0:
                pause_entry = {
                    "name": "pause",
                    "class_vector": None,
                    "label_identifier": None,
                    "duration": pause_duration
                }
                playlist["attack_playlist"].append(pause_entry)
                current_time += pause_duration
            
            # Next will be attack
            is_attack_turn = True

    return playlist

 
def generate_random_hashes(n=10, min_len=8, max_len=64):
    # Function to generate a random string of variable length
    def generate_random_string():
        length = random.randint(min_len, max_len)
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    # Create a dictionary to store the random strings for each label
    label_hashes = {
        "BENIGN": [],
        "TCP_SYN_FLOOD": [],
        "UDP_FLOOD": []
    }
    
    # Generate n random strings for each label
    for label in label_hashes:
        for _ in range(n):
            label_hashes[label].append(generate_random_string())
    
    return label_hashes

def create_pairs_to_verify(
    files_to_verify: List[str], 
    remote_base_directory: str,
    base_directory: str = BASE_DIR
) -> Tuple[str, List[Tuple[str, str]]]:
    
    paired_list = []
    for file in files_to_verify:
        local_path = get_immutable_path(base_directory, file)  # Use the passed base_directory
        remote_path = get_immutable_path(remote_base_directory, file)
        paired_list.append((local_path, remote_path))

    return paired_list

def get_local_sha256_hash(file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a local file.
    
    Args:
        file_path (str): Path to the local file.
        
    Returns:
        str: The SHA-256 hash of the local file.
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read the file in chunks
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

async def check_files_and_execute(ip: str, key_path: str, ssh_user: str, pair_files_list: List[Tuple[str, str]], cmd: str) -> Union[bool, object]:

    try:
        
        # Hash check disabled - files are trusted
        # for local_file, remote_file in pair_files_list:
        #     # Compare hashes
        #     if not await compare_file_hashes(ip, key_path, ssh_user, local_file, remote_file):
        #         return False
        
        # Run the script securely

        return await ssh_connect_execute(ip, key_path, ssh_user, cmd)
    
    except Exception as e:
        return False
    

async def get_remote_sha256_hash(ip: str, key_path: str, ssh_user: str, remote_file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a remote file using SSH.
    
    Args:
        ip (str): The IP address of the remote machine.
        key_path (str): Path to the private SSH key.
        ssh_user (str): The SSH user on the remote machine.
        remote_file_path (str): The path to the file on the remote machine.
        
    Returns:
        str: The SHA-256 hash of the remote file.
    """
    
    # SSH command to calculate SHA-256 of the remote file
    cmd = f"sha256sum {remote_file_path} | awk '{{print $1}}'"

    remote_hash = await ssh_connect_execute(ip, key_path, ssh_user, cmd)
    return remote_hash.stdout.strip()


async def compare_file_hashes(ip: str, key_path: str, ssh_user: str, local_file_path: str, remote_file_path: str) -> bool:
    """
    Compares the SHA-256 hashes of a local file and a remote file.
    
    Args:
        ip (str): The IP address of the remote machine.
        key_path (str): Path to the private SSH key.
        ssh_user (str): The SSH user on the remote machine.
        local_file_path (str): Path to the local file.
        remote_file_path (str): Path to the remote file.
        
    Returns:
        bool: True if the hashes match, False otherwise.
    """
    # Calculate the SHA-256 hash of the local file
    local_hash = get_local_sha256_hash(local_file_path)

    # Calculate the SHA-256 hash of the remote file
    remote_hash = await get_remote_sha256_hash(ip, key_path, ssh_user, remote_file_path)

    # Compare the two hashes
    return local_hash == remote_hash


async def generate_local_session_keypair(key_path: str) -> Tuple[str, str]:
    """
    Asynchronously generates an ED25519 SSH key pair and stores it securely.

    Args:
        key_path (str): The file path where the private key should be stored.

    Returns:
        Tuple[str, str]: A tuple containing the private and public keys as strings.
    """

    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(f"{key_path}.pub"):
        os.remove(f"{key_path}.pub")
    
    # log_message("INFO", "🚀 Generating session ED25519 keypair...")
    proc = await asyncio.create_subprocess_exec(
        "ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await proc.communicate()  # Wait for completion

    os.chmod(key_path, 0o600)
    if os.path.exists(f"{key_path}.pub"):
        os.chmod(f"{key_path}.pub", 0o644)
    
    with open(key_path, "r") as fk:
        priv = fk.read().strip()
    with open(f"{key_path}.pub", "r") as fpk:
        pub = fpk.read().strip()
    
    # log_message("INFO", "✅ Session keypair generated and secured.")
    return priv, pub

async def make_file_immutable(ip, key_path, ssh_user, remote_file_path, state=True):
    immutable_flag = "+i" if state == True else "-i"
    immutable_cmd = f"sudo chattr {immutable_flag} {remote_file_path}"
    await ssh_connect_execute(ip, key_path, ssh_user, immutable_cmd)

# Function to verify the remote file's signature
async def verify_remote_signature(ip, key_path, ssh_user, remote_signature_path, remote_file_path):
    verify_cmd = f"gpg --verify --trust-model always {remote_signature_path} {remote_file_path}"
    result = await ssh_connect_execute(ip, key_path, ssh_user, verify_cmd)
    return result
    
async def send_file_via_scp(local_file, remote_path, remote_ip, remote_key_path, remote_user):
    # Construct the SCP command
    scp_command = [
        'scp',
        '-i', remote_key_path,  # Specify the SSH private key
        '-o', 'StrictHostKeyChecking=no',  # Disable host key verification
        '-o', 'UserKnownHostsFile=/dev/null',  # Don't store the host key
        local_file,  # Local file to transfer
        f'{remote_user}@{remote_ip}:{remote_path}'  # Remote destination
    ]

    try:
        # Run the SCP command asynchronously using asyncio.subprocess
        process = await asyncio.create_subprocess_exec(*scp_command)

        # Wait for the SCP process to complete
        await process.wait()

        if process.returncode == 0:
            print(f"File {local_file} successfully sent to {remote_ip}:{remote_path}")
        else:
            print(f"SCP failed with return code {process.returncode}")

    except Exception as e:
        print(f"Error: {e}")


async def ssh_connect_execute(
    ip: str, 
    private_key_path: str, 
    username: str, 
    cmd: Union[str, list] = None,
    connection_timeout: float = 10.0  # Default timeout in seconds
) -> Union[bool, object]:
    """
    Establishes an SSH connection with timeout, optionally executes a command, and closes the connection.

    Args:
        ip (str): The target machine's IP address.
        private_key_path (str): The path to the private key used for authentication.
        username (str): The SSH user to authenticate as.
        cmd (Union[str, list], optional): The command to execute.
        connection_timeout (float, optional): Connection timeout in seconds. Default is 10.0.

    Returns:
        Union[bool, object]: 
            - If no command is provided, returns True if the connection is successful, False otherwise.
            - If a command is provided, returns the result.
    """
    try:
        #DELETE FOR PRODUCTION!
        # logger.debug(f"Attempting SSH connection to {ip} (user: {username}, key: {private_key_path}, timeout: {connection_timeout}s)")
        
        # Use wait_for with a timeout instead of the context manager
        connect_task = asyncssh.connect(
            ip, 
            username=username, 
            client_keys=[private_key_path], 
            known_hosts=None
        )
        
        client = await asyncio.wait_for(connect_task, timeout=connection_timeout)
        #DELETE FOR PRODUCTION!
        # logger.debug(f"SSH connection established successfully to {ip}")
        
        try:
            if cmd:
                try:
                    # Run the command and capture the result
                    result = await client.run(cmd, check=False, stderr=asyncssh.PIPE)
                    return result
                except asyncio.TimeoutError:
                    logger.error(f"SSH command execution timed out after {connection_timeout} seconds to {ip}")
                    return False
                except Exception as e:
                    logger.error(f"SSH command execution failed to {ip}: {e}, stderr: {getattr(e, 'stderr', 'N/A')}")
                    return False  # Command execution failed
            
            # If no command is provided, return True for successful connection
            return True
        finally:
            client.close()
            
    except asyncio.TimeoutError:
        logger.error(f"SSH connection timed out after {connection_timeout} seconds to {ip} (user: {username})")
        return False
    except asyncssh.Error as e:
        # Connection failed, log the error
        logger.error(f"SSH connection failed to {ip} (user: {username}): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during SSH connection to {ip} (user: {username}): {e}")
        return False