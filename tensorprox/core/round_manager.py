"""
================================================================================
TensorProx Miner Availability and SSH Session Setup

This script provides functionalities for managing miner availability, handling
SSH session setup, and automating firewall rule adjustments for Bittensor miners.
It utilizes asyncssh for efficient asynchronous SSH connections and ensures 
secure access control through key management.

--------------------------------------------------------------------------------
FEATURES:
- **Logging & Debugging:** Provides structured logging via Loguru and Python's 
  built-in logging module.
- **SSH Session Management:** Supports key-based authentication, session key 
  generation, and automated secure key insertion.
- **Firewall & System Utilities:** Ensures miners have necessary dependencies 
  installed, configures firewall rules, and manages sudo privileges.
- **Miner Availability Tracking:** Maintains a live status of miners' readiness 
  using the PingSynapse protocol.
- **Resilient Command Execution:** Executes commands safely with error handling 
  to prevent system lockouts.
- **Asynchronous Execution:** Uses asyncio and asyncssh for efficient remote 
  command execution and key management.

--------------------------------------------------------------------------------
USAGE:
1. **Miner Availability Tracking**  
   The `MinerManagement` class tracks the status of miners via the 
   `PingSynapse` protocol.
   
2. **SSH Session Key Management**  
   - Generates an ED25519 session key pair.
   - Inserts the session key into the authorized_keys file of remote miners.
   - Establishes an SSH session using the generated key.
   - Automates firewall and system setup tasks.

3. **Remote Configuration Management**  
   - Installs missing packages required for network security.
   - Ensures `iptables` and other network security tools are available.
   - Configures passwordless sudo execution where necessary.

--------------------------------------------------------------------------------
DEPENDENCIES:
- Python 3.10
- `asyncssh`: For managing SSH connections asynchronously.
- `paramiko`: Fallback for SSH key handling.
- `pydantic`: For structured data validation.
- `loguru`: Advanced logging capabilities.

--------------------------------------------------------------------------------
SECURITY CONSIDERATIONS:
- The script enforces strict permissions on session keys.
- Firewall configurations and sudo privileges are managed carefully.
- SSH keys are handled securely to prevent exposure.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to use, share, and modify the code for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating within the TensorProx subnet.
For any other commercial licensing requests, please contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

#!/usr/bin/env python3
import asyncio
import os
import json
import random
from tensorprox import *
from typing import List, Dict, Tuple, Union, Callable, Optional
from loguru import logger
from pydantic import BaseModel
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse
from tensorprox.utils.utils import *
from tensorprox.settings import settings
from tensorprox.base.protocol import MachineConfig
import dotenv
import logging
from functools import partial
import shlex
import traceback
import aiohttp
import socket
from tensorprox.core.apis.azure_api import (
    get_azure_access_token,
    retrieve_vm_infrastructure, 
    provision_azure_vms_for_uid,
    clear_vms
)

######################################################################
# LOGGING and ENVIRONMENT SETUP
######################################################################

dotenv.load_dotenv()

# Disable all asyncssh logging by setting its level to CRITICAL
asyncssh_logger = logging.getLogger('asyncssh')
asyncssh_logger.setLevel(logging.CRITICAL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

create_session_key_dir()

BATCH_SIZE = 10
BATCH_DELAY = 2

######################################################################
# CLASS ROUND MANAGER
######################################################################

class RoundManager(BaseModel):
    """
    Tracks the availability of miners using the PingSynapse protocol.
    
    Attributes:
        miners (Dict[int, PingSynapse]): A dictionary mapping miner UIDs to their availability status.
        ip (str): The local IP address of the machine running this instance.
    """

    miners: Dict[int, 'PingSynapse'] = {}
    validator_ip: str = get_public_ip()
    king_ips: Dict[int, str] = {}
    moat_private_ips: Dict[int, str] = {}
    king_details: Dict[int, dict] = {}
    traffic_generator_details: Dict[int, List[dict]] = {}

    def check_machine_availability(self, machine_name: str = None, uid: int = None) -> bool:
        """
        Checks whether a specific miner machine is available.

        Args:
            machine_name (str, optional): The machine name to check. Defaults to None.
            uid (int, optional): The UID of the miner. Defaults to None.

        Returns:
            bool: True if the machine is available, False otherwise.
        """

        ip_machine = self.miners[uid].machine_availabilities[machine_name]
        return bool(ip_machine)


    def is_miner_ready(self, uid: int = None) -> bool:
        """
        Checks if a miner is fully ready by verifying all associated machines.

        Args:
            uid (int, optional): The UID of the miner. Defaults to None.

        Returns:
            bool: True if all machines are available, False otherwise.
        """

        for machine_name in self.miners[uid].machine_availabilities.keys():
            if not self.check_machine_availability(machine_name=machine_name, uid=uid):
                return False
        return True
    

    def get_uid_status_availability(self, k: int = None) -> List[int]:
        """
        Retrieves a list of available miners.

        Args:
            k (int, optional): The number of available miners to return. Defaults to None.

        Returns:
            List[int]: A list of UIDs of available miners.
        """

        available = [uid for uid in self.miners.keys() if self.is_miner_ready(uid)]
        if k:
            available = random.sample(available, min(len(available), k))

        return available


    async def run(self, ip: str, ssh_user: str, key_path: str, args: list, files_to_verify: list, remote_base_directory: str) -> Union[bool, object]:
        """
        Performs a single-pass SSH session setup on a remote miner. This includes generating session keys,
        configuring passwordless sudo, installing necessary packages, and executing user-defined commands.

        Args:
            ip (str): The IP address of the miner to set up.
            ssh_user (str): The SSH user account on the miner.
            key_path (str): Path to the original SSH key used for initial access.
            paired_list (List[str]): List of paired items (purpose unclear from the context, needs adaptation).
        Returns:
            bool: True if the setup was successful, False if an error occurred.
        """

        paired_list = create_pairs_to_verify(files_to_verify, remote_base_directory)

        cmd = ' '.join(shlex.quote(arg) for arg in args)
        
        # logger.debug(f"Executing command on {ip}: {cmd[:100]}...") #DELETE FOR PRODUCTION!
        # logger.debug(f"Full command: {cmd}") #DELETE FOR PRODUCTION!
        
        result = await check_files_and_execute(ip, key_path, ssh_user, paired_list, cmd)
        
        # if hasattr(result, 'stdout'): #DELETE FOR PRODUCTION!
        #     logger.debug(f"Command stdout from {ip}: {result.stdout[:200] if result.stdout else 'empty'}") #DELETE FOR PRODUCTION!
        # if hasattr(result, 'stderr') and result.stderr: #DELETE FOR PRODUCTION!
        #     logger.debug(f"Command stderr from {ip}: {result.stderr[:200]}") #DELETE FOR PRODUCTION!
        
        return result
    

    async def extract_metrics(self, result: str, machine_name: str, label_hashes: dict) -> tuple:
        """
        Extracts label counts and average RTT (Round Trip Time) from the result output.

        This method processes the result string, which contains various metrics, and extracts the label counts
        and average RTT value. It then returns the parsed data along with the machine name.

        Args:
            result (str): The result string that contains the metric values (including label counts and RTT).
            machine_name (str): The name of the machine from which the metrics were collected.
            label_hashes (dict): A dictionary containing label hashes, which are used to match the labels in the result.

        Returns:
            tuple: A tuple containing:
                - `machine_name` (str): The name of the machine from the argument.
                - `label_counts` (dict): A dictionary with label names as keys and their corresponding counts as values.
                - `rtt_avg` (float or None): The average RTT value parsed from the result, or None if not found or invalid.
        
        If any errors occur during parsing (e.g., invalid result format or failed conversions), the method logs a warning
        and skips the invalid entries. In case of a general failure, the method logs the error and returns `None`.
        """

        try:

            # Parse the result to get the counts from stdout
            counts_and_rtt = result.stdout.strip().split(", ")

            # Initialize a dictionary to store counts using a for loop
            label_counts = {label: 0 for label in label_hashes.keys()}

            rtt_avg = None

            # Parse each label count from the result string
            for count in counts_and_rtt:
                
                if "AVG_RTT" in count:
                    extracted_rtt = count.split(":", maxsplit=1)[1].strip()
                    
                    # Check if extracted_rtt is a valid float before converting
                    try:
                        rtt_avg = float(extracted_rtt)
                    except ValueError:
                        logger.warning(f"Invalid RTT value: {extracted_rtt}")
                else:
                    try:
                        label, value = count.split(":", maxsplit=1)
                        value = value.strip()
                        
                        if label in label_counts:
                            label_counts[label] = int(value)  # Convert only if valid
                        
                    except ValueError:
                        logger.warning(f"Invalid label count entry: {count}")  # Log and skip invalid entries


            return machine_name, label_counts, rtt_avg

        except Exception as e:
            logger.error(f"Error occurred: {e}")
            return None

    
    async def query_availability(self, uid: int) -> Tuple['PingSynapse', Dict[str, Union[int, str]]]:
        """Query the availability of a given UID.
        
        This function attempts to retrieve machine availability information for a miner
        identified by `uid`. It validates the response, checks for SSH key pairs, and 
        verifies SSH connectivity to each machine.
        
        Args:
            uid (int): The unique identifier of the miner.

        Returns:
            Tuple[PingSynapse, Dict[str, Union[int, str]]]:
                - A `PingSynapse` object containing the miner's availability details.
                - A dictionary with the UID's availability status, including status code and message.
        """

        # Initialize a dummy synapse
        synapse = PingSynapse(machine_availabilities=MachineConfig())
        uid, synapse = await self.dendrite_call(uid, synapse)
        
        uid_status_availability = {"uid": uid, "ping_status_message" : None, "ping_status_code" : None}

        if synapse is None:
            uid_status_availability["ping_status_message"] = "Query failed."
            uid_status_availability["ping_status_code"] = 500
            return synapse, uid_status_availability

        # Extract provider from synapse
        provider = synapse.machine_availabilities.provider
                
        # Generate session key pair
        session_key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}")
        _, public_key = await generate_local_session_keypair(session_key_path)
        
        # Initialize variables
        king_machine = None
        traffic_generators = None
        moat_ip = None
        
        # Route based on provider
        if provider == "AZURE":
            # Translate generic fields to Azure-specific
            credentials = {}
            credentials["AZURE_CLIENT_ID"] = synapse.machine_availabilities.auth_id
            credentials["AZURE_CLIENT_SECRET"] = synapse.machine_availabilities.auth_secret
            credentials["AZURE_TENANT_ID"] = synapse.machine_availabilities.project_id
            credentials["AZURE_RESOURCE_GROUP"] = synapse.machine_availabilities.resource_group
            # Extract subscription ID from resource group path
            if synapse.machine_availabilities.resource_group and "/" in synapse.machine_availabilities.resource_group:
                credentials["AZURE_SUBSCRIPTION_ID"] = synapse.machine_availabilities.resource_group.split("/")[2]
            else:
                credentials["AZURE_SUBSCRIPTION_ID"] = None
            
            machine_config = {
                'app_credentials': credentials,
                'location': synapse.machine_availabilities.region,
                'num_tgens': synapse.machine_availabilities.num_tgens,
                'tgens_size': synapse.machine_availabilities.vm_size_small,
                'king_size': synapse.machine_availabilities.vm_size_large
            }
            
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 session key generated, getting Azure token...")
            token = await get_azure_access_token(credentials)
            
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 validating infrastructure...")
            subnet_id, nsg_id = await retrieve_vm_infrastructure(
                token, 
                credentials["AZURE_SUBSCRIPTION_ID"], 
                credentials["AZURE_RESOURCE_GROUP"], 
                synapse.machine_availabilities.region, 
                uid, 
                synapse.machine_availabilities.vpc_name, 
                synapse.machine_availabilities.subnet_name
            )
            
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 provisioning VMs...")
            king_machine, traffic_generators, moat_ip = await provision_azure_vms_for_uid(
                uid, 
                machine_config, 
                public_key, 
                subnet_id, 
                nsg_id
            )
        elif provider == "GCP":
            # Import GCP-specific functions
            from tensorprox.core.apis.gcp_api import (
                get_gcp_access_token,
                retrieve_vm_infrastructure as gcp_retrieve_infrastructure,
                provision_gcp_vms_for_uid,
                translate_config
            )
            
            # Pass full generic config to GCP API
            machine_config = synapse.machine_availabilities.dict()
            
            # Get GCP access token
            token = await get_gcp_access_token(machine_config)
            
            # GCP API will handle translation internally
            gcp_config = translate_config(machine_config)
            project_id = gcp_config["GCP_PROJECT_ID"]
            zone = machine_config["region"]
            vpc_name = machine_config["vpc_name"]
            subnet_name = machine_config["subnet_name"]
            
            # Retrieve infrastructure (miners provide subnets with firewall rules)
            subnet_link = await gcp_retrieve_infrastructure(
                token,
                project_id,
                zone,
                uid,
                vpc_name,
                subnet_name
            )
            
            # Provision VMs with custom specs if provided
            king_machine, traffic_generators, moat_ip = await provision_gcp_vms_for_uid(
                uid,
                machine_config,
                public_key,
                subnet_link
            )
        elif provider == "AWS":
            try:
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.info(f"Processing AWS provider for UID {uid}")
                # Import AWS-specific functions
                from tensorprox.core.apis.aws_api import (
                    get_aws_session,
                    retrieve_vm_infrastructure as aws_retrieve_infrastructure,
                    provision_aws_vms_for_uid
                )
                
                # Pass full generic config to AWS API
                machine_config = synapse.machine_availabilities.dict()
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.debug(f"AWS machine_config for UID {uid}: {machine_config}")
                
                # Get AWS session and signer
                session, signer = await get_aws_session(machine_config)
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.debug(f"AWS session created for UID {uid}")
                
                # Retrieve infrastructure
                subnet_id, vpc_id = await aws_retrieve_infrastructure(
                    session,
                    signer,
                    machine_config,
                    uid
                )
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.info(f"AWS infrastructure retrieved for UID {uid}: subnet={subnet_id}, vpc={vpc_id}")
                
                # Provision VMs with custom specs if provided
                king_machine, traffic_generators, moat_ip = await provision_aws_vms_for_uid(
                    uid,
                    machine_config,
                    public_key,
                    subnet_id,
                    vpc_id
                )
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.info(f"AWS VMs provisioned for UID {uid}: king={king_machine}, tgens={len(traffic_generators) if traffic_generators else 0}")
            except Exception as e:
                #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.error(f"AWS provisioning failed for UID {uid}: {str(e)}")
                #     import traceback
                #     logger.error(f"Full traceback: {traceback.format_exc()}")
                uid_status_availability["ping_status_message"] = f"AWS provisioning failed: {str(e)}"
                uid_status_availability["ping_status_code"] = 500
                return synapse, uid_status_availability
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        # Provider-specific VM readiness handling
        if provider == "AZURE":
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 Azure VMs provisioned, waiting for VM readiness...")
            
            # Azure still uses static wait (can be improved later)
            await asyncio.sleep(90)
            
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 Azure VM readiness wait complete, starting SSH tests...")
        elif provider == "GCP":
            # GCP handles readiness polling internally in provision_gcp_vms_for_uid
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 GCP VMs ready, starting SSH tests...")
            pass
        elif provider == "AWS":
            # AWS handles readiness polling internally in provision_aws_vms_for_uid
            pass
        # logger.info(f"Response: king_machine={king_machine}, traffic_generators={traffic_generators}, moat_private_ip={moat_ip}")

        all_machines_available = True

        # Create a list containing all machines to check - king and all traffic generators
        machines_to_check = [king_machine]+traffic_generators
        
        # Check all machines
        for machine_details in machines_to_check:

            ip = machine_details['ip']
            ssh_user = machine_details['username']

            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 testing SSH to {ip} with user {ssh_user}...")

            if not is_valid_ip(ip):
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "Invalid IP format."
                uid_status_availability["ping_status_code"] = 400
                # #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.error(f"UID 9 invalid IP: {ip}")
                logger.error(f"UID {uid} SSH validation failed - Invalid IP format: {ip}")
                break

            # Test SSH Connection with asyncssh
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 starting SSH connection test to {ip}...")
            
            client = await ssh_connect_execute(ip, session_key_path, ssh_user)

            if not client:
                all_machines_available = False
                uid_status_availability["ping_status_message"] = "SSH connection failed."
                uid_status_availability["ping_status_code"] = 500
                # #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.error(f"UID 9 SSH failed to {ip}")
                logger.error(f"UID {uid} SSH validation failed - Connection to {ip} with user {ssh_user} failed (key: {session_key_path})")
                break
            else:
                # #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.info(f"UID 9 SSH connection successful to {ip}")
                # logger.info(f"UID {uid} SSH connection successful to {ip} with user {ssh_user}")
                pass

        if all_machines_available:
            uid_status_availability["ping_status_message"] = f"✅ All machines are accessible for UID {uid}."
            uid_status_availability["ping_status_code"] = 200
            # Store machine details for later use in execute_task
            self.king_details[uid] = king_machine
            self.traffic_generator_details[uid] = traffic_generators
            self.moat_private_ips[uid] = moat_ip
            # #DELETE FOR PRODUCTION!
            # if uid == 9:
            #     logger.info(f"UID 9 SUCCESS: All machines accessible!")
        
        # #DELETE FOR PRODUCTION!
        # if uid == 9:
        #     logger.info(f"UID 9 FINAL RETURN: all_machines_available={all_machines_available}, status={uid_status_availability}")

        return synapse, uid_status_availability


    async def dendrite_call(self, uid: int, synapse: Union[PingSynapse, ChallengeSynapse], timeout: int = settings.NEURON_TIMEOUT):
        """
        Query a single miner's availability.
            
        Args:
            uid (int): Unique identifier for the miner.
            synapse (Union[PingSynapse, ChallengeSynapse]): The synapse message to send.
            timeout (int, optional): Timeout duration in seconds. Defaults to settings.NEURON_TIMEOUT.
        
        Returns:
            Tuple[int, Optional[Response]]: The miner's UID and response, if available.
        """

        try:

            # Check if the uid is within the valid range for the axons list
            if uid < len(settings.METAGRAPH.axons):
                axon = settings.METAGRAPH.axons[uid]
            else:
                return uid, PingSynapse()
        
            response = await settings.DENDRITE(
                axons=[axon],
                synapse=synapse,
                timeout=timeout,
                deserialize=False,
            )

            return uid, response[0] if response else PingSynapse()

        except Exception as e:
            logger.error(f"❌ Failed to query miner {uid}: {e}\n{traceback.format_exc()}")
            return uid, PingSynapse()
            

    async def clone_tensorprox_immutable(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        repo_url: str = "https://github.com/shugo-labs/tensorprox.git",
        branch: str = "main",
        sparse_folder: str = "tensorprox/core/immutable",
        timeout: int = 120
    ) -> bool:
        """Clone the immutable folder to validator-provisioned machines.
        
        The target path is context-sensitive:
        - root user: /root/tensorprox
        - other users: /home/{ssh_user}/tensorprox
        
        Args:
            ip (str): IP address of the remote machine
            ssh_user (str): SSH username
            key_path (str): Path to SSH key
            repo_url (str): Repository URL to clone from
            branch (str): Branch to checkout
            sparse_folder (str): Sparse checkout folder path
            timeout (int): SSH connection timeout
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Determine target path based on user
            default_dir = get_default_dir(ssh_user=ssh_user)
            target_path = os.path.join(default_dir, "tensorprox")
            
            commands = [
                # Install git if needed
                "which git || (sudo apt-get update && sudo apt-get install -y git)",
                
                # Remove existing directory and create fresh
                f"sudo rm -rf {target_path}",
                f"sudo mkdir -p {target_path}",
                f"sudo chown {ssh_user}:{ssh_user} {target_path}",
                
                # Initialize sparse checkout
                f"cd {target_path} && git init",
                f"cd {target_path} && git config core.sparseCheckout true",
                f"cd {target_path} && echo '{sparse_folder}/*' > .git/info/sparse-checkout",
                f"cd {target_path} && git remote add origin {repo_url}",
                f"cd {target_path} && git fetch origin {branch}",
                f"cd {target_path} && git checkout {branch}"
            ]
            
            # Execute commands via SSH
            result = await ssh_connect_execute(
                ip=ip,
                private_key_path=key_path,
                username=ssh_user,
                cmd=" && ".join(commands),
                connection_timeout=timeout
            )
            
            if result is False:
                # logging.error(f"SSH connection failed during clone for {ip}") #DELETE FOR PRODUCTION!
                return False
                
            if hasattr(result, 'returncode') and result.returncode != 0:
                # logging.error(f"Git clone commands failed on {ip}: exit code {result.returncode}") #DELETE FOR PRODUCTION!
                # if hasattr(result, 'stderr'):
                #     logging.error(f"Git clone stderr: {result.stderr}") #DELETE FOR PRODUCTION!
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to clone repository on {ip}: {e}")
            return False

    async def process_initial_setup(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        uid: int,
        script_name: str = "initial_setup.sh",
        linked_files: list = []
    ) -> bool:
        """
        Performs the initial setup process on validator-controlled machines.

        This method first clones the tensorprox immutable repository, then runs
        the package installation script.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            uid (int): The miner UID for logging purposes.
            script_name (str, optional): The name of the script to execute (default is "initial_setup.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if both cloning and setup were successful, otherwise `False`.
        """

        # First, clone the repository
        clone_success = await self.clone_tensorprox_immutable(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path
        )
        if not clone_success:
            logging.error(f"Failed to clone repository for miner {uid} on {ip}")
            return False

        # Then run the package installation script
        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files
        
        args = ['sudo', '/usr/bin/bash', remote_script_path]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    
    async def process_gre_setup(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        machine_type: str,
        index: str,
        moat_private_ip: str,
        private_ip: str,
        interface: str,
        script_name: str = "gre_setup.py",
        linked_files: list = []
    ) -> bool:
        """
        Sets up the GRE tunnel on the remote server.

        This method prepares the arguments for running the GRE setup script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            machine_name (str): The name of the machine for the GRE setup.
            moat_private_ip (str): The private IP address of the Moat machine.
            script_name (str, optional): The name of the script to execute (default is "gre_setup.py").
            linked_files (list, optional): List of linked files to verify along with the script (default is an empty list).

        Returns:
            bool: Returns `True` if the GRE setup process was successful, otherwise `False`.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        files_to_verify = [script_name] + linked_files

        args = [
            '/usr/bin/python3.10', 
            remote_script_path,
            machine_type, 
            moat_private_ip,
            private_ip,
            interface,
            str(index)  # Ensure index is string for command line
        ]

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )
    
    async def process_challenge(
        self,
        ip: str,
        ssh_user: str,
        key_path: str,
        remote_base_directory: str,
        machine_name: str,
        challenge_duration: int,
        label_hashes: Dict[str, list],
        playlists: dict,
        script_name: str = "challenge.sh",
        linked_files: list = ["traffic_generator.py"]
    ) -> tuple:
        """
        Runs the challenge script on the remote server.

        This method prepares the arguments for running the challenge script and calls the `run` method
        to execute it on the remote server.

        Args:
            ip (str): The IP address of the remote server.
            ssh_user (str): The SSH username to access the server.
            key_path (str): The path to the SSH private key for authentication.
            remote_base_directory (str): The base directory on the remote server.
            machine_name (str): The name of the machine running the challenge.
            challenge_duration (int): The duration of the challenge in seconds.
            label_hashes (Dict[str, list]): A dictionary mapping labels to their corresponding hash values.
            playlists (dict): A dictionary containing playlists for each machine or the new structure with benign_playlist and attack_playlist.
            script_name (str, optional): The name of the script to execute (default is "challenge.sh").
            linked_files (list, optional): List of linked files to verify along with the script (default includes "traffic_generator.py" and "tcp_server.py").

        Returns:
            tuple: The result of the challenge execution.
        """

        remote_script_path = get_immutable_path(remote_base_directory, script_name)
        remote_traffic_gen = get_immutable_path(remote_base_directory, "traffic_generator.py")
        files_to_verify = [script_name] + linked_files

        # Handle playlist structure
        if machine_name == "king":
            playlist = "null"
        else:
            # Use the new playlist structure - each machine gets its own complete playlist
            playlist = json.dumps(playlists[machine_name]) if machine_name in playlists else "null"

        label_hashes = json.dumps(label_hashes)
        
        # logger.debug(f"Preparing challenge for {machine_name}: script={remote_script_path}, playlist={'provided' if machine_name != 'king' else 'null'}") #DELETE FOR PRODUCTION!
        
        args = [
            "/usr/bin/bash",
            remote_script_path,
            machine_name,
            str(challenge_duration),
            str(label_hashes),  
            str(playlist),    
            KING_OVERLAY_IP,
            remote_traffic_gen,
        ]

        # logger.debug(f"Challenge args for {machine_name}: {args[2:5]}...") #DELETE FOR PRODUCTION!

        return await self.run(
            ip=ip,
            ssh_user=ssh_user,
            key_path=key_path,
            args=args,
            files_to_verify=files_to_verify,
            remote_base_directory=remote_base_directory
        )


    async def check_machines_availability(self, uids: List[int], timeout: float = QUERY_AVAILABILITY_TIMEOUT) -> Tuple[List[PingSynapse], List[dict]]:
        """
        Asynchronously checks the availability of a list of miners by their unique IDs with a timeout.

        Args:
            uids (List[int]): A list of unique identifiers (UIDs) corresponding to the miners.
            timeout (float): Maximum time in seconds to wait for each miner's response.

        Returns:
            Tuple[List[Synapse], List[dict]]: 
                - A list of Synapse responses from each miner.
                - A list of dictionaries containing availability status for each miner.
        """
        
        async def check_with_timeout(uid):
            try:
                return await asyncio.wait_for(self.check_miner(uid), timeout=timeout)
            except asyncio.TimeoutError:
                # Build a dummy synapse and an error dictionary
                dummy_synapse = PingSynapse(machine_availabilities=MachineConfig())
                uid_status_availability = {
                    "uid": uid,
                    "ping_status_message": "Timeout while checking availability.",
                    "ping_status_code": 408,  # 408 Request Timeout
                }
                return dummy_synapse, uid_status_availability
            except Exception as e:
                # General exception fallback (optional, but good practice)
                # #DELETE FOR PRODUCTION!
                # if uid == 9:
                #     logger.error(f"Exception in check_miner for UID {uid}: {str(e)}")
                dummy_synapse = PingSynapse(machine_availabilities=MachineConfig())
                uid_status_availability = {
                    "uid": uid,
                    "ping_status_message": f"Error: {str(e)}",
                    "ping_status_code": 500,  # Internal server error
                }
                return dummy_synapse, uid_status_availability

        tasks = [check_with_timeout(uid) for uid in uids]  # Call the existing check_miner method
        results = await asyncio.gather(*tasks)
        synapses, all_miners_availability = zip(*results) if results else ([], [])

        return list(synapses), list(all_miners_availability)

    async def check_miner(self, uid: int) -> Tuple[PingSynapse, dict]:
        """
        Checks the status and availability of a specific miner.

        Args:
            uid (int): Unique identifier of the miner.

        Returns:
            Tuple[Synapse, dict]: A tuple containing the synapse response and miner's availability status.
        """
        synapse, uid_status_availability = await self.query_availability(uid)  

        return synapse, uid_status_availability
    
    async def execute_task(
        self, 
        task: str,
        miners: List[Tuple[int, 'PingSynapse']],
        subset_miners: list[int],
        backup_suffix: str = "", 
        label_hashes: dict = None,
        playlists: dict = {},
        challenge_duration: int = CHALLENGE_DURATION,
        timeout: int = ROUND_TIMEOUT
    ) -> List[Dict[str, Union[int, str]]]:
        """
        A generic function to execute different tasks (such as setup, challenge) on miners. 
        This function orchestrates the process of executing the provided task on multiple miners in parallel, 
        handling individual machine configurations, and ensuring each miner completes the task within a specified timeout.

        Args:
            task (str): The type of task to perform. Possible values are:
                'setup': Setup the miner environment (e.g., install dependencies).
                'challenge': Run a challenge procedure on the miner.
            miners (List[Tuple[int, PingSynapse]]): List of miners represented as tuples containing the unique ID (`int`) 
                                                    and the `PingSynapse` object, which holds machine configuration details.
            assigned_miners (list[int]): List of miner IDs assigned for the task. Used for tracking miners not available 
                                        during the task execution.
            backup_suffix (str, optional): A suffix for backup operations, typically used for reversion or setup purposes. 
                                            Defaults to an empty string.
            challenge_duration (int, optional): Duration (in seconds) for the challenge task to run. Defaults to 60 seconds.
            timeout (int, optional): Timeout duration for the task to complete for each miner, in seconds. Defaults to 30 seconds.

        Returns:
            List[Dict[str, Union[int, str]]]: A list of dictionaries containing the task status for each miner.
            Each dictionary includes the `uid` of the miner and the status code/message 
            indicating whether the task was successful or encountered an issue.
            200: Success.
            500: Failure (task failed on the miner).
            408: Timeout error (task did not complete in time).
            503: Service Unavailable (miner not available for the task).
        """
            
        task_status = {}

        async def process_miner(uid, synapse):
            """
            Process all machines for a given miner and apply the specified task.

            Args:
                uid (int): Miner's unique ID.
                synapse (PingSynapse): Miner's machine configurations.

            Returns:
                None: Updates task status for each machine.
            """

            async def process_machine(machine_type, machine_details):
                """
                Apply task to a specific machine.

                Args:
                    machine_type (str): Type of the machine ("king" or "tgen").
                    machine_details (dict): Machine connection details (contains `ip`, `username`).

                Returns:
                    bool: True if the task succeeds, False otherwise.
                """

                # Retrieve necessary connection and task details
                ip = machine_details['ip']
                ssh_user = machine_details['username']
                key_path = os.path.join(SESSION_KEY_DIR, f"session_key_{uid}")  # Use correct session key path

                # Get machine-specific details like private IP and default directories
                moat_private_ip = self.moat_private_ips[uid]  # Private IP for the Moat machine
                default_dir = get_default_dir(ssh_user=ssh_user)  # Get the default directory for the user
                remote_base_directory = os.path.join(default_dir, "tensorprox")  # Define the remote base directory for tasks

                # Determine network interface based on provider
                provider = synapse.machine_availabilities.provider
                if provider == "GCP":
                    from tensorprox.core.apis.gcp_api import GCP_INTERFACE
                    interface = GCP_INTERFACE
                elif provider == "AWS":
                    from tensorprox.core.apis.aws_api import AWS_INTERFACE
                    interface = AWS_INTERFACE
                else:
                    interface = AZURE_INTERFACE  # Default to Azure interface

                # For traffic generators, extract index from the task creation call
                if machine_type == "king":
                    machine_name = "king"
                    index = 0
                    private_ip = machine_details.get('private_ip')  # Get private IP from provider response
                elif machine_type == "tgen":
                    # Index will be passed separately, default to 0 for now
                    index = machine_details.get('_index', 0)
                    machine_name = f"tgen-{index}"
                    private_ip = machine_details.get('private_ip')  # Get private IP from provider response
                else:
                    machine_name = "unknown"
                    index = 0
                    private_ip = None

                try:
                    if task == "initial_setup":
                        result = await self.process_initial_setup(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            uid
                        )
                    elif task == "gre_setup":
                        if not private_ip or not interface:
                            # logger.error(f"Missing network config for {machine_type} {machine_name}: private_ip={private_ip}, interface={interface}") #DELETE FOR PRODUCTION!
                            result = False
                        else:
                            result = await self.process_gre_setup(
                                ip,
                                ssh_user,
                                key_path,
                                remote_base_directory,
                                machine_type,
                                index,
                                moat_private_ip,
                                private_ip,
                                interface
                            )
                            if not result:
                                # logger.error(f"GRE setup failed for {machine_type} {machine_name} at {ip}") #DELETE FOR PRODUCTION!
                                pass
                    elif task == "challenge":
                        # logger.debug(f"Starting challenge execution on {machine_name} at {ip}") #DELETE FOR PRODUCTION!
                        result = await self.process_challenge(
                            ip,
                            ssh_user,
                            key_path,
                            remote_base_directory,
                            machine_name,
                            challenge_duration,
                            label_hashes,
                            playlists
                        )
                        # logger.debug(f"Challenge execution result for {machine_name}: {result}") #DELETE FOR PRODUCTION!
                        result = await self.extract_metrics(result, machine_name, label_hashes)
                        # logger.debug(f"Extracted metrics for {machine_name}: {result}") #DELETE FOR PRODUCTION!
                    else:
                        raise ValueError(f"Unsupported task: {task}")

                    return result

                except Exception as e:
                    logging.error(f"Error executing task on {machine_name} with ip {ip} for miner {uid}: {e}")
                    return False
            
            # Create tasks for all machines of the miner using stored machine details
            king_machine_task = process_machine("king", self.king_details[uid])
            traffic_generators_tasks = [
                process_machine("tgen", {**details, '_index': i}) for i, details in enumerate(self.traffic_generator_details[uid])
            ]

            # Run all tasks concurrently
            tasks = [king_machine_task] + traffic_generators_tasks
            results = await asyncio.gather(*tasks)

            if task == "challenge":
                # For each machine, collect its result and handle `label_counts` or `None`
                label_counts_results = []
                failed_machines = 0

                for result in results:
                    if isinstance(result, tuple):
                        label_counts_results.append(result)
                    else:
                        failed_machines += 1

                all_success = failed_machines == 0

                task_status[uid] = {
                    f"{task}_status_code": 200 if all_success else 500,
                    f"{task}_status_message": f"All machines processed {task} successfully with label counts" if all_success else f"Failure: {failed_machines} machines failed in processing {task}",
                    "label_counts_results": label_counts_results,  # Add the successful label counts
                }

            else:
                # For other tasks, just mark the status based on boolean success
                all_success = all(results)  # All machines should return True for success
                
                task_status[uid] = {
                    f"{task}_status_code": 200 if all_success else 500,
                    f"{task}_status_message": f"All machines processed {task} successfully" if all_success else f"Failure: Some machines failed to process {task}",
                }

        async def setup_miner_with_timeout(uid, synapse):
            """
            Setup miner with a timeout.
            
            Args:
                uid (int): Unique identifier for the miner.
                synapse (PingSynapse): The synapse containing machine availability information.
            """

            try:
                # Apply timeout to the entire setup_miner function for each miner
                await asyncio.wait_for(process_miner(uid, synapse), timeout=timeout)

                state = (
                    "GET_READY" if task == "gre_setup" 
                    else "END_ROUND" if task == "challenge" 
                    else None
                )
                
                if state :
                    try:
                        challenge_synapse = ChallengeSynapse(
                            task="Defend The King",
                            state=state,
                        )
                        await self.dendrite_call(uid, challenge_synapse)
                        
                    except Exception as e:
                        logger.error(f"Error sending synapse to miner {uid}: {e}")


            except asyncio.TimeoutError:
                logger.error(f"⏰ Timeout reached for {task} with miner {uid}.")
                task_status[uid] = {
                    f"{task}_status_code": 408,
                    f"{task}_status_message": f"Timeout: Miner {task} aborted. Skipping miner {uid} for this round."
                }
            
        # Split miners into batches
        batch_tasks = []
        for i in range(0, len(miners), BATCH_SIZE):
            batch = miners[i:i + BATCH_SIZE]

            async def launch_batch(batch, delay):
                await asyncio.sleep(delay)
                await asyncio.gather(*[
                    setup_miner_with_timeout(uid, synapse) for uid, synapse in batch
                ])

            batch_tasks.append(launch_batch(batch, i // BATCH_SIZE * BATCH_DELAY))

        # Await all batch launches
        await asyncio.gather(*batch_tasks)

        # Mark assigned miners that are not in ready_miners as unavailable
        available_miner_ids = {uid for uid, _ in miners}
        for miner_id in subset_miners:
            if miner_id not in available_miner_ids:
                task_status[miner_id] = {
                    f"{task}_status_code": 503,  # HTTP status code for Service Unavailable
                    f"{task}_status_message": "Unavailable: Miner not available in the current round."
                }
        
        return [{"uid": uid, **status} for uid, status in task_status.items()]
    
    async def clear_round_vms(self, miners_to_clear: List[Tuple[int, 'PingSynapse']]) -> None:
        """
        Clear VMs for all miners after round completion.
        
        This method handles cleanup for different cloud providers in a generic way.
        Currently supports Azure and GCP providers.
        
        Args:
            miners_to_clear: List of (uid, synapse) tuples for miners whose VMs should be cleared
        """
                
        cleanup_tasks = []
        
        for uid, synapse in miners_to_clear:
            try:
                provider = synapse.machine_availabilities.provider
                
                if provider == "GCP":
                    # Dynamic import of GCP clear_vms to avoid circular dependencies
                    from tensorprox.core.apis.gcp_api import clear_vms as gcp_clear_vms
                    
                    # Pass full generic config to GCP API
                    machine_config = synapse.machine_availabilities.dict()
                    
                    # Use timestamp for tracking
                    import time
                    timestamp = int(time.time())
                    cleanup_tasks.append(gcp_clear_vms(uid, machine_config, timestamp))
                    
                elif provider == "AWS":
                    # Dynamic import of AWS clear_vms to avoid circular dependencies
                    from tensorprox.core.apis.aws_api import clear_vms as aws_clear_vms
                    
                    # Pass full generic config to AWS API
                    machine_config = synapse.machine_availabilities.dict()
                    
                    # Use timestamp for tracking
                    import time
                    timestamp = int(time.time())
                    cleanup_tasks.append(aws_clear_vms(uid, machine_config, timestamp))
                    
                else:
                    logger.warning(f"Unsupported provider '{provider}' for UID {uid}, skipping cleanup")
                    
            except Exception as e:
                logger.error(f"Error preparing cleanup for UID {uid}: {e}")
                # Continue with other miners even if one fails
        
        if cleanup_tasks:
            # Execute all cleanup tasks concurrently
            results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
            
            # Log results
            for i, (uid, _) in enumerate(miners_to_clear):
                if i < len(results):
                    if isinstance(results[i], Exception):
                        logger.error(f"Failed to clear VMs for UID {uid}: {results[i]}")
                    else:
                        # # DELETE FOR PRODUCTION ! # COMMENTED OUT
                        # logger.info(f"Successfully cleared VMs for UID {uid}")
                        pass
        
        
