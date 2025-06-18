"""
================================================================================

TensorProx Validator

This module initializes a TensorProx validator responsible for managing miners and running validation tasks. 
It sets up the necessary dependencies, configurations, and the aiohttp web server for orchestrator communication.

Key Responsibilities:
- Check miner's availability.
- Manages the lifecycle of validation tasks, including setup, lockdown, challenge, and revert phases.
- Provides an API for readiness checks and miner assignments.

Dependencies:
- `aiohttp`: For handling asynchronous web requests.
- `asyncio`: For managing concurrent tasks.
- `loguru`: For structured logging.
- `tensorprox`: Core TensorProx framework for miner management and validation.

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


import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
from aiohttp import web
import asyncio
import signal
import bittensor as bt
from tensorprox import *
from tensorprox.utils.utils import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings
from loguru import logger
from tensorprox.base.validator import BaseValidatorNeuron
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.utils.logging import ErrorLoggingEvent
from concurrent.futures import ThreadPoolExecutor
from tensorprox.core.round_manager import RoundManager
from tensorprox.utils.utils import create_random_playlist, get_remaining_time, generate_random_hashes
from tensorprox.rewards.scoring import task_scorer
from tensorprox.utils.timer import Timer
from tensorprox.rewards.weight_setter import weight_setter
from datetime import datetime, timezone
import random
import time
import hashlib
from pathlib import Path
import subprocess
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

executor = ThreadPoolExecutor(max_workers=1)

# Global variables to store the runner references
EPOCH_TIME = ROUND_TIMEOUT + EPSILON

class Validator(BaseValidatorNeuron):
    """Tensorprox validator neuron responsible for managing miners and running validation tasks."""
    
    def __init__(self, config=None):
        """
        Initializes the validator instance.

        Args:
            config (dict, optional): Configuration settings for the validator.
        """
        super(Validator, self).__init__(config=config)
        self.load_state()
        self._lock = asyncio.Lock()
        self.should_exit = False
        self.active_count = 0

        # Container management attributes
        self.container_name = f"{settings.WALLET.hotkey.ss58_address.lower()}_challenge_v1_0_0"
        self.scratch_tag = f"{settings.DOCKER_REGISTRY_REPO}:scratch-{self.container_name}"
        self.container_path = Path(__file__).parent.parent / "tensorprox" / "core" / "immutable" / f"{self.container_name}.tar.enc"
        self.container_password = ""  # Initialize with empty string
        self.container_hash = ""  # Initialize with empty string
        self.image_hash = ""  # Initialize with empty string (Docker image hash)
        self.container_ready = False
        self.round_nonce = ""  # Initialize with empty string
        self.nonce_key = ""  # Initialize with empty string
        self.docker_logged_in = False  # Track Docker login status
        self.dockersafe_metadata = None  # Store dockersafe metadata for the round

    def _create_encrypted_round_nonce(self, round_nonce_value: str) -> tuple:
        """
        Create an encrypted round_nonce.enc file and return the decryption key.
        
        Args:
            round_nonce_value (str): The round nonce value to encrypt
            
        Returns:
            tuple: (encryption_key_base64, encrypted_data_base64)
        """
        try:
            key = get_random_bytes(32)  # 256-bit key
            cipher = AES.new(key, AES.MODE_ECB)
            padded_nonce = pad(round_nonce_value.encode('utf-8'), AES.block_size)
            encrypted_data = cipher.encrypt(padded_nonce)

            key_base64 = base64.b64encode(key).decode()
            encrypted_base64 = base64.b64encode(encrypted_data).decode()

            return key_base64, encrypted_base64
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
        
    def _docker_login(self):
        """
        Authenticate with Docker registry using the access token.
        
        Returns:
            bool: True if login successful, False otherwise
        """
        if self.docker_logged_in:
            return True
            
        try:
            logger.info("Logging into Docker registry...")
            
            # Use echo to pipe the token to docker login for security
            login_process = subprocess.run([
                "bash", "-c", 
                f"echo '{settings.DOCKER_REGISTRY_TOKEN}' | docker login -u {settings.DOCKER_REGISTRY_USERNAME} --password-stdin"
            ], capture_output=True, text=True, check=False)
            
            if login_process.returncode == 0:
                logger.success("Successfully logged into Docker registry")
                self.docker_logged_in = True
                return True
            else:
                logger.error(f"Docker login failed: {login_process.stderr.strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Exception during Docker login: {e}")
            return False

    def _build_dockersafe_for_round(self, base_directory: str = None) -> dict:
        """Build dockersafe binary with current round nonce embedded
        
        Args:
            base_directory (str, optional): Base directory for tensorprox (for consistent paths)
            
        Returns:
            dict: Metadata containing token, sha, and docker_cli_sha
        """
        try:
            # Use consistent base directory pattern, but keep building locally for security
            if base_directory is None:
                base_directory = str(Path.home() / "tensorprox")
            
            # Path to docker-cli binary in immutable directory using standard utility
            docker_cli_path = get_immutable_path(base_directory, "docker-cli")
            
            # Get docker-cli hash automatically
            sha = hashlib.sha256(Path(docker_cli_path).read_bytes()).hexdigest()
            
            CFLAGS = [f'-DEXPECTED_DOCKER_HASH_MACRO="{sha}"',
                      f'-DROUND_TOKEN_MACRO="{self.round_nonce}"']
            
            # Path to dockersafe.c source file using consistent pattern
            dockersafe_c_path = os.path.join(base_directory, 'tensorprox/utils/dockersafe.c')
            
            # Build dockersafe binary in home directory (validator controlled)
            subprocess.check_call(['gcc','-static','-O2','-pipe','-s','-D_GNU_SOURCE',
                                   *CFLAGS, dockersafe_c_path, '-lcrypto', '-o', 'dockersafe'],
                                 cwd=Path.home())
            
            # Generate metadata for verification
            sh = subprocess.check_output(['sha256sum','dockersafe'], cwd=Path.home()).split()[0].decode()
            metadata = {'token': self.round_nonce, 'sha': sh, 'docker_cli_sha': sha}
            
            logger.info(f"🔒 Built dockersafe for round {self.round_nonce[:8]} - SHA256: {metadata['sha'][:16]}...")
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to build dockersafe: {e}")
            return None

    def _push_scratch_container_to_registry(self, tar_enc_path: str) -> bool:
        """
        Create a scratch container with embedded .tar.enc file and push to registry.
        
        Args:
            tar_enc_path (str): Path to the .tar.enc file
            
        Returns:
            bool: True if push successful, False otherwise
        """
        try:
            # Ensure we're logged in
            if not self._docker_login():
                return False
            
            # Create a temporary build directory for the scratch container
            scratch_build_dir = Path.home() / f"scratch_build_{self.container_name}"
            
            # Clean up any existing build directory
            if scratch_build_dir.exists():
                shutil.rmtree(scratch_build_dir)
            
            # Create build directory
            scratch_build_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy the .tar.enc file to build directory
            tar_enc_build_path = scratch_build_dir / f"{self.container_name}.tar.enc"
            import shutil
            shutil.copy2(tar_enc_path, tar_enc_build_path)
            
            # Create Dockerfile for scratch container
            scratch_dockerfile_content = f"""
FROM scratch

# Copy the encrypted container file
COPY {self.container_name}.tar.enc /{self.container_name}.tar.enc

"""
            
            scratch_dockerfile_path = scratch_build_dir / "Dockerfile"
            scratch_dockerfile_path.write_text(scratch_dockerfile_content)
            
            logger.info(f"Building scratch container: {self.scratch_tag}")
            
            # Build the scratch container
            build_process = subprocess.run([
                "docker", "build", "-t", self.scratch_tag, str(scratch_build_dir)
            ], capture_output=True, text=True, check=False)
            
            if build_process.returncode != 0:
                logger.error(f"Failed to build scratch container: {build_process.stderr.strip()}")
                return False
            
            # Get the scratch container image hash
            inspect_result = subprocess.run([
                "docker", "image", "inspect", self.scratch_tag, "--format", "{{.Id}}"
            ], capture_output=True, text=True, check=False)
            
            logger.info(f"Pushing scratch container to registry: {self.scratch_tag}")
            
            # Push the container
            push_process = subprocess.run([
                "docker", "push", self.scratch_tag
            ], capture_output=True, text=True, check=False)
            
            if push_process.returncode == 0:
                logger.success(f"Successfully pushed scratch container {self.scratch_tag} to registry")
                
                # Clean up local scratch container image
                subprocess.run([
                    "docker", "rmi", self.scratch_tag
                ], capture_output=True, text=True, check=False)
                
                return True
            else:
                logger.error(f"Failed to push scratch container: {push_process.stderr.strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Exception during scratch container push: {e}")
            return False
        finally:
            # Always cleanup build directory
            if 'scratch_build_dir' in locals() and scratch_build_dir.exists():
                import shutil
                shutil.rmtree(scratch_build_dir)

    def map_to_consecutive(self, active_uids):
        # Sort the input list
        sorted_list = sorted(active_uids)
        
        # Create a mapping from sorted list to consecutive numbers starting from 1
        mapping = {num: idx for idx, num in enumerate(sorted_list)}
        
        return mapping
    
    def fetch_active_validators(self, data: str):
        all_commitments = settings.SUBTENSOR.get_all_commitments(netuid=settings.NETUID) 
        matching_hotkeys = [hotkey for hotkey, value in all_commitments.items() if value == data]
        uids = [
            neuron.uid
            for neuron in settings.METAGRAPH.neurons
            if neuron.hotkey in matching_hotkeys
            and neuron.validator_permit
            and settings.METAGRAPH.S[neuron.uid] >= settings.NEURON_VPERMIT_TAO_LIMIT
        ]
        return uids

    def sync_shuffle_uids(self, uids: list, active_count: int, seed: int):
        
        random.seed(seed)
        random.shuffle(uids)

        # Split the shuffled UIDs into subsets based on the active validator count
        miner_subsets = [uids[i::active_count] for i in range(active_count)]

        return miner_subsets
        
    def check_timeout(self, start_time: datetime, round_timeout: float = ROUND_TIMEOUT) -> tuple:
        """
        Checks if the round should be broken due to a timeout.

        Args:
            start_time (datetime): The start time of the round.
            round_timeout (float): Timeout for the round (default is ROUND_TIMEOUT).

        Returns:
            tuple: A tuple containing:
                - condition (bool): The updated condition indicating whether the round should be broken.
                - elapsed_time (float): The elapsed time in seconds since the round started.
                - remaining_time (float): The remaining time in seconds until the round timeout.
        """

        elapsed_time = (datetime.now() - start_time).total_seconds()
        remaining_time = round_timeout - elapsed_time

        # If the timeout has been reached
        if remaining_time <= 0:
            logger.info("Timeout reached for this round.")
            return True # Timeout occurred

        elif elapsed_time % 10 < 1:
            logger.debug(f"Waiting until the end of the round... Remaining time: {int(remaining_time // 60)}m {int(remaining_time % 60)}s")
    
        return False  # Round is still active


    async def ready(self, request):
        """
        Handles readiness checks from the orchestrator.

        Args:
            request (aiohttp.web.Request): Incoming HTTP request.

        Returns:
            aiohttp.web.Response: JSON response indicating readiness status.
        """
        data = await request.json()
        message = data.get("message", "").lower()

        if message == "ready":
            return web.json_response({"status": "ready"})
        else:
            return web.json_response({"status": "failed"}, status=400)

    
    async def run_step(self, timeout: float, sync_time: int, start_time: datetime) -> DendriteResponseEvent | None:
        """
        Runs a validation step to query assigned miners, process availability, and initiate challenges.

        Args:
            timeout (float): Maximum allowed time for the step execution.

        Returns:
            DendriteResponseEvent | None: The response event with miner availability details or None if no miners are available.
        """

        try:
            async with self._lock:
                
                logger.info("Waiting 60s before fetching active count..")

                await asyncio.sleep(60)

                active_validators_uids = self.fetch_active_validators(str(sync_time))

                # Check if validator's uid is in the active list
                if self.uid not in active_validators_uids :
                    logger.debug(f"UID was not found in the list of active validators, ending round.")
                    return None
                
                # Initialize container for this round
                self.round_nonce = hashlib.sha256(str(sync_time).encode()).hexdigest()
                self._init_container(round_manager)
                
                self.active_count = len(active_validators_uids)     

                logger.debug(f"Number of active validators = {self.active_count}")

                # Generate hash seed from universal time sync
                seed = int(hashlib.sha256(str(sync_time).encode('utf-8')).hexdigest(), 16) % (2**32)               

                sync_shuffled_uids = self.sync_shuffle_uids(list(range(settings.SUBNET_NEURON_SIZE)), self.active_count, seed)

                mapped_uids = self.map_to_consecutive(active_validators_uids)
                                    
                idx_permutation = mapped_uids[self.uid]

                # Ensure that each validator gets a unique subset of shuffled UIDs based on idx_permutation
                subset_miners = sync_shuffled_uids[idx_permutation]

                #Random generate soft/aggressive random playlist pairs
                playlists = {}
                random_int = random.randint(1, 10000)
                label_hashes = generate_random_hashes()

                for i in range(MAX_TGENS):
                    role_index = random_int + i
                    role = "soft" if role_index % 2 == 0 else "aggressive"
                    playlist = create_random_playlist(
                        total_seconds=CHALLENGE_DURATION,
                        label_hashes=label_hashes,
                        role=role,
                    )
                    playlists[f"tgen-{i}"] = playlist
                
                backup_suffix = start_time.strftime("%Y%m%d%H%M%S")

                if subset_miners:
                    success = False
                    while not success :
                        try:
                            elapsed_time = (datetime.now() - start_time).total_seconds()
                            timeout_process = ROUND_TIMEOUT - elapsed_time
                            success = await asyncio.wait_for(self._process_miners(subset_miners, backup_suffix, label_hashes, playlists), timeout=timeout_process)
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout reached for this round after {int(ROUND_TIMEOUT / 60)} minutes.")
                        except Exception as ex:
                            logger.exception(f"Unexpected error while processing miners: {ex}.")

                        condition = self.check_timeout(start_time)
                        
                        if condition :
                            break
                else :
                    logger.warning("📖 No miners assigned for this round.")
                    condition = False

                if not condition:  
                    await self._wait_for_condition(start_time)

                # Clean up container resources at the end of the round
                self._cleanup_container()

                logger.debug(f"🎉  End of round, waiting for the next one...")


        except Exception as ex:
            logger.exception(ex)
            return ErrorLoggingEvent(
                error=str(ex),
            )
        

    async def periodic_epoch_check(self) :
        """Periodically checks the current UTC time to decide when to trigger the next epoch."""
        while not self.should_exit:

            now = datetime.now(timezone.utc)
            current_time = int(now.timestamp())

            if current_time % EPOCH_TIME == 0:  # Trigger epoch every `EPOCH_TIME` seconds

                logger.info(f"📢 Starting new round at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC.")

                logger.info(f"🐛 Committing Proof of Activity : {current_time}")
    
                async def try_commit_with_retries():
                    attempt = 1
                    while attempt <= 3:
                        try:
                            loop = asyncio.get_running_loop()
                            await loop.run_in_executor(
                                executor,
                                lambda: settings.SUBTENSOR.commit(
                                    wallet=settings.WALLET,
                                    netuid=settings.NETUID,
                                    data=str(current_time)
                                )
                            )
                            logger.info(f"✅ Commit succeeded on attempt {attempt}")
                            return True
                        except Exception as e:
                            logger.warning(f"⚠️ Commit attempt {attempt} failed: {e}")
                            await asyncio.sleep(1)               
                        attempt +=1
                    return False

                try:
                    success = await asyncio.wait_for(try_commit_with_retries(), timeout=55)
                    if not success:
                        logger.error("❌ All commit attempts failed. Skipping step.")
                    else:
                        await self.run_step(timeout=settings.NEURON_TIMEOUT, sync_time=current_time, start_time=datetime.now())
                except asyncio.TimeoutError:
                    logger.error("❌ Commit process timed out after 55 seconds. Skipping step.")

            await asyncio.sleep(1) 


    async def _wait_for_condition(self, start_time):
        """
        Waits for the timeout condition to be met by checking the elapsed time.

        Args:
            start_time (datetime): The start time of the current round.

        Returns:
            bool: Returns True when the condition is met, False otherwise.
        """

        while not self.check_timeout(start_time):
            await asyncio.sleep(1)  # Check the condition every second
        return True  # The condition is met, the loop ends
    

    async def _process_miners(self, subset_miners, backup_suffix, label_hashes, playlists):
        """Handles processing of miners, including availability check, setup, challenge, and revert phases."""
        
        # Step 1: Query miner availability
        with Timer() as timer:

            logger.debug(f"🔍 Querying machine availabilities for UIDs: {subset_miners}")
            
            try:
                synapses, all_miners_availability = await round_manager.check_machines_availability(subset_miners)
            except Exception as e:
                logger.error(f"Error querying machine availabilities: {e}")
                return False

        logger.debug(f"Received responses in {timer.elapsed_time:.2f} seconds")

        available_miners = [
            (uid, synapse) for uid, synapse, availability in zip(subset_miners, synapses, all_miners_availability)
            if availability["ping_status_code"] == 200
        ]

        if not available_miners:
            logger.warning("No miners are available after availability check. Retrying..")
            return False

        # Step 2: Initial Session Key Setup
        with Timer() as setup_timer:

            logger.info(f"🛠 Running initial setup for available miners : {[uid for uid, _ in available_miners]}")

            try:

                setup_results = await round_manager.execute_task(
                    task="initial_setup",
                    miners=available_miners,
                    subset_miners=subset_miners,
                    backup_suffix=backup_suffix,
                    timeout=INITIAL_SETUP_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during setup phase: {e}")
                setup_results = []
                return False

        setup_completed_miners = [
            (uid, synapse) for uid, synapse in available_miners
            if any(entry["uid"] == uid and entry["initial_setup_status_code"] == 200 for entry in setup_results)
        ]

        if not setup_completed_miners:
            logger.warning("No miners left after the setup attempt.")
            return False

        setup_completed_uids = [uid for uid, _ in setup_completed_miners]

        logger.debug(f"Initial setup phase completed in {setup_timer.elapsed_time:.2f} seconds")

        # Step 3: GRE Setup
        with Timer() as gre_timer:

            logger.info(f"⚙️ Starting GRE configuration phase for miners: {setup_completed_uids}")

            try:

                gre_results = await round_manager.execute_task(
                    task="gre_setup",
                    miners=setup_completed_miners,
                    subset_miners=subset_miners,
                    timeout=GRE_SETUP_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during GRE configuration phase: {e}")
                gre_results = []

        logger.debug(f"GRE configuration completed in {gre_timer.elapsed_time:.2f} seconds")
        
        gre_completed_miners = [
            (uid, synapse) for uid, synapse in setup_completed_miners
            if any(entry["uid"] == uid and entry["gre_setup_status_code"] == 200 for entry in gre_results)
        ]

        if not gre_completed_miners:
            logger.warning("No miners are available after the GRE setup.")
            return False
        
        gre_completed_uids = [uid for uid, _ in gre_completed_miners]

        # Step 4: Lockdown
        with Timer() as lockdown_timer:
            logger.info(f"🔒 Locking down miners with revert scheduling : {gre_completed_uids}")
            try:
                
                lockdown_results = await round_manager.execute_task(
                    task="lockdown",
                    miners=gre_completed_miners,
                    subset_miners=subset_miners,
                    timeout=LOCKDOWN_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during lockdown phase: {e}")
                lockdown_results = []
                return False
            
        logger.debug(f"Lockdown phase completed in {lockdown_timer.elapsed_time:.2f} seconds")

        locked_miners = [
            (uid, synapse) for uid, synapse in gre_completed_miners
            if any(entry["uid"] == uid and entry["lockdown_status_code"] == 200 for entry in lockdown_results)
        ]

        if not locked_miners:
            logger.warning("No miners are available for challenge phase.")
            return False

        locked_uids = [uid for uid, _ in locked_miners]

        # Step 5: Challenge
        with Timer() as challenge_timer:
            
            logger.info(f"🚀 Starting challenge phase for miners: {locked_uids} | Duration: {CHALLENGE_DURATION} seconds")

            try:

                challenge_results = await round_manager.execute_task(
                    task="challenge",
                    miners=locked_miners,
                    subset_miners=subset_miners,
                    label_hashes=label_hashes,
                    playlists=playlists,
                    timeout=CHALLENGE_TIMEOUT
                )

            except Exception as e:
                logger.error(f"Error during challenge phase: {e}")
                challenge_results = []

        logger.debug(f"Challenge phase completed in {challenge_timer.elapsed_time:.2f} seconds")

        # Create a complete response event
        response_event = DendriteResponseEvent(
            all_miners_availability=all_miners_availability,
            setup_status=setup_results,
            gre_status=gre_results,
            lockdown_status=lockdown_results,
            challenge_status=challenge_results,
            uids=subset_miners,
        )

        logger.debug(f"🎯 Scoring round and adding it to reward event ..")

        # Scoring manager will score the round
        task_scorer.score_round(response=response_event, uids=subset_miners, label_hashes=label_hashes, block=self.block, step=self.step)
        
        return True
        
        
    async def forward(self):
        """Implements the abstract forward method."""
        await asyncio.sleep(1)


    async def handle_challenge(self):
        """Implements the abstract handle challenge method."""
        await asyncio.sleep(1)

    def _init_container(self, round_manager):
        """Initialize container for each round with a unique nonce"""
        try:
            # Generate a unique password for this round using the nonce
            self.container_password = hashlib.sha256(
                f"validator_{settings.WALLET.hotkey.ss58_address.lower()}_container_{self.round_nonce}".encode()
            ).hexdigest()[:16]

            # Create encrypted round nonce and get the decryption key
            self.nonce_key, encrypted_round_nonce = self._create_encrypted_round_nonce(self.round_nonce)
            
            # Always rebuild container for each round
            logger.info("Building new container for this round...")
            self._build_container(encrypted_round_nonce)

            # Build dockersafe once per round (not per machine)
            logger.info("Building dockersafe binary for this round...")
            self.dockersafe_metadata = self._build_dockersafe_for_round()
            if not self.dockersafe_metadata:
                raise Exception("Failed to build dockersafe binary")

            # Update RoundManager with new container attributes
            round_manager.container_name = self.container_name
            round_manager.scratch_tag = self.scratch_tag
            round_manager.container_path = self.container_path
            round_manager.container_password = self.container_password
            round_manager.container_hash = self.container_hash
            round_manager.image_hash = self.image_hash
            round_manager.container_ready = self.container_ready
            round_manager.round_nonce = self.round_nonce
            round_manager.nonce_key = self.nonce_key
            round_manager.dockersafe_metadata = self.dockersafe_metadata

        except Exception as e:
            logger.error(f"Container initialization failed: {e}")

    def _build_container(self, encrypted_round_nonce):
        """Build the validator container with a nonce"""
        
        container_dir = Path(self.container_path).parent
        container_dir.mkdir(parents=True, exist_ok=True)
            
        # Read the challenge script from challenge folder
        challenge_script_path = Path(__file__).parent.parent / "tensorprox" / "core" / "challenge" / "challenge.sh"
        with open(challenge_script_path, 'r') as f:
            challenge_script = f.read()

        # Read the traffic generator script from challenge folder
        traffic_gen_script_path = Path(__file__).parent.parent / "tensorprox" / "core" / "challenge" / "traffic_generator.py"
        with open(traffic_gen_script_path, 'r') as f:
            traffic_gen_script = f.read()

        # Create Dockerfile with nonce embedded
        dockerfile_content = f"""
FROM python:3.10-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    python3-dev \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir --user faker scapy pycryptodome

FROM python:3.10-slim

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    tcpdump \\
    iputils-ping \\
    gawk \\
    jq \\
    iproute2 \\
    && rm -rf /var/lib/apt/lists/* \\
    && apt-get clean \\
    && rm -rf /tmp/* /var/tmp/* /usr/share/doc/* /usr/share/man/*

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy round nonce securely
COPY round_nonce.enc /etc/round_nonce.enc
RUN chmod 600 /etc/round_nonce.enc

# Copy scripts
COPY challenge.sh /usr/local/bin/challenge.sh
COPY traffic_generator.py /usr/local/bin/traffic_generator.py

RUN chmod +x /usr/local/bin/challenge.sh /usr/local/bin/traffic_generator.py

ENTRYPOINT ["/usr/local/bin/challenge.sh"]
"""
        
        # Use home directory for build (more reliable than /tmp)
        build_dir = Path.home() / f"docker_build_{self.container_name}"
        
        # Clean up any existing build directory
        if build_dir.exists():
            shutil.rmtree(build_dir)
    
        # Create build directory
        build_dir.mkdir(parents=True, exist_ok=True)
        
        # Write challenge.sh
        challenge_path = build_dir / "challenge.sh"
        challenge_path.write_text(challenge_script)

        # Write traffic_generator.py
        traffic_gen_path = build_dir / "traffic_generator.py"
        traffic_gen_path.write_text(traffic_gen_script)

        # Write encrypted round_nonce file
        nonce_path = build_dir / "round_nonce.enc"
        nonce_path.write_text(encrypted_round_nonce)

        dockerfile_path = build_dir / "Dockerfile"
        dockerfile_path.write_text(dockerfile_content)
        
        logger.info(f"Building Docker image from: {build_dir}")
        
        try:
            # Use latest tag since we're rebuilding every round anyway
            image_tag = f"{self.container_name}:latest"
            
            result = subprocess.run([
                "sudo", "docker", "build", "-t", image_tag, str(build_dir)
            ], capture_output=True, text=True, check=False)
                            
            if result.returncode != 0:
                raise Exception(f"Docker build failed with return code {result.returncode}: {result.stderr}")

            # Get the Docker image hash after successful build
            inspect_result = subprocess.run([
                "docker", "image", "inspect", image_tag, "--format", "{{.Id}}"
            ], capture_output=True, text=True, check=False)
            
            if inspect_result.returncode == 0:
                self.image_hash = inspect_result.stdout.strip()
            else:
                logger.error(f"Failed to get Docker image hash: {inspect_result.stderr}")
                self.image_hash = ""
        
            # Save container
            tar_path = container_dir / f"{self.container_name}.tar"
            with open(tar_path, "wb") as f:
                subprocess.run([
                    "docker", "save", image_tag
                ], stdout=f, check=True)
            
            # Encrypt container
            subprocess.run([
                "gpg", "--batch", "--yes",
                "--passphrase", self.container_password,
                "--cipher-algo", "AES256",
                "-z", "9",  # Maximum compression
                "-c", str(tar_path)
            ], check=True)
            
            # Clean up and get hash
            tar_path.unlink()
            encrypted_path = container_dir / f"{self.container_name}.tar.gpg"
            if encrypted_path.exists():
                encrypted_path.rename(self.container_path)
            
            with open(self.container_path, 'rb') as f:
                self.container_hash = hashlib.sha256(f.read()).hexdigest()

            # Push scratch container with embedded .tar.enc
            push_success = self._push_scratch_container_to_registry(str(self.container_path))
            if push_success:
                logger.success("Scratch container with embedded .tar.enc successfully pushed to Docker Hub!")
            else:
                logger.warning("Failed to push scratch container to Docker Hub, but continuing with local operations")

        finally:
            # Always cleanup build directory
            if build_dir.exists():
                shutil.rmtree(build_dir)

            # Clean up the main Docker image (we only need the scratch container in registry)
            subprocess.run([
                "sudo", "docker", "rmi", image_tag
            ], capture_output=True, text=True, check=False)

        logger.success(f"Container built successfully!")
        logger.info(f"Container hash: {self.container_hash}")
        logger.info(f"Image hash: {self.image_hash}")
        self.container_ready = True
            
    def _cleanup_container(self):
        """Clean up container resources at the end of the round"""
        try:
            # Stop and remove running container
            subprocess.run([
                "docker", "stop", self.container_name
            ], capture_output=True, text=True, check=False)
            
            subprocess.run([
                "docker", "rm", self.container_name
            ], capture_output=True, text=True, check=False)
            
            # Remove Docker image
            image_tag = f"{self.container_name}:latest"
            subprocess.run([
                "sudo", "docker", "rmi", image_tag
            ], capture_output=True, text=True, check=False)
            
            # Remove encrypted container file
            if Path(self.container_path).exists():
                Path(self.container_path).unlink()
            
            # Remove dockersafe binary
            dockersafe_path = Path.home() / "dockersafe"
            if dockersafe_path.exists():
                dockersafe_path.unlink()
            
            # Reset dockersafe metadata
            self.dockersafe_metadata = None
                
            logger.info("Container resources cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Error during container cleanup: {e}")


async def shutdown(signal=None):
    """
    Handle shutdown signals gracefully, reverting any locked miners first.
    
    Args:
        signal: The signal that triggered the shutdown (optional)
    """
    if signal:
        logger.info(f"Received shutdown signal: {signal.name}")
    
    # Mark the validator for exit
    validator_instance.should_exit = True
    
    logger.info("Validator shutdown complete.")

    
###############################################################################

# Create an aiohttp app for validator
app = web.Application()

# Create a RoundManager instance (will be initialized after container is ready)
round_manager = None

# Define the validator instance
validator_instance = Validator()


# Main function to start background tasks
async def main():
    """
    Starts the validator's aiohttp server.

    This function initializes and runs the web server to handle incoming requests
    and sets up signal handlers for graceful shutdown.
    """

    global round_manager

    # Set up signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        asyncio.get_event_loop().add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(shutdown(s))
        )

    # Create a RoundManager instance
    round_manager = RoundManager()

    # Start background tasks
    asyncio.create_task(weight_setter.start())
    asyncio.create_task(task_scorer.start())
    asyncio.create_task(validator_instance.periodic_epoch_check())  # Start the periodic epoch check
    
    try:
        logger.info(f"Validator is up and running, next round starting in {get_remaining_time(EPOCH_TIME)}...")
        
        while not validator_instance.should_exit:
            await asyncio.sleep(1)

    except Exception as e:
        logger.exception(f"Unexpected error in main loop: {e}")
        validator_instance.should_exit = True
    
    finally:
        # Ensure proper cleanup happens even if an exception occurs
        await shutdown()
        logger.info("Validator has been shut down.")


if __name__ == "__main__":

    asyncio.run(main())