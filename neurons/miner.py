"""
================================================================================

TensorProx Miner Implementation

Copyright (c) 2025 Shugo LTD. All Rights Reserved.

This module defines the `Miner` class, which represents a mining node within the TensorProx network. 
The miner is responsible for secure SSH key distribution to validators, packet sniffing, 
firewall management, and real-time DDoS detection.

Key Features:
- **SSH Key Management:** Generates and distributes SSH key pairs to authorized machines.
- **Packet Inspection:** Captures and processes network packets using raw sockets.
- **Firewall Control:** Dynamically enables or disables firewall functionality based on challenge states.
- **Machine Learning-Based Traffic Filtering:** Uses a trained Decision Tree model to classify network traffic 
  and determine whether to allow or block packets.
- **Batch Processing:** Aggregates packets over a configurable interval and evaluates them using feature extraction.

Dependencies:
- `tensorprox`: Provides core functionalities and network protocols.
- `paramiko`: Used for SSH key distribution and management.
- `sklearn`, `joblib`: Used for loading and running machine learning models.
- `numpy`: Supports feature extraction and data manipulation.
- `loguru`: Handles logging and debugging information.

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


# ruff: noqa: E402
import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
import csv
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="miner")
settings = settings.settings
import time
from loguru import logger
from tensorprox.base.miner import BaseMinerNeuron
from tensorprox.utils.logging import ErrorLoggingEvent, log_event
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse, MachineConfig
from tensorprox.utils.utils import *
from tensorprox.core.immutable.gre_setup import GRESetup
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from threading import Thread, Event
import asyncio
import socket
import struct
from pydantic import Field, PrivateAttr
from typing import List, Tuple, Any, Dict
import select
from collections import defaultdict
import numpy as np
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
import asyncssh
from pathlib import Path

NEURON_STOP_ON_FORWARD_EXCEPTION: bool = False

def load_azure_credentials() -> dict:
    """
    Loads Azure credentials and resource group from a .env.miner file.
    Returns a dictionary with keys: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_RESOURCE_GROUP
    """

    creds = {}
    azure_keys = ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_RESOURCE_GROUP"]
    
    # Check that all required Azure keys are present
    for k in azure_keys:
        creds[k] = os.environ.get(k)
        
    return creds

def load_network_config() -> dict:
    """
    Loads VNet and subnet info from .env.miner.
    Returns a dictionary with keys: VNET_NAME, VNET_ADDRESS_SPACE, SUBNET_NAME, SUBNET_ADDRESS_PREFIX
    """

    network_config = {}
    network_keys = ["VNET_NAME", "VNET_ADDRESS_SPACE", "SUBNET_NAME", "SUBNET_ADDRESS_PREFIX"]
    
    # Check that all required network keys are present
    for k in network_keys:
        network_config[k] = os.environ.get(k)
        
    return network_config

def load_vm_config() -> dict:
    """
    Loads VM config info from .env.miner.
    Returns a dictionary with keys: LOCATION, TGENS_SIZE, KING_SIZE, NUM_TGENS
    """
    vm_config = {}
    vm_keys = ["LOCATION", "TGENS_SIZE", "KING_SIZE", "NUM_TGENS"]
    
    for k in vm_keys:
        vm_config[k] = os.environ.get(k)

    return vm_config

class Miner(BaseMinerNeuron):
    """
    A class representing a miner node in the TensorProx network. 
    This node performs SSH key distribution to validators, packet inspection
    and firewall management for secure network access.
    """

    should_exit: bool = False
    firewall_active: bool = False
    firewall_thread: Thread = None
    stop_firewall_event: Event = Field(default_factory=Event)
    packet_buffers: Dict[str, List[Tuple[bytes, int]]] = Field(default_factory=lambda: defaultdict(list))
    batch_interval: int = 10
    max_tgens: int = 0
    azure_creds: dict = Field(default_factory=dict)
    machines_config: dict = Field(default_factory=dict)
    network_config: dict = Field(default_factory=dict)

    _lock: asyncio.Lock = PrivateAttr()
    _model: DecisionTreeClassifier = PrivateAttr()
    _imputer: SimpleImputer = PrivateAttr()
    _scaler: StandardScaler = PrivateAttr()

    def __init__(self, **data):
        """Initializes the Miner neuron with necessary machine learning models and configurations."""

        super().__init__(**data)
        self._lock = asyncio.Lock()

        base_path = os.path.expanduser("~/tensorprox/model") 
        self._model = joblib.load(os.path.join(base_path, "decision_tree.pkl"))
        self._imputer = joblib.load(os.path.join(base_path, "imputer.pkl"))
        self._scaler = joblib.load(os.path.join(base_path, "scaler.pkl"))

    async def forward(self, synapse: PingSynapse) -> PingSynapse:
        """
        Handles incoming PingSynapse messages and responds with the miner's machine configuration and credentials.

        Args:
            synapse (PingSynapse): The synapse message containing machine details and configurations.

        Returns:
            PingSynapse: The updated synapse message.
        """

        logger.debug(f"📧 Ping received from {synapse.dendrite.hotkey}, IP: {synapse.dendrite.ip}.")

        try:

            # Create new MachineConfig
            machine_config = MachineConfig(
                app_credentials=self.azure_creds, 
                vnet_name=self.network_config.get("VNET_NAME"),
                subnet_name=self.network_config.get("SUBNET_NAME"),
                vnet_address_space=self.network_config.get("VNET_ADDRESS_SPACE", "10.0.0.0/8"),
                subnet_address_prefix=self.network_config.get("SUBNET_ADDRESS_PREFIX", "10.0.0.0/24"),
                location = self.machines_config.get("LOCATION", "eastus"),
                tgens_size = self.machines_config.get("TGENS_SIZE", "Standard_B1ms"),
                king_size = self.machines_config.get("KING_SIZE", "Standard_B1ms"),
                num_tgens = self.machines_config.get("NUM_TGENS", 2),
            )
            
            # Respond with new PingSynapse 
            synapse.machine_availabilities = machine_config
            logger.debug(f"⏩ Forwarding Ping synapse with machine details to validator {synapse.dendrite.hotkey} : {synapse}.")
            return synapse

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in forward: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True
            return synapse

    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """
        Handles challenge requests, including firewall activation and deactivation based on the challenge state.

        Args:
            synapse (ChallengeSynapse): The received challenge synapse containing task details and state information.

        Returns:
            ChallengeSynapse: The same `synapse` object after processing the challenge.
        """

        try:
            # Extract challenge information from the synapse
            task = synapse.task
            state=synapse.state

            logger.debug(f"📧 Synapse received from {synapse.dendrite.hotkey}. Task : {task} | State : {state}.")

            if state == "GET_READY":
                interfaces = [f"gre-tgen-{i}" for i in range(min(len(self.traffic_generators),self.max_tgens))]
                if not self.firewall_active:
                    self.firewall_active = True
                    self.stop_firewall_event.clear()  # Reset stop event
                    # Start sniffing in a separate thread to avoid blocking
                    self.firewall_thread = Thread(target=self.run_packet_stream, args=(KING_OVERLAY_IP, interfaces))
                    self.firewall_thread.daemon = True  # Set the thread to daemon mode to allow termination
                    self.firewall_thread.start()
                    logger.info("🔥 Moat firewall activated.")
                else:
                    logger.info("💥 Moat firewall already activated.")
    
            elif state == "END_ROUND":

                if self.firewall_active:
                    self.firewall_active = False
                    self.stop_firewall_event.set()  # Signal firewall to stop
                    logger.info("🛑 Moat firewall deactivated.")
                else:
                    logger.info("💥 Moat firewall already deactivated.")

                logger.warning("🚨 Round finished, waiting for next one...")    

        except Exception as e:
            logger.exception(e)
            logger.error(f"Error in challenge handling: {e}")
            log_event(ErrorLoggingEvent(error=str(e)))
            if NEURON_STOP_ON_FORWARD_EXCEPTION:
                self.should_exit = True

        return synapse

    def is_allowed_batch(self, features):
        """
        Determines if a batch of packets should be allowed or blocked.

        Args:
            features (np.ndarray): A 1D NumPy array representing the extracted features of a batch of packets.

        Returns:
            bool: 
                - `False` if the batch should be **blocked** (prediction is 1 or 2).  
                - `True` if the batch should be **allowed** (prediction is -1 or 0).
            label_type: `UDP_FLOOD`, `TCP_SYN_FLOOD`, `BENIGN` or None
        """

        prediction = self.predict_sample(features)  # Get prediction
        label_type = None
        allowed = True

        if prediction == 1 :
            label_type = "UDP_FLOOD"
            allowed = False
        elif prediction == 2 :
            label_type = "TCP_SYN_FLOOD"
            allowed = False

        return allowed, label_type
    
    
    def run_packet_stream(self, destination_ip, iface):
        """
        Runs the firewall sniffing logic in an asynchronous event loop.

        Args:
            king_private_ip (str): The private IP address of the King node to forward packets to.
            iface (str, optional): The network interface to sniff packets from. Defaults to "eth0".
        """

        loop = asyncio.new_event_loop()  # Create a new event loop for the sniffing thread
        asyncio.set_event_loop(loop)  # Set the new loop as the current one for this thread
        
        # Ensure that the sniffer doesn't block the main process
        loop.create_task(self.sniff_packets_stream(destination_ip, iface, self.stop_firewall_event))
        loop.run_forever()  # Ensure the loop keeps running


    async def moat_forward_packet(self, packet, destination_ip, out_iface="gre-king"):
        """
        Forward the packet to King using raw socket and bind to `gre-king` interface.
        
        Args:
            packet (bytes): The raw IP packet to be forwarded.
            destination_ip (str): IP address of the King machine (should match GRE peer IP or overlay IP).
            out_iface (str): Interface to send packet from (default: gre-king).
        """
        try:
            # Open raw socket for IP
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # Bind to specific interface
            s.setsockopt(socket.SOL_SOCKET, 25, out_iface.encode())  # 25 = SO_BINDTODEVICE

            # Send the raw packet (includes full IP header)
            s.sendto(packet, (destination_ip, 0))

            s.close()
        except Exception as e:
            print(f"Forwarding failed: {e}")

    async def process_packet_stream(self, packet_data, destination_ip, iface):
        """
        Store packet and its protocol in the corresponding buffer for the given interface.
        
        Args:
            packet_data (bytes): The network packet data to store.
            destination_ip (str): The expected destination IP.
            iface (str): The interface name.
        """

        if len(packet_data) < 20:
            return

        ip_header = packet_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]

        if protocol not in (6, 17):
            return  # Ignore non-TCP and non-UDP packets

        # Convert the destination IP from binary to string format
        dest_ip = socket.inet_ntoa(iph[9])

        # Filter: Only process packets where the destination IP matches king_overlay_ip
        if dest_ip != destination_ip :
            return  # Ignore packets not originating from king_overlay_ip

        async with self._lock:
            self.packet_buffers[iface].append((packet_data, protocol))  # Store in the respective buffer


    def extract_batch_features(self, packet_batch):
        """
        Extract features from a batch of packets.
        
        Args:
            packet_batch (bytes): The network packet buffer to process.

        Returns:
            np.array : output data sample with model input features.
        """

        if not packet_batch:
            return None

        # Initialize flow statistics
        flow_stats = defaultdict(lambda: {
            "tcp_syn_fwd_count": 0, "tcp_syn_bwd_count": 0,
            "fwd_packet_count": 0, "bwd_packet_count": 0,
            "unique_udp_source_ports": set(), "unique_udp_dest_ports": set(),
            "total_fwd_pkt_size": 0, "total_bwd_pkt_size": 0,
            "flow_packets_per_sec": 0, "flow_bytes_per_sec": 0,
            "source_ip_entropy": 0, "dest_port_entropy": 0
        })

        for packet_data, protocol in packet_batch:
            if len(packet_data) < 20:
                continue

            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[0:20])
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            if protocol not in (6, 17):  # Only process TCP/UDP packets
                continue

            key = (src_ip, dest_ip)
            entry = flow_stats[key]
            entry["fwd_packet_count"] += 1

            if protocol == 6:  # TCP
                if len(packet_data) < 40:
                    continue  # Not enough for full TCP header
                tcp_header = struct.unpack('!HHLLBBHHH', packet_data[20:40])
                flags = tcp_header[5]
                pkt_size = len(packet_data)
                entry["total_fwd_pkt_size"] += pkt_size

                if flags & 0x02:  # SYN flag
                    entry["tcp_syn_fwd_count"] += 1

            elif protocol == 17:  # UDP
                if len(packet_data) < 28:
                    continue  # Not enough for UDP header
                udp_header = struct.unpack('!HHHH', packet_data[20:28])
                src_port, dest_port = udp_header[0], udp_header[1]
                pkt_size = len(packet_data)
                entry["total_fwd_pkt_size"] += pkt_size

                entry["unique_udp_source_ports"].add(src_port)
                entry["unique_udp_dest_ports"].add(dest_port)

        # Compute aggregated feature values
        tcp_syn_flag_ratio = (
            sum(e["tcp_syn_fwd_count"] + e["tcp_syn_bwd_count"] for e in flow_stats.values()) /
            (sum(e["fwd_packet_count"] + e["bwd_packet_count"] for e in flow_stats.values()) + 1e-6)
        )

        udp_port_entropy = sum(len(e["unique_udp_source_ports"]) * len(e["unique_udp_dest_ports"]) for e in flow_stats.values())

        avg_pkt_size = (
            sum(e["total_fwd_pkt_size"] + e["total_bwd_pkt_size"] for e in flow_stats.values()) /
            (2 * len(flow_stats) + 1e-6)
        )

        flow_density = sum(
            e["flow_packets_per_sec"] / (e["flow_bytes_per_sec"] + 1e-6)
            for e in flow_stats.values()
        )

        ip_entropy = sum(
            e["source_ip_entropy"] + e["dest_port_entropy"]
            for e in flow_stats.values()
        )

        return np.array([tcp_syn_flag_ratio, udp_port_entropy, avg_pkt_size, flow_density, ip_entropy])
    

    async def batch_processing_loop(self, iface):
        """
        Process the buffered packets every `batch_interval` seconds.
        """

        try:
            while not self.stop_firewall_event.is_set():
                await asyncio.sleep(self.batch_interval)  # Wait for batch interval

                async with self._lock:
                    if not self.packet_buffers[iface]:
                        continue  # No packets to process

                    batch = self.packet_buffers[iface][:]
                    self.packet_buffers[iface].clear()

                # Extract batch-level features
                features = self.extract_batch_features(batch)

                # Predict whether batch is allowed
                is_allowed, label_type = self.is_allowed_batch(features)  
                
                # Forward or block the packets based on decision
                if is_allowed:
                    logger.info(f"Allowing batch of {len(batch)} packets on interface {iface}...")
                    for packet_data, protocol in batch:  # Extract packet and protocol
                        await self.moat_forward_packet(packet_data, KING_OVERLAY_IP)
                else:
                    logger.info(f"Blocked {len(batch)} packets on interface {iface} : {label_type} detected !")
                
        except Exception as e:
            logger.error(f"Error in batch processing on interface {iface}: {e}")


    async def sniff_packets_stream(self, destination_ip, ifaces, stop_event=None):
        """
        Sniffs packets on multiple interfaces asynchronously.

        Args:
            destination_ip (str): The destination IP to filter packets.
            ifaces (list): List of network interfaces to sniff packets on.
        """

        tasks = [self._sniff_on_interface(destination_ip, iface, stop_event) for iface in ifaces]
        await asyncio.gather(*tasks)  # Run sniffing tasks concurrently

    async def _sniff_on_interface(self, destination_ip, iface, stop_event):
        """
        Sniffs packets and adds them to the buffer.
        
        Args:
            king_private_ip (str): The private IP of the King for batch packet forwarding.  
            iface (str, optional): The network interface to sniff packets on. Defaults to 'eth0'.
            stop_event (asyncio.Event, optional): An event to signal stopping the sniffing loop. 
                If provided, the function will exit when stop_event is set. Defaults to None.
        """
        
        logger.info(f"Sniffing packets going to {destination_ip} on interface {iface}")

        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((iface, 0))
        raw_socket.setblocking(False)

        # Start batch processing immediately and ensure it's non-blocking
        asyncio.create_task(self.batch_processing_loop(iface))  # Create task to run concurrently

        while not stop_event.is_set():
            ready, _, _ = select.select([raw_socket], [], [], 1)  # 1s timeout
            if ready:
                packet_data = raw_socket.recv(65535)
                await self.process_packet_stream(packet_data, destination_ip, iface)

            await asyncio.sleep(0)  # Yield control back to the event loop to run other tasks (like batch_processing_loop)

        logger.info(f"Stopping packet sniffing on interface {iface}...")
        raw_socket.close()


    def predict_sample(self, sample_data):
        """
        Predicts whether a batch of packets should be allowed or blocked.
        
        Args:
            sample_data (np.ndarray): A 1D NumPy array representing the extracted features of a batch of packets.
        
        Returns:
            int | None: The predicted class label, which can be one of [-1, 0, 1, 2].
                - -1: UNKNOWN
                -  0: BENIGN
                -  1: UDP_FLOOD
                -  2: TCP_SYN_FLOOD
                
                Returns `None` if the prediction fails.
        """

        # Impute missing values
        sample_data_imputed = self._imputer.transform([sample_data])

        # Standardize the sample
        sample_data_scaled =self._scaler.transform(sample_data_imputed)

        # Predict using the model
        prediction = self._model.predict(sample_data_scaled)

        return prediction[0] if isinstance(prediction, np.ndarray) and len(prediction) > 0 else None

        
def run_gre_setup(num_tgens):

    logger.info("Running GRE Setup...")
    
    try:
        # Performing GRE Setup before starting
        tgen_private_ips = [f"10.0.0.{6 + i}" for i in range(num_tgens)]
        gre = GRESetup(node_type="moat", private_ip="10.0.0.4", interface="eth0")
        success = gre.moat(king_private_ip="10.0.0.5", traffic_gen_ips=tgen_private_ips)
        if success :
            logger.info("GRE setup successfully done.")
        else :
            logger.info("GRE setup failed.")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error during GRE Setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    logger.info("Miner Instance started.")

    # Load Azure credentials, VM config, and network config
    azure_creds = load_azure_credentials()
    machines_config = load_vm_config()
    network_config = load_network_config()

    num_tgens = int(os.environ.get("NUM_TGENS", 2))
    run_gre_setup(num_tgens)

    with Miner(azure_creds=azure_creds, machines_config=machines_config, network_config=network_config) as miner:
        while not miner.should_exit:
            miner.log_status()
            time.sleep(5)
        logger.warning("Ending miner...")