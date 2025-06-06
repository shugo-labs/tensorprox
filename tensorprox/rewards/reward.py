"""
================================================================================

TensorProx Challenge Reward Computation Module

This module defines classes and functions for computing rewards on the TensorProx 
subnetwork. It processes packet capture (pcap) files to analyze
network traffic and assigns rewards based on attack detection accuracy, false
positive rates, and the volume of packets processed.

Key Components:
- `ChallengeRewardEvent`: Represents a reward event in a challenge, encapsulating
  reward values and associated user IDs.
- `BatchRewardOutput`: Represents the output of a batch reward computation,
  containing an array of computed reward values.
- `ChallengeRewardModel`: Provides methods to extract labeled packet counts from
  pcap files and calculate rewards based on network traffic analysis.
- `BaseRewardConfig`: Configuration class for setting up the reward model and
  default labels, offering a method to apply the reward model to a list of user IDs.

Dependencies:
- `numpy`: For numerical operations and array handling.
- `pydantic`: For data validation and settings management.
- `tensorprox`: Specifically, the `PacketAnalyzer` from `tensorprox.rewards.pcap`
  for analyzing pcap files.
- `os`: For interacting with the operating system, particularly in handling file
  paths.
- `logging`: For structured logging and debugging.

License:
This software is licensed under the Creative Commons Attribution-NonCommercial
4.0 International (CC BY-NC 4.0). You are free to use, share, and modify the code
for non-commercial purposes only.

Commercial Usage:
The only authorized commercial use of this software is for mining or validating
within the TensorProx subnet. For any other commercial licensing requests, please
contact Shugo LTD.

See the full license terms here: https://creativecommons.org/licenses/by-nc/4.0/

Author: Shugo LTD
Version: 0.1.0

================================================================================
"""

import numpy as np
from typing import ClassVar, Dict, List, Union
from tensorprox.base.dendrite import DendriteResponseEvent
from pydantic import BaseModel, ConfigDict
import logging
import math
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

MTU_GRE=1465

class ChallengeRewardEvent(BaseModel):
    """
    Represents a detailed reward event resulting from a challenge evaluation.

    Attributes:
        response (DendriteResponseEvent): The response event returned by the dendrite during challenge handling.
        rewards (list[float]): Total reward values computed for each UID.
        bdr (list[float]): Block-Drop Ratio values for each UID.
        ama (list[float]): Allow-Miss Accuracy values for each UID.
        sps (list[float]): Samples per second processed for each UID.
        rtc (list[float]): Real-Time Constraint (or similar performance metric) values for each UID.
        rtt_value (list[float]): Round-trip time values recorded for each UID.
        lf (list[float]): Latency factor or final penalty scores for each UID.
        uids (list[int]): User IDs corresponding to each reward entry.
    """
    response: DendriteResponseEvent
    rewards: list[float]
    bdr: list[float]
    ama: list[float]
    sps: list[float]
    rtc: list[float]
    vps: list[float]
    rtt_value: list[float]
    lf: list[float]
    ttl_attacks_sent: list[int]
    ttl_packets_sent: list[int]
    best_miner_score: float
    best_bandwidth: float
    best_capacity: float
    best_purity: float
    best_bdr: float
    global_bandwidth: float
    global_capacity: float
    global_purity: float
    global_bdr: float
    uids: list[int]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def asdict(self) -> dict:
        """
        Convert the ChallengeRewardEvent instance to a dictionary.

        Returns:
            dict: A dictionary representation of the instance with keys 'response_event', 'rewards' and 'uids'.
        """
        return {
            "response_event": self.response,
            "rewards": self.rewards,
            "bdr": self.bdr,
            "ama": self.ama,
            "sps": self.sps,
            "rtc": self.rtc,
            "vps": self.vps,
            "rtt_value": self.rtt_value,
            "lf": self.lf,
            "ttl_attacks_sent": self.ttl_attacks_sent,
            "ttl_packets_sent": self.ttl_packets_sent,
            "best_miner_score": self.best_miner_score,
            "best_bandwidth": self.best_bandwidth,
            "best_capacity": self.best_capacity,
            "best_purity": self.best_purity,
            "best_bdr": self.best_bdr,
            "global_bandwidth": self.global_bandwidth,
            "global_capacity": self.global_capacity,
            "global_purity": self.global_purity,
            "global_bdr": self.global_bdr,
            "uids": self.uids,
        }

class BatchRewardOutput(BaseModel):
    """
    Represents the output of a batch reward computation.

    Attributes:
        rewards (np.ndarray): An array of computed reward values.
    """
    rewards: np.ndarray
    bdr: np.ndarray
    ama: np.ndarray
    sps: np.ndarray
    rtc: np.ndarray
    vps: np.ndarray
    rtt_value: np.ndarray
    lf: np.ndarray 
    ttl_attacks_sent: np.ndarray
    ttl_packets_sent: np.ndarray
    best_miner_score: float
    best_bandwidth: float
    best_capacity: float
    best_purity: float
    best_bdr: float
    global_bandwidth: float
    global_capacity: float
    global_purity: float
    global_bdr: float
    model_config = ConfigDict(arbitrary_types_allowed=True)

class ChallengeRewardModel(BaseModel):
    
    @staticmethod
    def normalize_rtt(input, exponent=4, scale_factor=10):
        # Use max to avoid negative logs causing unexpected results
        return 1 / (1 + math.log(input + 1)**exponent / scale_factor)
    
    @staticmethod
    def exponential_ratio(ratio):
        return (math.exp(ratio**2) - 1) / (math.exp(1) - 1)

    # Helper function to calculate total attack and benign traffic
    @staticmethod
    def calculate_traffic_counts(counts, attack_labels):
        total_attacks = sum(counts.get(label, 0) for label in attack_labels)
        total_benign = counts.get("BENIGN", 0)
        return total_attacks, total_benign
        
    def reward(self, response_event: DendriteResponseEvent, uids: List[int], label_hashes: Dict) -> BatchRewardOutput:
        """
        Calculate rewards for a batch of users based on their packet capture data.

        Args:
            response_event (DendriteResponseEvent): Contains challenge results.
            uids (List[int]): A list of user IDs.
            label_hashes (Dict): Mapping of labels used in the challenge.

        Returns:
            BatchRewardOutput: Rewards for each UID.
        """


        #Initialize metrics lists
        scores = []
        bdr, ama, sps, rtc, vps, lf, ttl_packets_sent, ttl_attacks_sent = [[0]*settings.SUBNET_NEURON_SIZE for _ in range(8)]
        rtt_value = [1e9]*settings.SUBNET_NEURON_SIZE


        # Track max throughput for normalization
        max_total_packets_sent = 0
        max_reaching_benign = 0
        global_reaching_benign = 0
        global_reaching_attacks = 0
        global_reaching_packets = 0
        global_packets_sent = 0
        global_benign_sent = 0
        packet_data = {}

        for uid in uids:
            label_counts_results = response_event.challenge_status_by_uid[uid]["label_counts_results"]
            default_count = {label: 0 for label in label_hashes.keys()}

            king_counts = next((counts for machine, counts, _ in label_counts_results if machine == "king"), default_count)
            tgen_entries = [(machine, counts, avg_rtt) for machine, counts, avg_rtt in label_counts_results if machine.startswith("tgen-")]

            # If all counts are the default (i.e., zero), skip this user
            if all(all(value == 0 for value in counts.values()) for _, counts, _ in tgen_entries) and \
            all(value == 0 for value in king_counts.values()):
                continue

            # Attack labels
            attack_labels = ["TCP_SYN_FLOOD", "UDP_FLOOD"]

            # Aggregate total attacks/benign from all tgens
            total_attacks_sent = 0
            total_benign_sent = 0
            rtt_list = []

            # Calculate total attacks and benign packets sent from all tgens
            for _, counts, avg_rtt in tgen_entries:
                rtt_list.append(avg_rtt)
                attacks, benign = self.calculate_traffic_counts(counts, attack_labels)
                total_attacks_sent += attacks
                total_benign_sent += benign

            # Average RTT across tgens
            valid_rtt_list = [rtt for rtt in rtt_list if rtt is not None]
            rtt = max(sum(valid_rtt_list) / len(valid_rtt_list), 0) if valid_rtt_list else 1e9
            
            total_packets_sent = total_attacks_sent + total_benign_sent
            total_reaching_attacks = sum(king_counts.get(label, 0) for label in attack_labels) # total attacks reaching King
            total_reaching_benign = king_counts.get("BENIGN", 0) # total benign reaching King
            total_reaching_packets = total_reaching_benign + total_reaching_attacks # total packets reaching King
            max_reaching_benign = max(max_reaching_benign, total_reaching_benign) # max benign reaching for this round across all miners 
            max_total_packets_sent = max(max_total_packets_sent, total_packets_sent)
            global_reaching_benign += total_reaching_benign
            global_reaching_packets += total_reaching_benign + total_reaching_attacks
            global_packets_sent += total_packets_sent
            global_benign_sent += total_benign_sent
            
            packet_data[uid] = {
                "total_attacks_sent": total_attacks_sent,
                "total_benign_sent": total_benign_sent,
                "total_packets_sent": total_packets_sent,
                "total_reaching_attacks": total_reaching_attacks,
                "total_reaching_benign": total_reaching_benign,
                "total_reaching_packets": total_reaching_packets,
                "rtt": rtt,
            }

            # logging.info(f"PACKET DATA : {packet_data}")

        global_bdr = min(max(global_reaching_benign / global_benign_sent, 0), 1) if global_benign_sent > 0 else 0
        global_purity = min(max(global_reaching_benign / global_reaching_packets, 0), 1) if global_reaching_packets > 0 else 0
        global_capacity = (global_reaching_benign / CHALLENGE_DURATION) * MTU_GRE * 8 / 1e6 if CHALLENGE_DURATION > 0 else 0
        global_bandwidth = (global_packets_sent / CHALLENGE_DURATION) * MTU_GRE * 8 / 1e6 if CHALLENGE_DURATION > 0 else 0

        # Calculate rewards and store metrics
        best_miner_score = -float('inf')
        best_miner_uid = None

        for uid in uids:
            if uid not in packet_data:
                scores.append(0.0)
                continue

            data = packet_data[uid]
            total_attacks_sent = data["total_attacks_sent"]
            total_benign_sent = data["total_benign_sent"]
            total_packets_sent = data["total_packets_sent"]
            total_reaching_attacks = data["total_reaching_attacks"]
            total_reaching_benign = data["total_reaching_benign"]
            total_reaching_packets = data["total_reaching_packets"]
            rtt = data["rtt"]

            # Benign Delivery Rate
            BDR = min(max(total_reaching_benign / total_benign_sent, 0), 1) if total_benign_sent > 0 else 0
            
            # Attack Penalty Score
            AMA = min(max(1 - (total_reaching_attacks / total_attacks_sent), 0), 1) if total_attacks_sent > 0 else 1

            # Selective Processing Score
            SPS = min(max(total_reaching_benign / total_reaching_packets, 0), 1) if total_reaching_packets > 0 else 0

            # Relative Throughput Capacity (benign only)
            RTC =  min(max(total_reaching_benign / max_reaching_benign, 0), 1) if max_reaching_benign > 0 else 0

            # Volume Processing Score (normalized to 0-1)
            VPS = min(max(total_packets_sent / max_total_packets_sent, 0), 1) if max_total_packets_sent > 0 else 0
        
            # Latency Factor
            LF = self.normalize_rtt(rtt)

            # Store all metrics for reporting
            for arr, val in zip(
                [bdr, ama, sps, rtc, vps, lf, rtt_value, vps, ttl_attacks_sent, ttl_packets_sent],
                [BDR, AMA, SPS, RTC, VPS, LF, rtt, VPS, total_attacks_sent, total_packets_sent]
            ):
                arr[uid] = val

            # Base weights (add up to 1)
            alpha = 0.25  # Accuracy component
            beta = 0.25   # Efficiency component
            gamma = 0.25  # Throughput component
            delta = 0.25  # Latency component

            volume_weight = 0.2 # Volume weight

            # Accuracy component (AMA & BDR)
            accuracy = self.exponential_ratio(BDR * AMA)
    
            # Efficiency component (combination of SPS & RTC with bandwidth bonus)
            efficiency = self.exponential_ratio(RTC * SPS)

            # Throughput component (combination of VPS & RTC with bandwidth bonus)
            throughput = self.exponential_ratio(RTC * VPS)
                        
            # Latency component (LF with slight tolerance for higher volumes)
            # For high volume, we're slightly more tolerant of latency
            latency_tolerance = VPS * volume_weight * 0.5 # 0 to 0.1 range
            latency = min(1.0, LF + latency_tolerance) * (BDR * AMA) # Ensure latency is coupled with accuracy
                        
            # logging.info(f"BDR for UID {uid} : {BDR}")
            # logging.info(f"AMA for UID {uid} : {AMA}")
            # logging.info(f"SPS for UID {uid} : {SPS}")
            # logging.info(f"RTC for UID {uid} : {RTC}")
            # logging.info(f"VPS for UID {uid} : {VPS}")
            # logging.info(f"Average RTT for UID {uid} : {rtt} ms")
            # logging.info(f"LF for UID {uid} : {LF}")
                
            # Final reward calculation
            reward = alpha * accuracy + beta * efficiency + gamma * throughput + delta * latency
         
            scores.append(reward)

            # Update best miner score if this UID has the highest reward
            if reward > best_miner_score:
                best_miner_score = reward
                best_miner_uid = uid

        # Get the best miner's specific metrics
        if best_miner_uid is not None:
            best_miner_data = packet_data[best_miner_uid]
            best_bdr = min(max(best_miner_data["total_reaching_benign"]/best_miner_data["total_benign_sent"], 0), 1) if best_miner_data["total_benign_sent"] > 0 else 0
            best_purity = min(max(best_miner_data["total_reaching_benign"] / best_miner_data["total_reaching_packets"], 0), 1) if best_miner_data["total_reaching_packets"] > 0 else 0
            best_bandwidth = (best_miner_data["total_packets_sent"] / CHALLENGE_DURATION) * MTU_GRE * 8 / 1e6 if CHALLENGE_DURATION > 0 else 0
            best_capacity = (best_miner_data["total_reaching_benign"] / CHALLENGE_DURATION) * MTU_GRE * 8 / 1e6 if CHALLENGE_DURATION > 0 else 0
        else:
            best_bdr, best_purity, best_bandwidth, best_capacity = 0, 0, 0, 0

        return BatchRewardOutput(
            rewards=np.array(scores),
            bdr=np.array(bdr),
            ama=np.array(ama),
            sps=np.array(sps),
            rtc=np.array(rtc),
            vps=np.array(vps),
            rtt_value=np.array(rtt_value),
            lf=np.array(lf),
            ttl_attacks_sent=np.array(ttl_attacks_sent),
            ttl_packets_sent=np.array(ttl_packets_sent),
            best_miner_score=best_miner_score,
            best_bandwidth=best_bandwidth,
            best_capacity=best_capacity,
            best_purity=best_purity,
            best_bdr=best_bdr,
            global_bandwidth=global_bandwidth,
            global_capacity=global_capacity,
            global_purity=global_purity,
            global_bdr=global_bdr
        )

class BaseRewardConfig(BaseModel):
    """
    Configuration class for setting up the reward model and default labels.

    Attributes:
        default_labels (ClassVar[dict]): Default mapping of labels.
        reward_model (ClassVar[ChallengeRewardModel]): An instance of the reward model.
    """

    reward_model: ClassVar[ChallengeRewardModel] = ChallengeRewardModel()

    @classmethod
    def apply(
        cls,
        response_event: DendriteResponseEvent,
        uids: list[int],
        label_hashes: dict,
    ) -> ChallengeRewardEvent:
        """
        Apply the reward model to a list of user IDs with optional custom labels.

        Args:
            uids (list[int]): A list of user IDs.
            label_hashes (dict): A custom dictionary mapping original labels to encrypted labels.

        Returns:
            ChallengeRewardEvent: An event containing the computed rewards and associated user IDs.
        """

        # Get the reward output
        batch_rewards_output = cls.reward_model.reward(response_event, uids, label_hashes)

        # Return the ChallengeRewardEvent using the BatchRewardOutput
        return ChallengeRewardEvent(
            response=response_event,
            rewards=batch_rewards_output.rewards.tolist(),
            bdr=batch_rewards_output.bdr.tolist(),
            ama=batch_rewards_output.ama.tolist(),
            sps=batch_rewards_output.sps.tolist(),
            rtc=batch_rewards_output.rtc.tolist(),
            vps=batch_rewards_output.vps.tolist(),
            rtt_value=batch_rewards_output.rtt_value.tolist(),                        
            lf=batch_rewards_output.lf.tolist(), 
            ttl_attacks_sent = batch_rewards_output.ttl_attacks_sent.tolist(),
            ttl_packets_sent = batch_rewards_output.ttl_packets_sent.tolist(),
            best_miner_score=batch_rewards_output.best_miner_score,
            best_bandwidth=batch_rewards_output.best_bandwidth,
            best_capacity=batch_rewards_output.best_capacity,
            best_purity = batch_rewards_output.best_purity,  
            best_bdr = batch_rewards_output.best_bdr, 
            global_bandwidth=batch_rewards_output.global_bandwidth,
            global_capacity=batch_rewards_output.global_capacity,
            global_purity = batch_rewards_output.global_purity,    
            global_bdr=batch_rewards_output.global_bdr,  
            uids=uids,
        )
