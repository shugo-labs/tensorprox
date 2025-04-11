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

class ChallengeRewardEvent(BaseModel):
    """
    Represents a detailed reward event resulting from a challenge evaluation.

    Attributes:
        response (DendriteResponseEvent): The response event returned by the dendrite during challenge handling.
        rewards (list[float]): Total reward values computed for each UID.
        bdr (list[float]): Block-Drop Ratio values for each UID.
        ama (list[float]): Allow-Miss Accuracy values for each UID.
        sps (list[float]): Samples per second processed for each UID.
        exp_bdr (list[float]): Expected Block-Drop Ratio used as a reward signal for each UID.
        exp_ama (list[float]): Expected Allow-Miss Accuracy used as a reward signal for each UID.
        exp_sps (list[float]): Expected Samples per second used as a reward signal for each UID.
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
    exp_bdr: list[float]
    exp_ama: list[float]
    exp_sps: list[float]
    rtc: list[float]
    vps: list[float]
    rtt_value: list[float]
    lf: list[float]
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
            "exp_bdr": self.exp_bdr,
            "exp_ama": self.exp_ama,
            "exp_sps": self.exp_sps,
            "rtc": self.rtc,
            "vps": self.vps,
            "rtt_value": self.rtt_value,
            "lf": self.lf,
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
    exp_bdr: np.ndarray
    exp_ama: np.ndarray
    exp_sps: np.ndarray
    rtc: np.ndarray
    vps: np.ndarray
    rtt_value: np.ndarray
    lf: np.ndarray 
    model_config = ConfigDict(arbitrary_types_allowed=True)

class ChallengeRewardModel(BaseModel):
    
    @staticmethod
    def normalize_rtt(input, exponent=3, scale_factor=10):
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
        bdr, ama, sps, exp_bdr, exp_ama, exp_sps, rtc, vps, lf = [[0]*len(uids) for _ in range(9)]
        rtt_value = [1e9]*len(uids)


        # Track max throughput for normalization
        max_total_packets_sent = 0
        max_reaching_benign = 0
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
            rtt = max(sum(rtt_list) / len(rtt_list), 0) if rtt_list else 1e9

            total_packets_sent = total_attacks_sent + total_benign_sent
            total_reaching_attacks = sum(king_counts.get(label, 0) for label in attack_labels) # total attacks reaching King
            total_reaching_benign = king_counts.get("BENIGN", 0) # total benign reaching King
            total_reaching_packets = total_reaching_benign + total_reaching_attacks # total packets reaching King
            max_reaching_benign = max(max_reaching_benign, total_reaching_benign) # max benign reaching for this round across all miners 
            max_total_packets_sent = max(max_total_packets_sent, total_packets_sent)

            packet_data[uid] = {
                "total_attacks_sent": total_attacks_sent,
                "total_benign_sent": total_benign_sent,
                "total_packets_sent": total_packets_sent,
                "total_reaching_attacks": total_reaching_attacks,
                "total_reaching_benign": total_reaching_benign,
                "total_reaching_packets": total_reaching_packets,
                "rtt": rtt
            }

            logging.info(f"PACKET DATA : {packet_data}")

        for uid in uids:
            if uid not in packet_data:
                scores.append(0.0)
                continue

            data = packet_data[uid]
            total_attacks_sent = data["total_attacks_sent"]
            total_benign_sent = data["total_benign_sent"]
            total_reaching_attacks = data["total_reaching_attacks"]
            total_reaching_benign = data["total_reaching_benign"]
            total_reaching_packets = data["total_reaching_packets"]
            rtt = data["rtt"]

            # Benign Delivery Rate
            BDR = total_reaching_benign / total_benign_sent if total_benign_sent > 0 else 0
            reward_BDR = self.exponential_ratio(BDR)

            # Attack Penalty Score
            AMA = 1 - (total_reaching_attacks / total_attacks_sent) if total_attacks_sent > 0 else 1
            reward_AMA = self.exponential_ratio(AMA)

            # Selective Processing Score
            SPS = total_reaching_benign / total_reaching_packets if total_reaching_packets > 0 else 0
            reward_SPS = self.exponential_ratio(SPS)

            # Relative Throughput Capacity (benign only)
            RTC = total_reaching_benign / max_reaching_benign if max_reaching_benign > 0 else 0

            # Volume Processing Score (normalized to 0-1)
            VPS = total_packets_sent / max_total_packets_sent if max_total_packets_sent > 0 else 0
        
            # Latency Factor
            LF = self.normalize_rtt(rtt)

            # Store all metrics for reporting
            for arr, val in zip(
                [bdr, ama, sps, exp_bdr, exp_ama, exp_sps, rtc, vps, lf, rtt_value, vps],
                [BDR, AMA, SPS, reward_BDR, reward_AMA, reward_SPS, RTC, VPS, LF, rtt, VPS]
            ):
                arr[uid] = val

            # Base weights (add up to 1)
            alpha = 0.25  # Accuracy component
            beta = 0.25   # Efficiency component
            gamma = 0.25  # Throughput component
            delta = 0.25  # Latency component
            
            # Volume weight - determines how much to consider volume in scoring
            volume_weight = 0.2
            
            # Accuracy component (AMA & BDR)
            accuracy = (reward_BDR * 0.5) + (reward_AMA * 0.5)
            
            # Efficiency component (SPS)
            # Scale up SPS importance linearly with volume, but cap at max 2x importance
            efficiency_boost = 1 + (VPS * volume_weight)  # 1.0 to 1.2 scaling
            efficiency = min(1.0, reward_SPS * efficiency_boost)
            
            # Throughput component (combination of RTC and VPS)
            # Higher volume gets more weight in throughput score
            throughput = (RTC * (1 - volume_weight)) + (VPS * volume_weight)
            
            # Latency component (LF with slight tolerance for higher volumes)
            # For high volume, we're slightly more tolerant of latency
            latency_tolerance = VPS * volume_weight * 0.5  # 0 to 0.1 range
            latency = min(1.0, LF + latency_tolerance)
                        
            logging.info(f"BDR for UID {uid} : {BDR}")
            logging.info(f"AMA for UID {uid} : {AMA}")
            logging.info(f"SPS for UID {uid} : {SPS}")
            logging.info(f"RTC for UID {uid} : {RTC}")
            logging.info(f"VPS for UID {uid} : {VPS}")
            logging.info(f"Average RTT for UID {uid} : {rtt} ms")
            logging.info(f"LF for UID {uid} : {LF}")
                
            # Final reward calculation
            reward = alpha * accuracy + beta * efficiency + gamma * throughput + delta * latency
         
            scores.append(reward)

        return BatchRewardOutput(
            rewards=np.array(scores),
            bdr=np.array(bdr),
            ama=np.array(ama),
            sps=np.array(sps),
            exp_bdr=np.array(exp_bdr),
            exp_ama=np.array(exp_ama),
            exp_sps=np.array(exp_sps),
            rtc=np.array(rtc),
            vps=np.array(vps),
            rtt_value=np.array(rtt_value),
            lf=np.array(lf)
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
            exp_bdr=batch_rewards_output.exp_bdr.tolist(),
            exp_ama=batch_rewards_output.exp_ama.tolist(),
            exp_sps=batch_rewards_output.exp_sps.tolist(),
            rtc=batch_rewards_output.rtc.tolist(),
            vps=batch_rewards_output.vps.tolist(),
            rtt_value=batch_rewards_output.rtt_value.tolist(),                        
            lf=batch_rewards_output.lf.tolist(),                        
            uids=uids,
        )
