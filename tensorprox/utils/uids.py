import numpy as np
from typing import Literal
import random
from tensorprox.settings import settings
from loguru import logger
import re

def check_uid_availability(
    uid: int,
    coldkeys: set = None,
    ips: set = None,
) -> bool:
    """Check if uid is available. The UID should be available if it is serving and has less than vpermit_tao_limit stake
    Args:
        metagraph (:obj: bt.metagraph.Metagraph): Metagraph object
        uid (int): uid to be checked
        vpermit_tao_limit (int): Validator permit tao limit
        coldkeys (set): Set of coldkeys to exclude
        ips (set): Set of ips to exclude
    Returns:
        bool: True if uid is available, False otherwise
    """
    metagraph = settings.METAGRAPH
    # Filter non serving axons.
    if not metagraph.axons[uid].is_serving:
        logger.debug(f"uid: {uid} is not serving")
        return False

    # Filter validator permit >  stake.
    if metagraph.validator_permit[uid] and metagraph.S[uid] > settings.NEURON_VPERMIT_TAO_LIMIT:
        logger.debug(f"uid: {uid} has vpermit and stake ({metagraph.S[uid]}) > {settings.NEURON_VPERMIT_TAO_LIMIT}")
        return False

    if coldkeys and metagraph.axons[uid].coldkey in coldkeys:
        return False

    if ips and metagraph.axons[uid].ip in ips:
        return False

    # Available otherwise.
    return True


def get_random_uids(k: int | None = 10**6, exclude: list[int] = None, own_uid: int | None = None) -> np.ndarray:
    """Returns k available random uids from the metagraph.
    Args:
        k (int): Number of uids to return.
        exclude (List[int]): List of uids to exclude from the random sampling.
    Returns:
        uids (torch.LongTensor): Randomly sampled available uids.
    Notes:
        If `k` is larger than the number of available `uids`, set `k` to the number of available `uids`.
    """

    candidate_uids = []
    coldkeys = set()
    ips = set()
    for uid in range(settings.METAGRAPH.n.item()):
        if uid == own_uid:
            continue

        uid_is_available = check_uid_availability(
            uid,
            coldkeys,
            ips,
        )
        if not uid_is_available:
            continue

        if settings.NEURON_QUERY_UNIQUE_COLDKEYS:
            coldkeys.add(settings.METAGRAPH.axons[uid].coldkey)

        if settings.NEURON_QUERY_UNIQUE_IPS:
            ips.add(settings.METAGRAPH.axons[uid].ip)

        if exclude is None or uid not in exclude:
            candidate_uids.append(uid)

    # Check if candidate_uids contain enough for querying, if not grab all avaliable uids
    if 0 < len(candidate_uids) < k:
        logger.warning(
            f"Requested {k} uids but only {len(candidate_uids)} were available. To disable this warning reduce the sample size (--neuron.sample_size)"
        )
        return np.array(candidate_uids).astype(int)
    elif len(candidate_uids) >= k:
        return np.array(random.sample(candidate_uids, k)).astype(int)
    else:
        raise ValueError(f"No eligible uids were found. Cannot return {k} uids")


def get_top_incentive_uids(k: int, vpermit_tao_limit: int) -> np.ndarray:
    miners_uids = list(map(int, filter(lambda uid: check_uid_availability(uid), settings.METAGRAPH.uids)))

    # Builds a dictionary of uids and their corresponding incentives.
    all_miners_incentives = {
        "miners_uids": miners_uids,
        "incentives": list(map(lambda uid: settings.METAGRAPH.I[uid], miners_uids)),
    }

    # Zip the uids and their corresponding incentives into a list of tuples.
    uid_incentive_pairs = list(zip(all_miners_incentives["miners_uids"], all_miners_incentives["incentives"]))

    # Sort the list of tuples by the incentive value in descending order.
    uid_incentive_pairs_sorted = sorted(uid_incentive_pairs, key=lambda x: x[1], reverse=True)

    # Extract the top uids.
    top_k_uids = [uid for uid, incentive in uid_incentive_pairs_sorted[:k]]

    return np.array(top_k_uids)


def get_uids(
    sampling_mode: Literal["random", "top_incentive", "all"],
    k: int | None = None,
    exclude: list[int] = [],
    own_uid: int | None = None,
) -> np.ndarray:

    if sampling_mode == "random":
        return get_random_uids(k=k, exclude=exclude or [])
    if sampling_mode == "top_incentive":
        vpermit_tao_limit = settings.NEURON_VPERMIT_TAO_LIMIT
        return get_top_incentive_uids(k=k, vpermit_tao_limit=vpermit_tao_limit, own_uid=own_uid)
    if sampling_mode == "all":
        return [uid for uid in settings.METAGRAPH.uids if (uid != own_uid and check_uid_availability(uid))]

def extract_axons_ips(uids: list[int] = [])  -> tuple[list, list]:
    axons = [settings.METAGRAPH.axons[uid] for uid in uids]
    # Regular expression to match an IP address pattern
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    # List comprehension with conditional extraction of IP addresses
    ips = [
        match.group(1) if (match := ip_pattern.search(axon.ip_str())) else "0.0.0.0"
        for axon in axons
    ]
    return axons, ips
