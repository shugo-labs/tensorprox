from tensorprox.rewards.reward import ChallengeRewardEvent

# Define shared mutable globals
reward_events: list[ChallengeRewardEvent] = []
BURN_UID = 0
BURN_WEIGHT = 1
BAG_UID = 10