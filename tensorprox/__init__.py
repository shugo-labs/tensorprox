import os

def _version_to_int(version_str: str) -> int:
    version_split = version_str.split(".") + ["0", "0"]
    major = int(version_split[0])
    minor = int(version_split[1])
    patch = int(version_split[2])
    return (10000 * major) + (100 * minor) + patch

#Release version
__version__ = "0.1.1" 
__spec_version__ = _version_to_int(__version__)

#Inner parameters
EPSILON: int = 180 # 3 minutes
DELTA: int = 480 # 8 minutes
CHALLENGE_DURATION: int = 900 #15 minutes
MIN_TGENS = 2
MAX_TGENS = 8

#Timeouts
ROUND_TIMEOUT: int = 1980 # 33 minutes
QUERY_AVAILABILITY_TIMEOUT: int = 60 # 1 minute
INITIAL_SETUP_TIMEOUT: int = 120 # 2 minutes
LOCKDOWN_TIMEOUT: int = 120 # 2 minutes
GRE_SETUP_TIMEOUT: int = 240 #4 minutes
CHALLENGE_TIMEOUT: int = CHALLENGE_DURATION + DELTA #23 minutes

# Store the base path dynamically, assuming `tensorprox` is the base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#Default validator user on remote machines
RESTRICTED_USER = "valiops"

#Temporary path for session_keys storage
SESSION_KEY_DIR = "/var/tmp/session_keys"

# Fixed overlay network IPs
KING_OVERLAY_IP = "10.0.0.1"