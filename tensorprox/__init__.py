import os

def _version_to_int(version_str: str) -> int:
    version_split = version_str.split(".") + ["0", "0"]
    major = int(version_split[0])
    minor = int(version_split[1])
    patch = int(version_split[2])
    return (10000 * major) + (100 * minor) + patch

#Release version
__version__ = "0.1.2" 
__spec_version__ = _version_to_int(__version__)

#Inner parameters
EPSILON: int = 30 # 30 seconds
DELTA: int = 10 # 10 seconds
CHALLENGE_DURATION: int = 10 # 10 seconds
MIN_TGENS = 2
MAX_TGENS = 8

#Timeouts
ROUND_TIMEOUT: int = 570 # 9 minutes 30 seconds
QUERY_AVAILABILITY_TIMEOUT: int = 180 # 3 minutes (for Azure VM provisioning testing)
INITIAL_SETUP_TIMEOUT: int = 120 # 2 minutes
LOCKDOWN_TIMEOUT: int = 10 # 10 seconds
GRE_SETUP_TIMEOUT: int = 300 # 5 Minutes
CHALLENGE_TIMEOUT: int = CHALLENGE_DURATION + DELTA # 20 seconds
EPOCH_TIME: int = ROUND_TIMEOUT + EPSILON

# Store the base path dynamically, assuming `tensorprox` is the base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#Default validator user on remote machines
RESTRICTED_USER = "valiops"

#Temporary path for session_keys storage
SESSION_KEY_DIR = "/var/tmp/session_keys"

# Fixed network IPs
KING_OVERLAY_IP = "100.0.0.1"
MOAT_PRIVATE_IP = "10.0.0.4"
KING_PRIVATE_IP = "10.0.0.5"

#Fixed Interfaces
AZURE_INTERFACE = "eth0"