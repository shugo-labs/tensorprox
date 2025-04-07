import sys
import bittensor as bt
from loguru import logger
from abc import ABC, abstractmethod
from tensorprox.utils.misc import ttl_get_block
from tensorprox.settings import settings
from tensorprox.base.protocol import PingSynapse, ChallengeSynapse


class BaseNeuron(ABC):
    """
    Base class for Bittensor miners. This class is abstract and should be inherited by a subclass. It contains the core logic for all neurons; validators and miners.

    In addition to creating a wallet, subtensor, and metagraph, this class also handles the synchronization of the network state via a basic checkpointing mechanism based on epoch length.
    """

    # @classmethod
    # def _config(cls):
    #     return config(cls)

    @property
    def block(self):
        self._block = ttl_get_block()
        self.latest_block = self._block or -1
        return self._block

    def __init__(self, config=None):
        # self.config = self._config()


        # Check if the miner is registered on the Bittensor network before proceeding further.
        self.check_registered()

        # Each miner gets a unique identity (UID) in the network for differentiation.
        self.uid = settings.METAGRAPH.hotkeys.index(settings.WALLET.hotkey.ss58_address)
        logger.info(f"Running neuron on subnet: {settings.NETUID} with uid {self.uid}")
        self.step = 0

    @abstractmethod
    def forward(self, synapse: PingSynapse) -> PingSynapse: ...

    @abstractmethod
    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse: ...

    @abstractmethod
    def run(self): ...

    def set_weights():
        raise NotImplementedError("set_weights() not implemented for this neuron.")

    def sync(self):
        """
        Wrapper for synchronizing the state of the network for the given miner or validator.
        """
        # Ensure miner or validator hotkey is still registered on the network.
        logger.info("Syncing neuron...")
        self.check_registered()

        if self.should_sync_metagraph():
            self.resync_metagraph()

        # if self.should_set_weights():
        #     logger.debug("Setting weights...")
        #     self.set_weights()

        # Always save state.
        self.save_state()

    def check_registered(self):
        # --- Check for registration.
        if not settings.SUBTENSOR.is_hotkey_registered(
            netuid=settings.NETUID,
            hotkey_ss58=settings.WALLET.hotkey.ss58_address,
        ):
            logger.error(
                f"Wallet: {settings.WALLET} is not registered on netuid {settings.NETUID}."
                f" Please register the hotkey using `btcli subnets register` before trying again"
            )
            sys.exit()

    def should_sync_metagraph(self):
        """
        Check if enough epoch blocks have elapsed since the last checkpoint to sync.
        """
        return (
            settings.SUBTENSOR.get_current_block() - settings.METAGRAPH.last_update[self.uid]
        ) > settings.NEURON_EPOCH_LENGTH

    def should_set_weights(self) -> bool:
        # Don't set weights on initialization.
        if self.step == 0:
            return False


        # If neuron has validator permit we assume its running the validator code. If it is a dual permit neuron then we check that it also has a set_weights method (only true if it is running validator neuron)
        if not settings.METAGRAPH.validator_permit[self.uid] or not hasattr(self, "set_weights"):
            return False

        # Define appropriate logic for when set weights.
        return (self.block - settings.METAGRAPH.last_update[self.uid]) > settings.NEURON_EPOCH_LENGTH

    def save_state(self):
        pass

    def load_state(self):
        logger.debug(
            "load_state() not implemented for this neuron. You can implement this function to load model checkpoints or other useful data."
        )