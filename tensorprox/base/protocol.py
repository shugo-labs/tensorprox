from pydantic import BaseModel, Field, model_validator
import bittensor as bt
from typing import List, Tuple, Any
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class MachineDetails(BaseModel):
    ip: str | None = None
    username: str | None = None
    private_ip: str | None = None
    index: str | None = None

    def get(self, key, default=None):
        return getattr(self, key, default)


class MachineConfig(BaseModel):
    key_pair: Tuple[str, str] = ("", "")
    traffic_generators: List[MachineDetails] = Field(default_factory=list)
    king: MachineDetails = Field(default_factory=MachineDetails)
    moat_private_ip: str = ""
    is_valid: bool = True

    @model_validator(mode='before')
    def truncate_traffic_generators(cls, values):
        # Truncate the traffic_generators to MAX_TGENS
        traffic_generators = values.get('traffic_generators', [])
        values['traffic_generators'] = traffic_generators[:MAX_TGENS]
        values['is_valid'] = False if len(traffic_generators) < 2 else True
        return values
    
class PingSynapse(bt.Synapse):

    # Adding MAX_TGENS as an immutable attribute
    max_tgens: int = Field(
        default_factory=lambda: MAX_TGENS,
        title="Max Traffic Generators", 
        description="Maximum number of traffic generators", 
        allow_mutation=False
    )

    machine_availabilities: MachineConfig = Field(
        default_factory=MachineConfig,
        title="Machine's Availabilities",
        description="Contains all machines' details for setup and challenge processing",
        allow_mutation=True,
    )

    def serialize(self) -> dict[str, Any]:
        return {
            "machine_availabilities": {
                "key_pair": self.machine_availabilities.key_pair,
                "traffic_generators": [m.model_dump() for m in self.machine_availabilities.traffic_generators],
                "king": self.machine_availabilities.king.model_dump(),
                "moat_private_ip": self.machine_availabilities.moat_private_ip,
            },
        }

    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        avail_data = data.get("machine_availabilities", {})
        max_tgens = avail_data.get("max_tgens", MAX_TGENS)  # Ensure max_tgens is obtained from the data or default to MAX_TGENS
        traffic_gens = avail_data.get("traffic_generators", [])[:max_tgens]  # truncate here
        return cls(
            machine_availabilities=MachineConfig(
                key_pair=tuple(avail_data.get("key_pair", ("", ""))),
                traffic_generators=[MachineDetails(**m) for m in traffic_gens],
                king=MachineDetails(**avail_data.get("king", {})),
                moat_private_ip=avail_data.get("moat_private_ip", ""),
            ),
        )

class ChallengeSynapse(bt.Synapse):
    """
    Synapse for sending challenge state to miners.
    """

    task: str = Field(
        ..., title="Task Name", description="Description of the task assigned to miners."
    )

    state: str = Field(
        ..., title="State", description="State of the task assigned."
    )


    def serialize(self) -> dict:
        """
        Serializes the ChallengeSynapse into a dictionary.
        """
        return {
            "task" : self.task,
            "state" : self.state,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ChallengeSynapse":
        """
        Deserializes a dictionary into a ChallengeSynapse instance.
        Converts ISO 8601 date strings to datetime.
        """
        return cls(
            task=data["task"],
            state=data["state"],
        )

class AvailabilitySynapse(bt.Synapse):
    """AvailabilitySynapse is a specialized implementation of the `Synapse` class used to allow miners to let validators know
    about their status/availability to serve certain tasks"""
    task_availabilities: dict[str, bool]