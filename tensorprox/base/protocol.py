from pydantic import BaseModel, Field, model_validator
import bittensor as bt
from typing import List, Tuple, Any
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class VMConfig(BaseModel):
    name: str | None = None
    image: str | None = None
    size: str | None = None
    admin_username: str | None = None
    location: str | None = None
    cores: int | None = None
    ram: int | None = None
    private_ip: str | None = None
    interface: str | None= None

    def get(self, key, default=None):
        return getattr(self, key, default)


class MachineConfig(BaseModel):
    app_credentials: dict = Field(default_factory=dict)
    vnet_name: str
    subnet_name: str
    vnet_address_space: str = "10.0.0.0/8"
    subnet_address_prefix: str = "10.0.0.0/24"
    machines_config: List[VMConfig] = Field(default_factory=list)
    is_valid: bool = True

    @model_validator(mode='before')
    def truncate_traffic_generators(cls, values):
        machines_config = values.get('machines_config', [])
        # Identify tgens by name
        tgens = [m for m in machines_config if getattr(m, 'name', '').startswith('tgen-')]
        # Cap tgens to MAX_TGENS
        capped_tgens = tgens[:MAX_TGENS]
        # Keep only the king machine
        king = [m for m in machines_config if getattr(m, 'name', '') == 'king']
        # Rebuild the list: capped tgens + king
        values['machines_config'] = capped_tgens + king
        # Set is_valid based on tgens count
        values['is_valid'] = len(tgens) >= MIN_TGENS
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
                "app_credentials": self.machine_availabilities.app_credentials,
                "machines_config": [m.model_dump() for m in self.machine_availabilities.machines_config],
                "is_valid": self.machine_availabilities.is_valid,
            },
        }

    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        avail_data = data.get("machine_availabilities", {})
        return cls(
            machine_availabilities=MachineConfig(
                app_credentials=avail_data.get("app_credentials", {}),
                machines_config=[VMConfig(**m) for m in avail_data.get("machines_config", [])],
                is_valid=avail_data.get("is_valid", True),
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