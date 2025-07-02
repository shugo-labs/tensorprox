from pydantic import BaseModel, Field, model_validator
import bittensor as bt
from typing import List, Tuple, Any
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class MachineConfig(BaseModel):
    provider: str | None = None
    app_credentials: dict = Field(default_factory=dict)
    vnet_name: str | None = None
    subnet_name: str | None = None
    vnet_address_space: str = "10.0.0.0/8"
    subnet_address_prefix: str = "10.0.0.0/24"
    location: str = "eastus"
    tgens_size: str = "Standard_B1ms"
    king_size: str = "Standard_B1ms"
    num_tgens: int = 2

    @model_validator(mode='before')
    def cap_tgen_counts(cls, values):
        num_tgens = values.get('num_tgens', 2)
        # Cap the num_tgens within the min and max bounds
        values['num_tgens'] = max(MIN_TGENS, min(int(num_tgens), MAX_TGENS))
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
            "max_tgens": self.max_tgens,
            "machine_availabilities": {
                "provider": self.machine_availabilities.provider,
                "app_credentials": self.machine_availabilities.app_credentials,
                "vnet_name": self.machine_availabilities.vnet_name,
                "subnet_name": self.machine_availabilities.subnet_name,
                "vnet_address_space": self.machine_availabilities.vnet_address_space,
                "subnet_address_prefix": self.machine_availabilities.subnet_address_prefix,
                "location": self.machine_availabilities.location,
                "tgens_size": self.machine_availabilities.tgens_size,
                "king_size": self.machine_availabilities.king_size,
                "num_tgens": self.machine_availabilities.num_tgens,
            },
        }

    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        avail_data = data.get("machine_availabilities", {})
        return cls(
            max_tgens=data.get("max_tgens", MAX_TGENS),
            machine_availabilities=MachineConfig(
                provider=avail_data.get("provider"),
                app_credentials=avail_data.get("app_credentials", {}),
                vnet_name=avail_data.get("vnet_name"),
                subnet_name=avail_data.get("subnet_name"),
                vnet_address_space=avail_data.get("vnet_address_space", "10.0.0.0/8"),
                subnet_address_prefix=avail_data.get("subnet_address_prefix", "10.0.0.0/24"),
                location=avail_data.get("location", "eastus"),
                tgens_size=avail_data.get("tgens_size", "Standard_B1ms"),
                king_size=avail_data.get("king_size", "Standard_B1ms"),
                num_tgens=avail_data.get("num_tgens", 2),
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