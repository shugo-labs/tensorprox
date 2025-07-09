from pydantic import BaseModel, Field, model_validator
import bittensor as bt
from typing import List, Tuple, Any
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class MachineConfig(BaseModel):
    # Provider identification
    provider: str | None = None
    
    # Generic cloud credentials
    project_id: str | None = None
    auth_id: str | None = None
    auth_secret: str | None = None
    resource_group: str | None = None
    
    # Generic network config
    vpc_name: str | None = None
    subnet_name: str | None = None
    vpc_cidr: str | None = None
    subnet_cidr: str | None = None
    
    # Generic compute config
    region: str | None = None
    vm_size_small: str | None = None
    vm_size_large: str | None = None
    num_tgens: int = 2
    
    # Optional custom VM specs for King
    custom_king_ram_mb: int | None = None
    custom_king_cpu_count: int | None = None
    
    # Optional custom VM specs for TGens
    custom_tgen_ram_mb: int | None = None
    custom_tgen_cpu_count: int | None = None
    
    # Legacy fields for backward compatibility
    app_credentials: dict = Field(default_factory=dict)
    vnet_address_space: str | None = None
    subnet_address_prefix: str | None = None
    location: str | None = None
    tgens_size: str | None = None
    king_size: str | None = None

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
                "project_id": self.machine_availabilities.project_id,
                "auth_id": self.machine_availabilities.auth_id,
                "auth_secret": self.machine_availabilities.auth_secret,
                "resource_group": self.machine_availabilities.resource_group,
                "vpc_name": self.machine_availabilities.vpc_name,
                "subnet_name": self.machine_availabilities.subnet_name,
                "vpc_cidr": self.machine_availabilities.vpc_cidr,
                "subnet_cidr": self.machine_availabilities.subnet_cidr,
                "region": self.machine_availabilities.region,
                "vm_size_small": self.machine_availabilities.vm_size_small,
                "vm_size_large": self.machine_availabilities.vm_size_large,
                "num_tgens": self.machine_availabilities.num_tgens,
                "custom_king_ram_mb": self.machine_availabilities.custom_king_ram_mb,
                "custom_king_cpu_count": self.machine_availabilities.custom_king_cpu_count,
                "custom_tgen_ram_mb": self.machine_availabilities.custom_tgen_ram_mb,
                "custom_tgen_cpu_count": self.machine_availabilities.custom_tgen_cpu_count,
                # Legacy fields
                "app_credentials": self.machine_availabilities.app_credentials,
                "vnet_address_space": self.machine_availabilities.vnet_address_space,
                "subnet_address_prefix": self.machine_availabilities.subnet_address_prefix,
                "location": self.machine_availabilities.location,
                "tgens_size": self.machine_availabilities.tgens_size,
                "king_size": self.machine_availabilities.king_size,
            },
        }

    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        avail_data = data.get("machine_availabilities", {})
        return cls(
            max_tgens=data.get("max_tgens", MAX_TGENS),
            machine_availabilities=MachineConfig(
                provider=avail_data.get("provider"),
                project_id=avail_data.get("project_id"),
                auth_id=avail_data.get("auth_id"),
                auth_secret=avail_data.get("auth_secret"),
                resource_group=avail_data.get("resource_group"),
                vpc_name=avail_data.get("vpc_name"),
                subnet_name=avail_data.get("subnet_name"),
                vpc_cidr=avail_data.get("vpc_cidr"),
                subnet_cidr=avail_data.get("subnet_cidr"),
                region=avail_data.get("region"),
                vm_size_small=avail_data.get("vm_size_small"),
                vm_size_large=avail_data.get("vm_size_large"),
                num_tgens=avail_data.get("num_tgens", 2),
                custom_king_ram_mb=avail_data.get("custom_king_ram_mb"),
                custom_king_cpu_count=avail_data.get("custom_king_cpu_count"),
                custom_tgen_ram_mb=avail_data.get("custom_tgen_ram_mb"),
                custom_tgen_cpu_count=avail_data.get("custom_tgen_cpu_count"),
                # Legacy fields
                app_credentials=avail_data.get("app_credentials", {}),
                vnet_address_space=avail_data.get("vnet_address_space"),
                subnet_address_prefix=avail_data.get("subnet_address_prefix"),
                location=avail_data.get("location"),
                tgens_size=avail_data.get("tgens_size"),
                king_size=avail_data.get("king_size"),
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