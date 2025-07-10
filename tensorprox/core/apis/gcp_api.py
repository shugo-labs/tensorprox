import os
import json
import aiohttp
import asyncio
from typing import Dict, Optional, Tuple, List
from loguru import logger
import time
from datetime import datetime, timezone
import jwt  # PyJWT library
import base64

from tensorprox import (
    KING_PRIVATE_IP, 
    MOAT_PRIVATE_IP,
)

# GCP-specific constants (should be moved to __init__.py in production)
GCP_INTERFACE = "ens4"  # Default GCP network interface
GCP_IMAGE_FAMILY = "ubuntu-2204-lts"
GCP_IMAGE_PROJECT = "ubuntu-os-cloud"
GCP_DISK_SIZE_GB = 10
GCP_NETWORK_TIER = "PREMIUM"


def translate_config(config: Dict[str, str]) -> Dict[str, str]:
    """
    Translate generic config fields to GCP-specific fields.
    This is where the magic happens - generic becomes specific!
    """
    return {
        "GCP_PROJECT_ID": config.get("project_id"),
        "GCP_SERVICE_ACCOUNT_EMAIL": config.get("auth_id"),
        "GCP_PRIVATE_KEY": config.get("auth_secret"),
        # GCP doesn't use resource groups
    }


async def get_gcp_access_token(config: Dict[str, str]) -> str:
    """
    Get OAuth2 access token using generic config.
    
    Args:
        config: Generic config dict from miner
    
    Returns:
        Access token for GCP API calls
    """
    # Translate generic to GCP-specific
    gcp_config = translate_config(config)
    
    service_account_email = gcp_config['GCP_SERVICE_ACCOUNT_EMAIL']
    private_key = gcp_config['GCP_PRIVATE_KEY']
    
    # Handle escaped newlines in private key
    if '\\n' in private_key:
        private_key = private_key.replace('\\n', '\n')
    
    # Create JWT for service account authentication
    now = int(time.time())
    jwt_claims = {
        "iss": service_account_email,
        "sub": service_account_email,
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
        "scope": "https://www.googleapis.com/auth/compute"
    }
    
    # Sign JWT with private key
    signed_jwt = jwt.encode(
        jwt_claims,
        private_key,
        algorithm="RS256"
    )
    
    # Exchange JWT for access token
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": signed_jwt
            }
        ) as response:
            data = await response.json()
            if "access_token" not in data:
                #DELETE FOR PRODUCTION!
                if "error" in data:
                    raise Exception(f"GCP OAuth2 failed: {data.get('error_description', data.get('error'))}")
                raise Exception("GCP OAuth2 response missing access_token")
            return data["access_token"]


async def validate_existing_vpc(
    token: str,
    project_id: str,
    vpc_name: str,
    subnet_name: str,
    region: str
) -> Optional[str]:
    """
    Validate that VPC and subnet exist, return subnet self-link.
    
    Returns:
        Subnet self-link if exists, None otherwise
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with aiohttp.ClientSession() as session:
        # Check VPC exists
        vpc_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/networks/{vpc_name}"
        async with session.get(vpc_url, headers=headers) as response:
            if response.status != 200:
                logger.error(f"VPC {vpc_name} not found")
                return None
        
        # Check subnet exists
        subnet_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/subnetworks/{subnet_name}"
        async with session.get(subnet_url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data["selfLink"]
            else:
                logger.error(f"Subnet {subnet_name} not found in region {region}")
                return None


async def retrieve_vm_infrastructure(
    token: str,
    project_id: str,
    zone: str,
    uid: int,
    vpc_name: str,
    subnet_name: str
) -> str:
    """
    Validate that VPC and subnet exist.
    Miners are responsible for providing subnets with appropriate firewall rules.
    
    Returns:
        subnet_self_link if exists
    """
    # Extract region from zone (e.g., "us-central1-a" -> "us-central1")
    region = "-".join(zone.split("-")[:-1])
    
    # Validate VPC and subnet
    subnet_link = await validate_existing_vpc(token, project_id, vpc_name, subnet_name, region)
    if not subnet_link:
        raise ValueError(f"VPC {vpc_name} or subnet {subnet_name} not found")
    
    logger.info(f"Using miner-provided subnet: {subnet_name} in VPC: {vpc_name}")
    return subnet_link


async def create_public_ip(
    token: str,
    project_id: str,
    region: str,
    address_name: str
) -> str:
    """
    Reserve a static external IP address.
    
    Returns:
        The reserved IP address
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    address_config = {
        "name": address_name,
        "addressType": "EXTERNAL",
        "networkTier": GCP_NETWORK_TIER
    }
    
    async with aiohttp.ClientSession() as session:
        url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses"
        async with session.post(url, headers=headers, json=address_config) as response:
            if response.status in [200, 201]:
                operation = await response.json()
                await gcp_wait_for_operation(session, operation["selfLink"], headers)
                
                # Get the allocated IP address
                get_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses/{address_name}"
                async with session.get(get_url, headers=headers) as get_response:
                    data = await get_response.json()
                    return data["address"]
            else:
                error = await response.text()
                raise Exception(f"Failed to create public IP: {error}")


async def create_vm_with_resources(
    token: str,
    project_id: str,
    zone: str,
    vm_name: str,
    machine_type: str,
    subnet_self_link: str,
    private_ip: str,
    public_key: str,
    custom_ram_mb: Optional[int] = None,
    custom_cpu_count: Optional[int] = None
) -> Tuple[str, str]:
    """
    Create VM instance with network configuration and optional custom resources.
    
    Returns:
        Tuple of (private_ip, public_ip)
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Handle custom machine type
    if custom_ram_mb and custom_cpu_count:
        machine_type_url = f"zones/{zone}/machineTypes/custom-{custom_cpu_count}-{custom_ram_mb}"
    else:
        machine_type_url = f"zones/{zone}/machineTypes/{machine_type}"
    
    # Extract region from zone
    region = "-".join(zone.split("-")[:-1])
    
    # First, create public IP
    public_ip_name = f"{vm_name}-ip"
    public_ip = await create_public_ip(token, project_id, region, public_ip_name)
    
    # VM configuration
    vm_config = {
        "name": vm_name,
        "machineType": f"projects/{project_id}/{machine_type_url}",
        "disks": [
            {
                "boot": True,
                "autoDelete": True,
                "initializeParams": {
                    "sourceImage": f"projects/{GCP_IMAGE_PROJECT}/global/images/family/{GCP_IMAGE_FAMILY}",
                    "diskSizeGb": str(GCP_DISK_SIZE_GB)
                }
            }
        ],
        "networkInterfaces": [
            {
                "subnetwork": subnet_self_link,
                "networkIP": private_ip,
                "accessConfigs": [
                    {
                        "type": "ONE_TO_ONE_NAT",
                        "name": "External NAT",
                        "natIP": public_ip,
                        "networkTier": GCP_NETWORK_TIER
                    }
                ],
                "nicType": "VIRTIO_NET"  # Use virtio for better performance
            }
        ],
        "metadata": {
            "items": [
                {
                    "key": "ssh-keys",
                    "value": f"validator:{public_key}"
                },
                {
                    "key": "startup-script",
                    "value": "#!/bin/bash\nsudo sysctl -w net.core.rmem_max=134217728\nsudo sysctl -w net.core.wmem_max=134217728"
                }
            ]
        },
        # No tags needed - miners provide subnets with existing firewall rules
        "scheduling": {
            "preemptible": False,
            "onHostMaintenance": "MIGRATE",
            "automaticRestart": True
        }
    }
    
    async with aiohttp.ClientSession() as session:
        url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
        async with session.post(url, headers=headers, json=vm_config) as response:
            if response.status in [200, 201]:
                operation = await response.json()
                await gcp_wait_for_operation(session, operation["selfLink"], headers)
                return private_ip, public_ip
            else:
                error = await response.text()
                raise Exception(f"Failed to create VM: {error}")


async def check_and_clear_existing_vms(
    token: str,
    project_id: str,
    zone: str,
    subnet_self_link: str
) -> None:
    """
    Check for existing VMs in subnet (except moat at 10.0.0.4) and delete them.
    This ensures clean state before provisioning new VMs.
    """
    headers = {"Authorization": f"Bearer {token}"}
    region = "-".join(zone.split("-")[:-1])
    
    async with aiohttp.ClientSession() as session:
        # List all instances in the zone
        list_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
        async with session.get(list_url, headers=headers) as response:
            if response.status != 200:
                logger.warning(f"Failed to list instances: {await response.text()}")
                return
            
            data = await response.json()
            instances = data.get("items", [])
        
        # Filter instances in our subnet (excluding moat)
        instances_to_delete = []
        ip_addresses_to_release = []
        
        for instance in instances:
            # Check if instance is in our subnet
            for interface in instance.get("networkInterfaces", []):
                if interface.get("subnetwork") == subnet_self_link:
                    private_ip = interface.get("networkIP")
                    # Skip moat (10.0.0.4)
                    if private_ip != MOAT_PRIVATE_IP:
                        instances_to_delete.append(instance["name"])
                        # Collect external IPs to release
                        for config in interface.get("accessConfigs", []):
                            if "natIP" in config:
                                # Assume IP name follows pattern: {instance-name}-ip
                                ip_addresses_to_release.append(f"{instance['name']}-ip")
                        break  # Found in subnet, no need to check other interfaces
        
        if instances_to_delete:
            logger.info(f"Found {len(instances_to_delete)} existing VMs in subnet to delete: {instances_to_delete}")
            
            # Delete instances
            delete_tasks = []
            for vm_name in instances_to_delete:
                delete_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{vm_name}"
                delete_tasks.append(delete_instance(session, delete_url, headers, vm_name))
            
            # Execute all deletions in parallel
            delete_results = await asyncio.gather(*delete_tasks, return_exceptions=True)
            
            # Wait for all delete operations to complete
            for result in delete_results:
                if isinstance(result, dict) and "selfLink" in result:
                    await gcp_wait_for_operation(session, result["selfLink"], headers)
            
            # Release static IPs after VMs are deleted
            for ip_name in ip_addresses_to_release:
                ip_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses/{ip_name}"
                try:
                    async with session.delete(ip_url, headers=headers) as del_response:
                        if del_response.status == 200:
                            operation = await del_response.json()
                            await gcp_wait_for_operation(session, operation["selfLink"], headers)
                            logger.info(f"Released IP: {ip_name}")
                except Exception as e:
                    logger.warning(f"Failed to release IP {ip_name}: {str(e)}")


async def delete_instance(
    session: aiohttp.ClientSession,
    delete_url: str,
    headers: Dict[str, str],
    vm_name: str
) -> Dict:
    """Helper function to delete a single instance."""
    async with session.delete(delete_url, headers=headers) as del_response:
        if del_response.status == 200:
            operation = await del_response.json()
            logger.info(f"Initiated deletion of VM: {vm_name}")
            return operation
        else:
            logger.error(f"Failed to delete VM {vm_name}: {await del_response.text()}")
            return {}


async def provision_gcp_vms_for_uid(
    uid: int,
    machine_config: Dict,
    public_key: str,
    subnet_self_link: str
) -> Tuple[Dict, List[Dict], str]:
    """
    Provision King and TGen VMs for a UID.
    
    Returns:
        Tuple of (king_machine, traffic_generators, moat_ip)
    """
    # Translate generic config
    gcp_config = translate_config(machine_config)
    project_id = gcp_config["GCP_PROJECT_ID"]
    
    # Use generic fields directly
    zone = machine_config.get("region")
    num_tgens = machine_config.get("num_tgens", 2)
    king_size = machine_config.get("vm_size_small", "e2-medium")  # King uses small size
    tgen_size = machine_config.get("vm_size_large", "e2-medium")  # TGens use large size
    # Get custom specs for King VM
    custom_king_ram_mb = machine_config.get("custom_king_ram_mb")
    custom_king_cpu_count = machine_config.get("custom_king_cpu_count")
    # Get custom specs for TGen VMs
    custom_tgen_ram_mb = machine_config.get("custom_tgen_ram_mb")
    custom_tgen_cpu_count = machine_config.get("custom_tgen_cpu_count")
    
    # Get access token
    token = await get_gcp_access_token(machine_config)
    
    # Check and clear any existing VMs in the subnet (except moat)
    await check_and_clear_existing_vms(
        token,
        project_id,
        zone,
        subnet_self_link
    )
    
    # Create King VM
    king_name = f"king-uid-{uid}-{int(time.time())}"
    king_private_ip, king_public_ip = await create_vm_with_resources(
        token, project_id, zone, king_name, king_size,
        subnet_self_link, KING_PRIVATE_IP, public_key,
        custom_king_ram_mb, custom_king_cpu_count
    )
    
    king_machine = {
        "private_ip": king_private_ip,
        "public_ip": king_public_ip,
        "name": king_name,
        "ip": king_public_ip,  # For SSH connectivity test
        "username": "validator"  # SSH username
    }
    
    # Create TGen VMs
    traffic_generators = []
    for i in range(num_tgens):
        tgen_name = f"tgen-{i}-uid-{uid}-{int(time.time())}"
        # Generate TGEN private IPs dynamically like Azure does
        tgen_private_ip_assigned = f"10.0.0.{6 + i}"
        tgen_private_ip, tgen_public_ip = await create_vm_with_resources(
            token, project_id, zone, tgen_name, tgen_size,
            subnet_self_link, tgen_private_ip_assigned, public_key,
            custom_tgen_ram_mb, custom_tgen_cpu_count
        )
        
        traffic_generators.append({
            "private_ip": tgen_private_ip,
            "public_ip": tgen_public_ip,
            "name": tgen_name,
            "ip": tgen_public_ip,  # For SSH connectivity test
            "username": "validator",  # SSH username
            "_index": i  # Index for machine identification
        })
    
    # Collect all VM names for polling
    vm_names = [king_machine["name"]] + [tg["name"] for tg in traffic_generators]
    
    # Poll VMs until they're ready instead of static sleep
    await wait_for_vms_ready(token, project_id, zone, vm_names)
    
    logger.info(f"Successfully provisioned and verified GCP VMs for UID {uid}")
    return king_machine, traffic_generators, MOAT_PRIVATE_IP


async def clear_vms(
    uid: int,
    machine_config: Dict,
    timestamp: int
) -> None:
    """
    Delete VMs and associated resources for a UID.
    """
    # Translate generic config
    gcp_config = translate_config(machine_config)
    project_id = gcp_config["GCP_PROJECT_ID"]
    zone = machine_config.get("region")
    
    token = await get_gcp_access_token(machine_config)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Extract region from zone
    region = "-".join(zone.split("-")[:-1])
    
    async with aiohttp.ClientSession() as session:
        # List all instances with matching names
        list_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
        async with session.get(list_url, headers=headers) as response:
            data = await response.json()
            instances = data.get("items", [])
        
        # Delete VMs and collect IP addresses to release
        ip_addresses = []
        for instance in instances:
            name = instance["name"]
            if f"uid-{uid}" in name and str(timestamp) in name:
                # Collect external IPs before deletion
                for interface in instance.get("networkInterfaces", []):
                    for config in interface.get("accessConfigs", []):
                        if "natIP" in config:
                            ip_addresses.append(f"{name}-ip")
                
                # Delete instance
                delete_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{name}"
                async with session.delete(delete_url, headers=headers) as del_response:
                    if del_response.status == 200:
                        operation = await del_response.json()
                        await gcp_wait_for_operation(session, operation["selfLink"], headers)
                        logger.info(f"Deleted VM: {name}")
        
        # Release static IPs
        for ip_name in ip_addresses:
            ip_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/regions/{region}/addresses/{ip_name}"
            async with session.delete(ip_url, headers=headers) as del_response:
                if del_response.status == 200:
                    operation = await del_response.json()
                    await gcp_wait_for_operation(session, operation["selfLink"], headers)
                    logger.info(f"Released IP: {ip_name}")


async def gcp_wait_for_operation(
    session: aiohttp.ClientSession,
    operation_url: str,
    headers: Dict[str, str],
    timeout: int = 300
) -> None:
    """
    Poll GCP operation until completion.
    """
    start_time = time.time()
    
    while True:
        async with session.get(operation_url, headers=headers) as response:
            operation = await response.json()
            
            if operation.get("status") == "DONE":
                if "error" in operation:
                    raise Exception(f"Operation failed: {operation['error']}")
                return
            
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Operation timed out after {timeout} seconds")
            
            await asyncio.sleep(2)


async def wait_for_vms_ready(
    token: str,
    project_id: str,
    zone: str,
    vm_names: List[str],
    timeout: int = 120
) -> None:
    """
    Poll VMs until they are RUNNING and guest OS is ready.
    More efficient than static sleep.
    """
    headers = {"Authorization": f"Bearer {token}"}
    start_time = time.time()
    
    #DELETE FOR PRODUCTION!
    logger.info(f"Polling {len(vm_names)} VMs for readiness...")
    
    async with aiohttp.ClientSession() as session:
        while True:
            all_ready = True
            
            # Check each VM's status
            for vm_name in vm_names:
                vm_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{vm_name}"
                
                async with session.get(vm_url, headers=headers) as response:
                    if response.status != 200:
                        all_ready = False
                        continue
                    
                    vm_data = await response.json()
                    status = vm_data.get("status")
                    
                    # Check if VM is running
                    if status != "RUNNING":
                        all_ready = False
                        #DELETE FOR PRODUCTION!
                        logger.debug(f"VM {vm_name} status: {status}")
                        continue
                    
                    # Check guest attributes for additional readiness (if available)
                    # GCP doesn't provide direct SSH readiness, but RUNNING status
                    # with a small delay is usually sufficient
            
            if all_ready:
                # Add small buffer for SSH daemon to fully start
                #DELETE FOR PRODUCTION!
                logger.info("All VMs are RUNNING, waiting 10s for SSH daemons...")
                await asyncio.sleep(10)
                return
            
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"VMs not ready after {timeout} seconds")
            
            # Wait before next poll
            await asyncio.sleep(5)