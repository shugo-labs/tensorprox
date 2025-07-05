import asyncio
import aiohttp
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from loguru import logger

async def get_azure_access_token(credentials: Dict[str, str]) -> str:
    """Get OAuth2 access token using miner's Azure credentials."""
    client_id = credentials.get('AZURE_CLIENT_ID')
    client_secret = credentials.get('AZURE_CLIENT_SECRET') 
    tenant_id = credentials.get('AZURE_TENANT_ID')
    
    if not all([client_id, client_secret, tenant_id]):
        raise ValueError("Missing required Azure credentials: CLIENT_ID, CLIENT_SECRET, TENANT_ID")
    
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://management.azure.com/.default'
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Azure authentication failed: {response.status} - {error_text}")
            
            result = await response.json()
            if 'access_token' not in result:
                raise Exception(f"No access token in Azure auth response: {result}")
            
            return result['access_token']

async def validate_existing_vnet(token: str, subscription_id: str, resource_group: str, 
                               vnet_name: str, subnet_name: str) -> Optional[str]:
    """
    Validate that the provided VNet and subnet exist and return subnet_id.
    Returns subnet_id if found, None otherwise.
    """
    headers = {'Authorization': f'Bearer {token}'}
    
    # Get the specific VNet
    vnet_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}?api-version=2024-05-01"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(vnet_url, headers=headers) as response:
            if response.status != 200:
                return None
            
            vnet_data = await response.json()
            
            # Check if the specified subnet exists
            for subnet in vnet_data.get('properties', {}).get('subnets', []):
                if subnet['name'] == subnet_name:
                    subnet_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/{subnet_name}"
                    return subnet_id
            
            return None

async def create_nsg(token: str, subscription_id: str, resource_group: str, 
                            location: str, vnet_name: str, uid: int) -> str:
    """Find existing NSG or create a new one for the VNet."""
    headers = {'Authorization': f'Bearer {token}'}
    

    # Create new NSG if none found
    timestamp = int(datetime.now().timestamp())
    nsg_name = f"tp-nsg-{uid}-{timestamp}"
        
    # NSG config with all ports open using API version 2024-05-01
    nsg_config = {
        'location': location,
        'properties': {
            'securityRules': [{
                'name': 'AllowAll',
                'properties': {
                    'priority': 100, 'protocol': '*', 'access': 'Allow', 'direction': 'Inbound',
                    'sourceAddressPrefix': '*', 'sourcePortRange': '*',
                    'destinationAddressPrefix': '*', 'destinationPortRange': '*'
                }
            }]
        }
    }

    async with aiohttp.ClientSession() as session:
        nsg_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}?api-version=2024-05-01"
        
        # Create VNet and NSG with error handling
        nsg_response = await session.put(nsg_url, headers=headers, json=nsg_config)
        
        if nsg_response.status not in [200, 201]:
            error_text = await nsg_response.text()
            raise Exception(f"Failed to create NSG {nsg_name}: {nsg_response.status} - {error_text}")
    
    nsg_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}"
    
    return nsg_id

async def retrieve_vm_infrastructure(token: str, subscription_id: str, resource_group: str,
                                 location: str, uid: int, vnet_name: str, 
                                 subnet_name: str) -> Tuple[str, str]:
    """
    Use existing VNet infrastructure.
    Return subnet_id and nsg_id.
    """
    #DELETE FOR PRODUCTION!
    if uid == 14:
        logger.info(f"UID 14 validating VNet {vnet_name} and subnet {subnet_name}...")

    # Validate that the VNet and subnet exist
    subnet_id = await validate_existing_vnet(token, subscription_id, resource_group, vnet_name, subnet_name)
    
    if subnet_id is None:
        #DELETE FOR PRODUCTION!
        if uid == 14:
            logger.error(f"UID 14 VNet '{vnet_name}' or subnet '{subnet_name}' not found!")
        raise Exception(f"VNet '{vnet_name}' or subnet '{subnet_name}' not found in resource group '{resource_group}'")
    
    #DELETE FOR PRODUCTION!
    if uid == 14:
        logger.info(f"UID 14 creating NSG...")
    
    # Find or create appropriate NSG
    nsg_id = await create_nsg(token, subscription_id, resource_group, location, vnet_name, uid)
    
    #DELETE FOR PRODUCTION!
    if uid == 14:
        logger.info(f"UID 14 infrastructure validated - subnet_id: {subnet_id}, nsg_id: {nsg_id}")
    
    return subnet_id, nsg_id

async def create_public_ip(token: str, subscription_id: str, resource_group: str,
                         location: str, pip_name: str) -> str:
    """Create public IP using API version 2024-05-01. Returns resource ID for NIC creation."""
    url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{pip_name}?api-version=2024-05-01"
    
    pip_config = {
        'location': location,
        'properties': {'publicIPAllocationMethod': 'Static'},
        'sku': {'name': 'Standard'}
    }
    
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    
    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=pip_config) as response:
            if response.status not in [200, 201]:
                error_text = await response.text()
                raise Exception(f"Failed to create public IP {pip_name}: {response.status} - {error_text}")
    
    return f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{pip_name}"

async def wait_for_resource_provisioning(session, url, headers, timeout=120):
    """Poll Azure resource until provisioningState is 'Succeeded' or timeout."""
    for _ in range(timeout // 5):
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                result = await response.json()
                state = result.get('properties', {}).get('provisioningState', '')
                if state == 'Succeeded':
                    return True
        await asyncio.sleep(5)
    return False

async def get_public_ip_address(token: str, subscription_id: str, resource_group: str, 
                               pip_name: str) -> str:
    """Get actual IP address from public IP resource."""
    url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{pip_name}?api-version=2024-05-01"
    headers = {'Authorization': f'Bearer {token}'}
    
    for _ in range(30):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    ip_address = result.get('properties', {}).get('ipAddress')
                    if ip_address:
                        return ip_address
        await asyncio.sleep(10)
    
    raise Exception(f"Public IP {pip_name} failed to allocate")

async def create_vm_with_resources(token: str, subscription_id: str, resource_group: str,
                                 location: str, vm_name: str, vm_size: str, subnet_id: str,
                                 nsg_id: str, private_ip: str, public_key: str) -> str:
    """Create VM with NIC and public IP. Return public IP address."""
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    
    # Create public IP
    pip_id = await create_public_ip(token, subscription_id, resource_group, location, f"{vm_name}-pip")
    
    # Create NIC with public IP using API version 2024-05-01
    nic_config = {
        'location': location,
        'properties': {
            'ipConfigurations': [{
                'name': 'ipconfig1',
                'properties': {
                    'subnet': {'id': subnet_id},
                    'privateIPAddress': private_ip,
                    'privateIPAllocationMethod': 'Static',
                    'publicIPAddress': {'id': pip_id}
                }
            }],
            'networkSecurityGroup': {'id': nsg_id}
        }
    }
    
    nic_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{vm_name}-nic?api-version=2024-05-01"
    
    async with aiohttp.ClientSession() as session:
        async with session.put(nic_url, headers=headers, json=nic_config) as nic_response:
            if nic_response.status not in [200, 201]:
                error_text = await nic_response.text()
                raise Exception(f"Failed to create NIC {vm_name}-nic: {nic_response.status} - {error_text}")
    
    nic_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{vm_name}-nic"
    
    # Wait for NIC
    await asyncio.sleep(30)
    
    # Create VM using API version 2024-11-01
    vm_config = {
        'location': location,
        'properties': {
            'hardwareProfile': {'vmSize': vm_size},
            'storageProfile': {
                'imageReference': {
                    'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy',
                    'sku': '22_04-lts-gen2', 'version': 'latest'
                },
                'osDisk': {'createOption': 'FromImage', 'managedDisk': {'storageAccountType': 'Premium_LRS'}}
            },
            'osProfile': {
                'computerName': vm_name,
                'adminUsername': 'azureuser',
                'linuxConfiguration': {
                    'disablePasswordAuthentication': True,
                    'ssh': {'publicKeys': [{'path': '/home/azureuser/.ssh/authorized_keys', 'keyData': public_key}]}
                }
            },
            'networkProfile': {'networkInterfaces': [{'id': nic_id}]}
        }
    }
    
    vm_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}?api-version=2024-11-01"
    
    async with aiohttp.ClientSession() as session:
        async with session.put(vm_url, headers=headers, json=vm_config) as vm_response:
            if vm_response.status not in [200, 201]:
                error_text = await vm_response.text()
                raise Exception(f"Failed to create VM {vm_name}: {vm_response.status} - {error_text}")
    
    # Get public IP address
    return await get_public_ip_address(token, subscription_id, resource_group, f"{vm_name}-pip")

async def provision_azure_vms_for_uid(uid: int, machine_config: Dict, public_key: str, subnet_id: str, nsg_id: str, moat_ip: str = "10.0.0.4") -> Tuple[Dict, List[Dict], str]:
    """
    Provision VMs for UID based on synapse response.
    
    Args:
        uid: Unique identifier for the provisioning session
        machine_config: Configuration dict containing credentials and VM specs
        public_key: SSH public key for VM access
        moat_ip: IP address of the moat machine (default: 10.0.0.4)
        vnet_name: Name of existing VNet to use (optional)
        subnet_name: Name of existing subnet to use (optional)
    
    Returns:
        Tuple containing:
        - king machine dict {ip, username}
        - traffic_generators list [{ip, username}, ...]
        - moat_private_ip string
    """
    #DELETE FOR PRODUCTION!
    logger.info(f"UID {uid} provision_azure_vms_for_uid called with subnet_id={subnet_id}, nsg_id={nsg_id}")
    
    credentials = machine_config['app_credentials']
    subscription_id = credentials['AZURE_SUBSCRIPTION_ID']
    resource_group = credentials['AZURE_RESOURCE_GROUP']
    location = machine_config.get('location', 'westeurope')
    
    #DELETE FOR PRODUCTION!
    logger.info(f"UID {uid} getting Azure token for VM provisioning...")
    token = await get_azure_access_token(credentials)
    
    # Get VM specs from synapse response
    num_tgens = machine_config.get('num_tgens', 2)
    king_size = machine_config.get('king_size', 'Standard_B1ms')
    tgens_size = machine_config.get('tgens_size', 'Standard_B1ms')
    
    #DELETE FOR PRODUCTION!
    logger.info(f"UID {uid} creating {num_tgens} TGens, King size: {king_size}, TGen size: {tgens_size}")
    
    timestamp = int(datetime.now().timestamp())

    # Create VMs concurrently
    vm_tasks = []
    
    # King VM
    #DELETE FOR PRODUCTION!
    logger.info(f"UID {uid} adding King VM task...")
    vm_tasks.append(create_vm_with_resources(
        token, subscription_id, resource_group, location,
        f'tp-king-{uid}-{timestamp}', king_size, subnet_id, nsg_id,
        '10.0.0.5', public_key
    ))
    
    # TGen VMs
    #DELETE FOR PRODUCTION!
    logger.info(f"UID {uid} adding {num_tgens} TGen VM tasks...")
    for i in range(num_tgens):
        vm_tasks.append(create_vm_with_resources(
            token, subscription_id, resource_group, location,
            f'tp-tgen{i+1}-{uid}-{timestamp}', tgens_size, subnet_id, nsg_id,
            f'10.0.0.{6+i}', public_key
        ))
    
    # Get all public IPs
    try:
        #DELETE FOR PRODUCTION!
        logger.info(f"UID {uid} starting VM creation tasks...")
        public_ips = await asyncio.gather(*vm_tasks)
        
        #DELETE FOR PRODUCTION!
        logger.info(f"UID {uid} VM creation completed, got public IPs: {public_ips}")
        
        # Build return objects
        king_machine = {'ip': public_ips[0], 'username': 'azureuser'}
        traffic_generators = [
            {'ip': public_ips[i+1], 'username': 'azureuser'} 
            for i in range(num_tgens)
        ]
        
        #DELETE FOR PRODUCTION!
        logger.info(f"UID {uid} returning king_machine={king_machine}, traffic_generators={traffic_generators}, moat_ip={moat_ip}")
        
        # FIXED: Return the actual moat_ip parameter
        return king_machine, traffic_generators, moat_ip
        
    except Exception as e:
        #DELETE FOR PRODUCTION!
        logger.error(f"UID {uid} VM provisioning failed: {e}")
        raise

async def azure_delete_with_lro(session: aiohttp.ClientSession, url: str, headers: Dict, resource_name: str) -> bool:
    """Azure-compliant DELETE with Long-Running Operation support."""
    try:
        async with session.delete(url, headers=headers) as response:
            if response.status in [200, 204]:
                return True  # Immediate success
            elif response.status == 202:
                # Asynchronous operation - need to poll
                polling_url = response.headers.get('Azure-AsyncOperation') or response.headers.get('Location')
                if not polling_url:
                    return False
                
                # Poll for completion
                for _ in range(60):  # Poll for up to 10 minutes
                    await asyncio.sleep(10)
                    async with session.get(polling_url, headers=headers) as poll_response:
                        if poll_response.status == 200:
                            poll_data = await poll_response.json()
                            status = poll_data.get('status', '').lower()
                            if status == 'succeeded':
                                return True
                            elif status in ['failed', 'canceled']:
                                return False
                        elif poll_response.status == 404:
                            return True  # Resource deleted
                return False  # Timeout
            else:
                return False  # Failed
    except Exception:
        return False

async def clear_vms(uid: int, machine_config: Dict, timestamp: int) -> None:
    """Delete VM-specific resources with proper Azure LRO handling."""
    credentials = machine_config['app_credentials']
    subscription_id = credentials['AZURE_SUBSCRIPTION_ID']
    resource_group = credentials['AZURE_RESOURCE_GROUP']
    
    token = await get_azure_access_token(credentials)
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    
    num_tgens = machine_config.get('num_tgens', 2)
    vm_names = [f'tp-king-{uid}-{timestamp}']
    for i in range(num_tgens):
        vm_names.append(f'tp-tgen{i+1}-{uid}-{timestamp}')
    
    failed_operations = []
    
    async with aiohttp.ClientSession() as session:
        # Step 1: Delete VMs with LRO support
        for vm_name in vm_names:
            vm_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}?api-version=2024-11-01"
            success = await azure_delete_with_lro(session, vm_url, headers, f"VM {vm_name}")
            if not success:
                failed_operations.append(f"VM {vm_name}")
        
        # Step 2: Wait for VM deletions to fully complete
        await asyncio.sleep(60)
        
        # Step 3: Delete NICs and Public IPs sequentially with proper LRO
        for vm_name in vm_names:
            nic_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{vm_name}-nic?api-version=2024-05-01"
            pip_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{vm_name}-pip?api-version=2024-05-01"
            
            # Try to disassociate Public IP from NIC first
            try:
                async with session.get(nic_url, headers=headers) as nic_response:
                    if nic_response.status == 200:
                        nic_config = await nic_response.json()
                        
                        # Remove Public IP association
                        for ip_config in nic_config['properties']['ipConfigurations']:
                            if 'publicIPAddress' in ip_config['properties']:
                                del ip_config['properties']['publicIPAddress']
                        
                        # Update NIC to remove Public IP association
                        async with session.put(nic_url, headers=headers, json=nic_config) as put_response:
                            if put_response.status in [200, 201, 202]:
                                await asyncio.sleep(30)  # Wait for disassociation
            except:
                pass  # Continue with deletion attempts
            
            # Delete Public IP with LRO
            pip_success = await azure_delete_with_lro(session, pip_url, headers, f"Public IP {vm_name}-pip")
            if not pip_success:
                failed_operations.append(f"Public IP {vm_name}-pip")
            
            # Delete NIC with LRO
            nic_success = await azure_delete_with_lro(session, nic_url, headers, f"NIC {vm_name}-nic")
            if not nic_success:
                failed_operations.append(f"NIC {vm_name}-nic")
        
        # Step 4: Delete OS disks with improved matching and LRO
        disks_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/disks?api-version=2024-03-02"
        
        try:
            async with session.get(disks_url, headers=headers) as disks_response:
                if disks_response.status == 200:
                    disks_data = await disks_response.json()
                    
                    for disk in disks_data.get('value', []):
                        disk_name = disk['name']
                        
                        # Better disk matching - check for our VM names with disk patterns
                        for vm_name in vm_names:
                            if (vm_name in disk_name and 
                                ('_disk1_' in disk_name or '_OsDisk_1_' in disk_name or disk_name.startswith(vm_name))):
                                
                                disk_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/disks/{disk_name}?api-version=2024-03-02"
                                disk_success = await azure_delete_with_lro(session, disk_url, headers, f"Disk {disk_name}")
                                if not disk_success:
                                    failed_operations.append(f"Disk {disk_name}")
                                break
        except Exception as e:
            failed_operations.append(f"Disk discovery: {str(e)}")
        
        # Step 5: Verification and retry for failed operations
        if failed_operations:
            await asyncio.sleep(60)  # Wait before retry
            
            # Retry failed operations once
            for operation in failed_operations[:]:  # Copy list to modify during iteration
                if "VM " in operation:
                    vm_name = operation.replace("VM ", "")
                    vm_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}?api-version=2024-11-01"
                    if await azure_delete_with_lro(session, vm_url, headers, operation):
                        failed_operations.remove(operation)
                
                elif "NIC " in operation:
                    nic_name = operation.replace("NIC ", "")
                    nic_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{nic_name}?api-version=2024-05-01"
                    if await azure_delete_with_lro(session, nic_url, headers, operation):
                        failed_operations.remove(operation)
                
                elif "Public IP " in operation:
                    pip_name = operation.replace("Public IP ", "")
                    pip_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{pip_name}?api-version=2024-05-01"
                    if await azure_delete_with_lro(session, pip_url, headers, operation):
                        failed_operations.remove(operation)
        
        # Report any remaining failures
        if failed_operations:
            raise Exception(f"Failed to delete: {', '.join(failed_operations)}")