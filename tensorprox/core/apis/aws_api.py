import os
import json
import aiohttp
import asyncio
from typing import Dict, Optional, Tuple, List
from loguru import logger
import time
from datetime import datetime, timezone
import base64
import hmac
import hashlib
from urllib.parse import quote, urlparse
import xml.etree.ElementTree as ET

from tensorprox import (
    KING_PRIVATE_IP, 
    MOAT_PRIVATE_IP,
    QUERY_AVAILABILITY_TIMEOUT,
    INITIAL_SETUP_TIMEOUT,
    GRE_SETUP_TIMEOUT,
    CHALLENGE_TIMEOUT,
)

# AWS-specific constants
AWS_INTERFACE = "ens5"  # Default AWS network interface - used directly in this module
AWS_IMAGE_OWNER = "099720109477"  # Canonical's AWS account ID
AWS_DISK_SIZE_GB = 10
AWS_INSTANCE_CONNECT_DISABLED = True  # Disable EC2 Instance Connect for confidentiality

# Self-destruction timer calculation 
NETWORK_BUFFER = 300  # 5 minutes for network delays
SAFETY_MARGIN = 320   # 5.33 minutes safety margin
SELF_DESTRUCT_TIMEOUT = (
    QUERY_AVAILABILITY_TIMEOUT +
    INITIAL_SETUP_TIMEOUT +
    GRE_SETUP_TIMEOUT +
    CHALLENGE_TIMEOUT +
    NETWORK_BUFFER +
    SAFETY_MARGIN
)  # Total: 2000 seconds (33.33 minutes)


def load_cloud_init_template() -> str:
    """Load the AWS cloud-init security template."""
    template_path = os.path.join(os.path.dirname(__file__), "aws-cloud-init.yml")
    with open(template_path, 'r') as f:
        return f.read()


def translate_config(config: Dict[str, str]) -> Dict[str, str]:
    """
    Translate generic config fields to AWS-specific fields.
    This is where the magic happens - generic becomes specific!
    """
    return {
        "AWS_ACCESS_KEY_ID": config.get("auth_id"),
        "AWS_SECRET_ACCESS_KEY": config.get("auth_secret"),
        "AWS_REGION": config.get("region"),
        "AWS_ACCOUNT_ID": config.get("project_id"),  # Optional for most operations
        # AWS doesn't use resource groups like Azure
    }


class AWSSignatureV4:
    """
    AWS Signature Version 4 signing for HTTP requests.
    This allows us to use raw HTTP like GCP, avoiding SDK dependencies.
    """
    def __init__(self, access_key: str, secret_key: str, region: str, service: str):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service
    
    def sign_request(self, method: str, url: str, headers: Dict[str, str], 
                     payload: str = "") -> Dict[str, str]:
        """
        Sign an AWS API request using Signature V4.
        Returns headers with authorization added.
        """
        # Parse URL
        parsed = urlparse(url)
        host = parsed.netloc
        uri = parsed.path or '/'
        query = parsed.query or ''
        
        # Add required headers
        headers = headers.copy()
        headers['Host'] = host
        headers['X-Amz-Date'] = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        
        # Create canonical request
        canonical_headers = ''.join(f'{k.lower()}:{v}\n' for k, v in sorted(headers.items()))
        signed_headers = ';'.join(k.lower() for k in sorted(headers.keys()))
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        canonical_request = f"{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        
        # Create string to sign
        date_stamp = headers['X-Amz-Date'][:8]
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = f"AWS4-HMAC-SHA256\n{headers['X-Amz-Date']}\n{credential_scope}\n" + \
                        hashlib.sha256(canonical_request.encode()).hexdigest()
        
        # Calculate signature
        def sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{self.secret_key}".encode(), date_stamp)
        k_region = sign(k_date, self.region)
        k_service = sign(k_region, self.service)
        k_signing = sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
        
        # Add authorization header
        headers['Authorization'] = f"AWS4-HMAC-SHA256 Credential={self.access_key}/{credential_scope}, " + \
                                  f"SignedHeaders={signed_headers}, Signature={signature}"
        
        return headers


class AWSSessionCache:
    """
    Thread-safe session cache for AWS API connections using aiohttp.
    Manages HTTP sessions and request signing for high-volume operations.
    Designed to handle 100 miners × 255 machines efficiently.
    """
    def __init__(self):
        self._sessions = {}  # {region: aiohttp.ClientSession}
        self._signers = {}   # {region: AWSSignatureV4}
        self._lock = asyncio.Lock()
    
    async def get_session(self, config: Dict[str, str]) -> Tuple[aiohttp.ClientSession, AWSSignatureV4]:
        """
        Get a cached aiohttp session and signer for a region.
        Creates new ones if they don't exist.
        """
        aws_config = translate_config(config)
        region = aws_config["AWS_REGION"]
        
        async with self._lock:
            # Create session if needed
            if region not in self._sessions:
                # Configure connection pooling for high throughput
                connector = aiohttp.TCPConnector(
                    limit=1000,  # Total connection pool size
                    limit_per_host=100,  # Per-host connection limit
                    ttl_dns_cache=300,  # DNS cache timeout
                    enable_cleanup_closed=True
                )
                self._sessions[region] = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=60)
                )
            
            # Create signer if needed
            if region not in self._signers:
                self._signers[region] = AWSSignatureV4(
                    aws_config["AWS_ACCESS_KEY_ID"],
                    aws_config["AWS_SECRET_ACCESS_KEY"],
                    region,
                    "ec2"  # Primary service we'll use
                )
            
            return self._sessions[region], self._signers[region]
    
    def clear_cache(self):
        """Clear all cached sessions (useful for testing or forced refresh)."""
        asyncio.create_task(self._close_all())
    
    async def _close_all(self):
        """Close all sessions gracefully."""
        async with self._lock:
            for session in self._sessions.values():
                await session.close()
            self._sessions.clear()
            self._signers.clear()


# Global session cache instance
_session_cache = AWSSessionCache()


async def get_aws_session(config: Dict[str, str]) -> Tuple[aiohttp.ClientSession, AWSSignatureV4]:
    """
    Get AWS session and signer using generic config.
    Now uses raw HTTP like GCP to avoid SDK dependencies.
    
    Args:
        config: Generic config dict from miner
    
    Returns:
        Tuple of (aiohttp session, AWS signer)
    """
    return await _session_cache.get_session(config)


async def validate_existing_vpc(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str,
    vpc_name: str,
    subnet_name: str
) -> Tuple[str, str]:
    """
    Validate that VPC and subnet exist, return IDs.
    
    Returns:
        Tuple of (subnet_id, vpc_id)
    """
    # Find VPC by name tag
    vpc_url = f"https://ec2.{region}.amazonaws.com/"
    vpc_params = {
        'Action': 'DescribeVpcs',
        'Version': '2016-11-15',
        'Filter.1.Name': 'tag:Name',
        'Filter.1.Value.1': vpc_name,
        'Filter.2.Name': 'state',
        'Filter.2.Value.1': 'available'
    }
    
    # Convert params to URL-encoded string
    vpc_params_str = '&'.join(f'{k}={v}' for k, v in vpc_params.items())
    
    headers = signer.sign_request('POST', vpc_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 vpc_params_str)
    
    async with session.post(vpc_url, data=vpc_params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to describe VPCs: {error}")
        
        # Parse XML response (AWS returns XML for EC2 API)
        text = await response.text()
        root = ET.fromstring(text)
        
        # AWS EC2 API doesn't use namespaces in practice for this call
        vpc_id = None
        for item in root.findall('.//item'):
            vpc_id_elem = item.find('vpcId')
            if vpc_id_elem is not None:
                vpc_id = vpc_id_elem.text
                break
        
        if not vpc_id:
            raise ValueError(f"VPC {vpc_name} not found")
    
    # Find subnet by name tag
    subnet_params = {
        'Action': 'DescribeSubnets',
        'Version': '2016-11-15',
        'Filter.1.Name': 'tag:Name',
        'Filter.1.Value.1': subnet_name,
        'Filter.2.Name': 'vpc-id',
        'Filter.2.Value.1': vpc_id,
        'Filter.3.Name': 'state',
        'Filter.3.Value.1': 'available'
    }
    
    subnet_params_str = '&'.join(f'{k}={v}' for k, v in subnet_params.items())
    
    headers = signer.sign_request('POST', vpc_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 subnet_params_str)
    
    async with session.post(vpc_url, data=subnet_params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to describe subnets: {error}")
        
        text = await response.text()
        root = ET.fromstring(text)
        
        subnet_id = None
        for item in root.findall('.//item'):
            subnet_id_elem = item.find('subnetId')
            if subnet_id_elem is not None:
                subnet_id = subnet_id_elem.text
                break
        
        if not subnet_id:
            raise ValueError(f"Subnet {subnet_name} not found in VPC {vpc_name}")
    
    logger.info(f"Using miner-provided subnet: {subnet_name} (ID: {subnet_id}) in VPC: {vpc_name}")
    return subnet_id, vpc_id


async def retrieve_vm_infrastructure(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    config: Dict[str, str],
    uid: int
) -> Tuple[str, str]:
    """
    Validate that VPC and subnet exist.
    Miners are responsible for providing subnets with appropriate security groups.
    
    Returns:
        Tuple of (subnet_id, vpc_id)
    """
    aws_config = translate_config(config)
    region = aws_config["AWS_REGION"]
    vpc_name = config.get("vpc_name")
    subnet_name = config.get("subnet_name")
    
    return await validate_existing_vpc(session, signer, region, vpc_name, subnet_name)


async def get_latest_ubuntu_ami(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str
) -> str:
    """
    Get the latest Ubuntu 22.04 LTS AMI ID for the region.
    Uses raw HTTP calls to match GCP pattern.
    """
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    
    params = {
        'Action': 'DescribeImages',
        'Version': '2016-11-15',
        'Owner.1': AWS_IMAGE_OWNER,
        'Filter.1.Name': 'name',
        'Filter.1.Value.1': 'ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*',
        'Filter.2.Name': 'state',
        'Filter.2.Value.1': 'available',
        'Filter.3.Name': 'architecture',
        'Filter.3.Value.1': 'x86_64',
        'Filter.4.Name': 'root-device-type',
        'Filter.4.Value.1': 'ebs',
        'Filter.5.Name': 'virtualization-type',
        'Filter.5.Value.1': 'hvm'
    }
    
    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    
    headers = signer.sign_request('POST', ec2_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 params_str)
    
    async with session.post(ec2_url, data=params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to describe images: {error}")
        
        text = await response.text()
        # Parse XML to find images
        root = ET.fromstring(text)
        
        images = []
        for item in root.findall('.//item'):
            image_id = item.find('imageId')
            creation_date = item.find('creationDate')
            if image_id is not None and creation_date is not None:
                images.append({
                    'ImageId': image_id.text,
                    'CreationDate': creation_date.text
                })
        
        if not images:
            raise Exception("No Ubuntu 22.04 LTS AMI found")
        
        # Sort by creation date and get the latest
        images.sort(key=lambda x: x['CreationDate'], reverse=True)
        
        logger.info(f"Found latest Ubuntu AMI: {images[0]['ImageId']}")
        return images[0]['ImageId']


async def create_public_ip(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str,
    address_name: str
) -> Tuple[str, str]:
    """
    Reserve a static external IP address.
    
    Returns:
        Tuple of (public_ip, allocation_id)
    """
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    
    params = {
        'Action': 'AllocateAddress',
        'Version': '2016-11-15',
        'Domain': 'vpc'
    }
    
    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    
    headers = signer.sign_request('POST', ec2_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 params_str)
    
    async with session.post(ec2_url, data=params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to allocate address: {error}")
        
        text = await response.text()
        root = ET.fromstring(text)
        
        allocation_id = root.find('.//allocationId')
        public_ip = root.find('.//publicIp')
        
        if allocation_id is None or public_ip is None:
            raise Exception("Failed to get allocation ID or public IP")
        
        return public_ip.text, allocation_id.text


async def create_vm_with_resources(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str,
    vm_name: str,
    instance_type: str,
    subnet_id: str,
    private_ip: str,
    public_key: str,
    user_data: str,
    vpc_id: str,
    uid: int,
    custom_ram_mb: Optional[int] = None,
    custom_cpu_count: Optional[int] = None
) -> Tuple[str, str]:
    """
    Create VM instance with network configuration and optional custom resources.
    
    Returns:
        Tuple of (private_ip, public_ip)
    """
    # Get latest Ubuntu AMI
    ami_id = await get_latest_ubuntu_ami(session, signer, region)
    
    # Handle custom instance types
    if custom_ram_mb and custom_cpu_count:
        instance_type = find_closest_instance_type(custom_cpu_count, custom_ram_mb)
    
    # Create public IP
    public_ip_name = f"{vm_name}-ip"
    public_ip, allocation_id = await create_public_ip(session, signer, region, public_ip_name)
    
    # Create instance
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    
    # Build parameters for RunInstances
    params = {
        'Action': 'RunInstances',
        'Version': '2016-11-15',
        'ImageId': ami_id,
        'MinCount': '1',
        'MaxCount': '1',
        'InstanceType': instance_type,
        'SubnetId': subnet_id,
        'PrivateIpAddress': private_ip,
        'UserData': base64.b64encode(user_data.encode()).decode(),
        'BlockDeviceMapping.1.DeviceName': '/dev/sda1',
        'BlockDeviceMapping.1.Ebs.VolumeSize': str(AWS_DISK_SIZE_GB),
        'BlockDeviceMapping.1.Ebs.VolumeType': 'gp3',
        'BlockDeviceMapping.1.Ebs.DeleteOnTermination': 'true',
        'BlockDeviceMapping.1.Ebs.Encrypted': 'true',
        'TagSpecification.1.ResourceType': 'instance',
        'TagSpecification.1.Tag.1.Key': 'Name',
        'TagSpecification.1.Tag.1.Value': vm_name,
        'TagSpecification.1.Tag.2.Key': 'TensorProx',
        'TagSpecification.1.Tag.2.Value': 'true',
        'TagSpecification.1.Tag.3.Key': 'self-destruct-timeout',
        'TagSpecification.1.Tag.3.Value': str(SELF_DESTRUCT_TIMEOUT),
        'MetadataOptions.HttpTokens': 'required',
        'MetadataOptions.HttpEndpoint': 'enabled',
        'MetadataOptions.HttpPutResponseHopLimit': '1',
        'MetadataOptions.InstanceMetadataTags': 'enabled',
        'InstanceInitiatedShutdownBehavior': 'terminate',
        'EbsOptimized': 'true'
    }
    
    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    
    headers = signer.sign_request('POST', ec2_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 params_str)
    
    async with session.post(ec2_url, data=params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to run instances: {error}")
        
        text = await response.text()
        root = ET.fromstring(text)
        
        instance_id = root.find('.//instanceId')
        if instance_id is None:
            raise Exception("Failed to get instance ID")
        
        instance_id = instance_id.text
    
    # Wait for instance to be running
    await aws_wait_for_instance_running(session, signer, region, instance_id)
    
    # Associate elastic IP
    await associate_elastic_ip(session, signer, region, instance_id, allocation_id)
    
    return private_ip, public_ip


async def associate_elastic_ip(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str,
    instance_id: str,
    allocation_id: str
) -> None:
    """Associate an Elastic IP with an instance."""
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    
    params = {
        'Action': 'AssociateAddress',
        'Version': '2016-11-15',
        'InstanceId': instance_id,
        'AllocationId': allocation_id
    }
    
    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    
    headers = signer.sign_request('POST', ec2_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 params_str)
    
    async with session.post(ec2_url, data=params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to associate address: {error}")
        
        # No need to parse response for successful association
        logger.info(f"Associated elastic IP with instance {instance_id}")


async def aws_wait_for_instance_running(
    session: aiohttp.ClientSession,
    signer: AWSSignatureV4,
    region: str,
    instance_id: str,
    timeout: int = 120
) -> None:
    """
    Wait for an instance to be in running state and pass status checks.
    Matches GCP's wait_for_vms_ready pattern.
    """
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    start_time = time.time()
    
    logger.info(f"Waiting for instance {instance_id} to be ready...")
    
    while True:
        # Check instance status
        params = {
            'Action': 'DescribeInstanceStatus',
            'Version': '2016-11-15',
            'InstanceId.1': instance_id,
            'IncludeAllInstances': 'true'
        }
        
        params_str = '&'.join(f'{k}={v}' for k, v in params.items())
        
        headers = signer.sign_request('POST', ec2_url, 
                                     {'Content-Type': 'application/x-www-form-urlencoded'},
                                     params_str)
        
        async with session.post(ec2_url, data=params_str, headers=headers) as response:
            if response.status != 200:
                error = await response.text()
                raise Exception(f"Failed to describe instance status: {error}")
            
            text = await response.text()
            root = ET.fromstring(text)
            
            # Check instance state
            instance_state = root.find('.//instanceState/name')
            if instance_state is not None and instance_state.text == 'running':
                # Check system and instance status
                system_status = root.find('.//systemStatus/status')
                instance_status = root.find('.//instanceStatus/status')
                
                if (system_status is not None and system_status.text == 'ok' and
                    instance_status is not None and instance_status.text == 'ok'):
                    # Instance is ready, wait a bit more for SSH
                    logger.info(f"Instance {instance_id} passed status checks, waiting 45s for SSH readiness...")
                    await asyncio.sleep(45)
                    return
        
        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise TimeoutError(f"Instance {instance_id} not ready after {timeout} seconds")
        
        # Wait before next poll
        await asyncio.sleep(5)


async def provision_aws_vms_for_uid(
    uid: int,
    machine_config: Dict,
    public_key: str,
    subnet_id: str,
    vpc_id: str
) -> Tuple[Dict, List[Dict], str]:
    """
    Provision King and TGen VMs for a UID.
    
    Returns:
        Tuple of (king_machine, traffic_generators, moat_ip)
    """
    # Clean up any existing resources first
    await cleanup_all_resources_for_uid(uid, machine_config)
    
    # Get AWS session and signer
    session, signer = await get_aws_session(machine_config)
    aws_config = translate_config(machine_config)
    region = aws_config["AWS_REGION"]
    
    # Extract configuration
    num_tgens = machine_config.get("num_tgens", 2)
    king_size = machine_config.get("vm_size_small", "t3.medium")
    tgen_size = machine_config.get("vm_size_large", "t3.large")
    
    # Get custom specs if provided
    custom_king_ram_mb = machine_config.get("custom_king_ram_mb")
    custom_king_cpu_count = machine_config.get("custom_king_cpu_count")
    custom_tgen_ram_mb = machine_config.get("custom_tgen_ram_mb")
    custom_tgen_cpu_count = machine_config.get("custom_tgen_cpu_count")
    
    # Load cloud-init content with AWS-specific security
    cloud_init_content = load_cloud_init_template()
    
    # Prepare user data with self-destruct timeout, SSH key, and AWS credentials
    user_data = cloud_init_content.format(
        ssh_key=public_key,
        self_destruct_timeout=SELF_DESTRUCT_TIMEOUT,
        uid=uid,
        aws_access_key=aws_config["AWS_ACCESS_KEY_ID"],
        aws_secret_key=aws_config["AWS_SECRET_ACCESS_KEY"],
        aws_region=aws_config["AWS_REGION"]
    )
    
    # Create King VM
    king_name = f"king-uid-{uid}-{int(time.time())}"
    king_private_ip, king_public_ip = await create_vm_with_resources(
        session, signer, region,
        king_name, king_size,
        subnet_id, KING_PRIVATE_IP,
        public_key, user_data,
        vpc_id, uid,
        custom_king_ram_mb, custom_king_cpu_count
    )
    
    king_machine = {
        "private_ip": king_private_ip,
        "public_ip": king_public_ip,
        "name": king_name,
        "ip": king_public_ip,
        "username": "ubuntu"  # AWS Ubuntu default user
    }
    
    # Create TGen VMs
    traffic_generators = []
    for i in range(num_tgens):
        tgen_name = f"tgen-{i}-uid-{uid}-{int(time.time())}"
        tgen_private_ip_assigned = f"10.0.0.{6 + i}"
        
        tgen_private_ip, tgen_public_ip = await create_vm_with_resources(
            session, signer, region,
            tgen_name, tgen_size,
            subnet_id, tgen_private_ip_assigned,
            public_key, user_data,
            vpc_id, uid,
            custom_tgen_ram_mb, custom_tgen_cpu_count
        )
        
        traffic_generators.append({
            "private_ip": tgen_private_ip,
            "public_ip": tgen_public_ip,
            "name": tgen_name,
            "ip": tgen_public_ip,
            "username": "ubuntu",
            "_index": i
        })
    
    logger.info(f"Successfully provisioned AWS VMs for UID {uid}")
    return king_machine, traffic_generators, MOAT_PRIVATE_IP


async def clear_vms(
    uid: int,
    machine_config: Dict,
    timestamp: int
) -> None:
    """
    Delete VMs and associated resources for a UID.
    """
    await cleanup_all_resources_for_uid(uid, machine_config)


async def cleanup_all_resources_for_uid(
    uid: int,
    machine_config: Dict
) -> None:
    """
    Aggressively clean up ALL resources associated with king/tgen VMs for a UID.
    This includes instances and elastic IPs.
    """
    # Get AWS session and signer
    session, signer = await get_aws_session(machine_config)
    aws_config = translate_config(machine_config)
    region = aws_config["AWS_REGION"]
    ec2_url = f"https://ec2.{region}.amazonaws.com/"
    
    # Find all instances with our tags
    params = {
        'Action': 'DescribeInstances',
        'Version': '2016-11-15',
        'Filter.1.Name': 'tag:Name',
        'Filter.1.Value.1': f'*uid-{uid}*',
        'Filter.2.Name': 'tag:TensorProx',
        'Filter.2.Value.1': 'true',
        'Filter.3.Name': 'instance-state-name',
        'Filter.3.Value.1': 'pending',
        'Filter.3.Value.2': 'running',
        'Filter.3.Value.3': 'stopping',
        'Filter.3.Value.4': 'stopped'
    }
    
    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    
    headers = signer.sign_request('POST', ec2_url, 
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 params_str)
    
    async with session.post(ec2_url, data=params_str, headers=headers) as response:
        if response.status != 200:
            error = await response.text()
            raise Exception(f"Failed to describe instances: {error}")
        
        text = await response.text()
        root = ET.fromstring(text)
    
        instance_ids = []
        allocation_ids = []
        
        # Parse instances from XML
        for reservation in root.findall('.//item'):
            for instance in reservation.findall('.//instancesSet/item'):
                instance_id = instance.find('instanceId')
                if instance_id is not None:
                    instance_ids.append(instance_id.text)
                
                # Collect elastic IP allocation IDs
                for interface in instance.findall('.//networkInterfaceSet/item'):
                    alloc_id = interface.find('.//association/allocationId')
                    if alloc_id is not None:
                        allocation_ids.append(alloc_id.text)
        
        # Terminate instances
        if instance_ids:
            logger.info(f"Terminating {len(instance_ids)} instances for UID {uid}")
            
            # Terminate all instances in one call
            terminate_params = {
                'Action': 'TerminateInstances',
                'Version': '2016-11-15'
            }
            
            # Add instance IDs to params
            for idx, instance_id in enumerate(instance_ids):
                terminate_params[f'InstanceId.{idx + 1}'] = instance_id
            
            terminate_params_str = '&'.join(f'{k}={v}' for k, v in terminate_params.items())
            
            headers = signer.sign_request('POST', ec2_url, 
                                         {'Content-Type': 'application/x-www-form-urlencoded'},
                                         terminate_params_str)
            
            async with session.post(ec2_url, data=terminate_params_str, headers=headers) as response:
                if response.status != 200:
                    error = await response.text()
                    logger.error(f"Failed to terminate instances: {error}")
            
            # Wait for termination (simplified - just sleep)
            logger.info("Waiting for instances to terminate...")
            await asyncio.sleep(60)
        
        # Release elastic IPs
        if allocation_ids:
            async def release_ip(alloc_id):
                try:
                    release_params = {
                        'Action': 'ReleaseAddress',
                        'Version': '2016-11-15',
                        'AllocationId': alloc_id
                    }
                    
                    release_params_str = '&'.join(f'{k}={v}' for k, v in release_params.items())
                    
                    headers = signer.sign_request('POST', ec2_url, 
                                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                                 release_params_str)
                    
                    async with session.post(ec2_url, data=release_params_str, headers=headers) as response:
                        if response.status == 200:
                            logger.info(f"Released elastic IP: {alloc_id}")
                            return True
                        else:
                            error = await response.text()
                            logger.warning(f"Failed to release elastic IP {alloc_id}: {error}")
                            return False
                except Exception as e:
                    logger.warning(f"Failed to release elastic IP {alloc_id}: {e}")
                    return False
            
            # Use asyncio.gather for parallel releases
            results = await asyncio.gather(
                *[release_ip(aid) for aid in allocation_ids],
                return_exceptions=True
            )
            
            success_count = sum(1 for r in results if r is True)
            logger.info(f"Released {success_count}/{len(allocation_ids)} elastic IPs")


def find_closest_instance_type(cpu_count: int, ram_mb: int) -> str:
    """
    Find the closest AWS instance type based on CPU and RAM requirements.
    Uses a comprehensive mapping for accurate selection.
    """
    ram_gb = ram_mb / 1024
    
    # Define instance types with their specs
    instance_types = [
        # General purpose
        {"type": "t3.micro", "cpu": 2, "ram": 1},
        {"type": "t3.small", "cpu": 2, "ram": 2},
        {"type": "t3.medium", "cpu": 2, "ram": 4},
        {"type": "t3.large", "cpu": 2, "ram": 8},
        {"type": "t3.xlarge", "cpu": 4, "ram": 16},
        {"type": "t3.2xlarge", "cpu": 8, "ram": 32},
        # Compute optimized
        {"type": "c5.large", "cpu": 2, "ram": 4},
        {"type": "c5.xlarge", "cpu": 4, "ram": 8},
        {"type": "c5.2xlarge", "cpu": 8, "ram": 16},
        {"type": "c5.4xlarge", "cpu": 16, "ram": 32},
        {"type": "c5.9xlarge", "cpu": 36, "ram": 72},
        # Memory optimized
        {"type": "r5.large", "cpu": 2, "ram": 16},
        {"type": "r5.xlarge", "cpu": 4, "ram": 32},
        {"type": "r5.2xlarge", "cpu": 8, "ram": 64},
        {"type": "r5.4xlarge", "cpu": 16, "ram": 128},
    ]
    
    # Find closest match
    best_match = None
    min_diff = float('inf')
    
    for instance in instance_types:
        cpu_diff = abs(instance["cpu"] - cpu_count)
        ram_diff = abs(instance["ram"] - ram_gb)
        # Weight CPU more heavily than RAM
        total_diff = cpu_diff * 2 + ram_diff
        
        if total_diff < min_diff and instance["cpu"] >= cpu_count and instance["ram"] >= ram_gb:
            min_diff = total_diff
            best_match = instance["type"]
    
    # If no exact match, use a larger instance
    if not best_match:
        if cpu_count <= 2 and ram_gb <= 8:
            best_match = "t3.xlarge"
        elif cpu_count <= 4 and ram_gb <= 32:
            best_match = "c5.2xlarge"
        else:
            best_match = "c5.4xlarge"
    
    #DELETE FOR PRODUCTION!
    logger.info(f"Selected instance type {best_match} for {cpu_count} CPUs and {ram_gb}GB RAM")
    return best_match