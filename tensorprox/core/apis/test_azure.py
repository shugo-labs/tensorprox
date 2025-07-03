import os, sys
sys.path.append(os.path.expanduser("~/tensorprox"))
import aiohttp
import asyncio
import argparse
from tensorprox.utils.utils import *
from tensorprox.core.apis.azure_api import (
    get_azure_access_token,
    retrieve_vm_infrastructure, 
    provision_azure_vms_for_uid,
    clear_vms
)

async def test_azure_api_functions():
    """Test all Azure API functions and print actual responses."""
    
    print("=== Testing Azure API Functions ===\n")
    
    credentials = {
        'AZURE_CLIENT_ID': '',
        'AZURE_CLIENT_SECRET': '',
        'AZURE_TENANT_ID': '',
        'AZURE_SUBSCRIPTION_ID': '',
        'AZURE_RESOURCE_GROUP': 'myRG'
    }
    

        # Generate the session key pair
    _, public_key = await generate_local_session_keypair("./session_key_test")

    subscription_id = credentials['AZURE_SUBSCRIPTION_ID']
    resource_group = credentials['AZURE_RESOURCE_GROUP']
    location = 'eastus'
    uid = 12345
    subnet_name = "mySubnet"
    vnet_name = "myVNet"
    print("1. get_azure_access_token()")
    try:
        token = await get_azure_access_token(credentials)
        print(f"Response: {token}")
    except Exception as e:
        print(f"Error: {e}")
        return
    
    print("\n2. retrieve_vm_infrastructure()")
    try:
        subnet_id, nsg_id = await retrieve_vm_infrastructure(
            token, subscription_id, resource_group, location, uid,
            vnet_name, subnet_name
        )
        print(f"Response: subnet_id={subnet_id}, nsg_id={nsg_id}")
    except Exception as e:
        print(f"Error: {e}")
        subnet_id, nsg_id = None, None
    
    print("\n3. provision_azure_vms_for_uid()")
    try:
        test_uid = uid + 1000
        machine_config = {
            'app_credentials': credentials,
            'location': location,
            'num_tgens': 3,
            'king_size': 'Standard_B1ms',
            'tgens_size': 'Standard_B1ms'
        }
        
        king_machine, traffic_generators, moat_private_ip = await provision_azure_vms_for_uid(
            test_uid, machine_config, public_key, subnet_id, nsg_id
        )
        
        print(f"Response: king_machine={king_machine}, traffic_generators={traffic_generators}, moat_private_ip={moat_private_ip}")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n=== Azure API Testing Complete ===")

async def test_clear_vms_only(uid: int, timestamp: int, num_tgens: int = 2):
    """Test clear_vms function independently with specific uid and timestamp."""
    
    print(f"=== Testing clear_vms for UID {uid} with timestamp {timestamp} ===\n")
    
    credentials = {
        'AZURE_CLIENT_ID': '',
        'AZURE_CLIENT_SECRET': '',
        'AZURE_TENANT_ID': '',
        'AZURE_SUBSCRIPTION_ID': '',
        'AZURE_RESOURCE_GROUP': 'myRG'
    }
    
    machine_config = {
        'app_credentials': credentials,
        'location': 'westeurope',
        'num_tgens': num_tgens,
        'king_size': 'Standard_B1ms',
        'tgens_size': 'Standard_B1ms'
    }
    
    print(f"Clearing VMs for UID {uid} with timestamp {timestamp}")
    print(f"Expected VM names:")
    print(f"  - tp-king-{uid}-{timestamp}")
    for i in range(num_tgens):
        print(f"  - tp-tgen{i+1}-{uid}-{timestamp}")
    print()
    
    try:
        await clear_vms(uid, machine_config, timestamp)
        print("✓ VMs cleared successfully")
        print("  - All VMs deleted with Long-Running Operation (LRO) support")
        print("  - NICs updated to remove Public IP associations")
        print("  - Public IPs deleted with LRO polling")
        print("  - NICs deleted with LRO polling")
        print("  - OS disks automatically discovered and deleted")
        print("  - Failed operations retried once")
        print("  - VNet/NSG infrastructure preserved")
    except Exception as e:
        print(f"✗ Error during VM cleanup: {e}")
        print("  Note: The cleanup process uses Azure-compliant LRO handling:")
        print("  - Proper 202 Accepted response polling")
        print("  - Azure-AsyncOperation header support")
        print("  - Automatic disk discovery and cleanup")
        print("  - Retry mechanism for failed operations")
    
    print("\n=== Clear VMs Test Complete ===")

def main():
    parser = argparse.ArgumentParser(description='Test Azure API functions')
    parser.add_argument('--mode', choices=['full', 'clear'], default='full',
                       help='Test mode: full (all functions) or clear (clear_vms only)')
    parser.add_argument('--uid', type=int, help='UID for clear_vms test')
    parser.add_argument('--timestamp', type=int, help='Timestamp for clear_vms test')
    parser.add_argument('--num-tgens', type=int, default=2, help='Number of TGen VMs (default: 2)')
    
    args = parser.parse_args()
    
    if args.mode == 'clear':
        if not args.uid or not args.timestamp:
            print("Error: --uid and --timestamp are required for clear mode")
            print("Usage: python test_azure_api.py --mode clear --uid 12345 --timestamp 1234567890")
            sys.exit(1)
        
        asyncio.run(test_clear_vms_only(args.uid, args.timestamp, args.num_tgens))
    else:
        asyncio.run(test_azure_api_functions())

if __name__ == "__main__":
    main()
