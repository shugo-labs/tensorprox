#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import time
from datetime import datetime

# Test configuration
VALIDATOR_API_URL = "http://57.129.82.116:8000"  # Use your validator's IP
TEST_UIDS = [1, 2, 3, 4, 5]  # List of UIDs to test
TEST_MACHINES = ["tgen-0", "tgen-1", "king"]  # List of machines to test

async def get_token(session: aiohttp.ClientSession, uid: int) -> str:
    """Get a token for a specific UID."""
    try:
        async with session.get(f"{VALIDATOR_API_URL}/token/{uid}") as response:
            if response.status == 200:
                data = await response.json()
                return data["token"]
            else:
                content = await response.text()
                print(f"Failed to get token for UID {uid}: {response.status}")
                print(f"Response content: {content}")
                return None
    except Exception as e:
        print(f"Error getting token for UID {uid}: {str(e)}")
        return None

async def store_hash(session: aiohttp.ClientSession, uid: int, machine: str, token: str) -> bool:
    """Store a hash for a specific UID and machine."""
    try:
        # Create a test hash
        test_hash = f"test_hash_{uid}_{machine}_{int(time.time())}"
        
        # Match the HashEntry model format
        payload = {
            "hash": test_hash
        }
        
        headers = {
            "X-API-KEY": token,
            "Content-Type": "application/json"
        }
        
        print(f"\nStoring hash for UID {uid}, machine {machine}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        print(f"Headers: {json.dumps(headers, indent=2)}")
        
        async with session.post(
            f"{VALIDATOR_API_URL}/hashes/{uid}/{machine}",
            json=payload,
            headers=headers
        ) as response:
            content = await response.text()
            if response.status == 200:
                print(f"Successfully stored hash for UID {uid}, machine {machine}")
                print(f"Response: {content}")
                return True
            else:
                print(f"Failed to store hash for UID {uid}, machine {machine}: {response.status}")
                print(f"Response content: {content}")
                try:
                    error_json = json.loads(content)
                    if "detail" in error_json:
                        print(f"Error detail: {error_json['detail']}")
                except:
                    pass
                return False
    except Exception as e:
        print(f"Error storing hash for UID {uid}, machine {machine}: {str(e)}")
        return False

async def verify_hash(session: aiohttp.ClientSession, uid: int, machine: str) -> bool:
    """Verify that a hash exists for a specific UID and machine."""
    try:
        async with session.get(f"{VALIDATOR_API_URL}/hashes/{uid}/{machine}") as response:
            content = await response.text()
            if response.status == 200:
                print(f"Found hash for UID {uid}, machine {machine}")
                print(f"Response: {content}")
                return True
            else:
                print(f"Hash not found for UID {uid}, machine {machine}: {response.status}")
                print(f"Response content: {content}")
                return False
    except Exception as e:
        print(f"Error verifying hash for UID {uid}, machine {machine}: {str(e)}")
        return False

async def main():
    timeout = aiohttp.ClientTimeout(total=30)  # 30 seconds timeout
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Test token generation
        print("\n=== Testing Token Generation ===")
        tokens = {}
        for uid in TEST_UIDS:
            token = await get_token(session, uid)
            if token:
                tokens[uid] = token
                print(f"Generated token for UID {uid}: {token}")
        
        # Test hash storage
        print("\n=== Testing Hash Storage ===")
        for uid in TEST_UIDS:
            if uid not in tokens:
                continue
            for machine in TEST_MACHINES:
                await store_hash(session, uid, machine, tokens[uid])
                await asyncio.sleep(1)  # Add delay between requests
        
        # Verify stored hashes
        print("\n=== Verifying Stored Hashes ===")
        for uid in TEST_UIDS:
            for machine in TEST_MACHINES:
                await verify_hash(session, uid, machine)
                await asyncio.sleep(1)  # Add delay between requests

if __name__ == "__main__":
    asyncio.run(main()) 