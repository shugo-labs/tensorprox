# Miners

## Compute Requirements

🛡️ What the Miner Firewall Does ?

The Miner machine acts as a real-time traffic firewall during challenge rounds:

🕵️‍♂️ Sniffs live traffic using tools like libpcap, AF_PACKET, nfqueue, or raw sockets

🤖 Analyzes packets on the fly using a lightweight ML or rule-based DDoS detection model

🚦 Makes immediate decisions to allow, block, or drop traffic

🔌 Listens on multiple interfaces (e.g., gre-tgen-0, gre-tgen-1, ...) — one per traffic generator

| Resource  | Requirement   |
|-----------|---------------|
| VRAM      | None          |
| vCPU      | 8 vCPU        |
| RAM       | 8 GB          |
| Storage   | 80 GB         |
| Network   | >= 1 Gbps     |


## Installation

Update system packages and install Python pip :

```bash
sudo apt update && sudo apt install python3-pip -y && apt install python3-venv -y
```

Install npm and pm2 for process management :

```bash
sudo apt install npm -y && sudo npm install -g pm2 
```

Create and activate virtual environment :

```bash
python3 -m venv tp && source tp/bin/activate
```

Clone the repository and install the required pip dependencies :

```bash
git clone https://github.com/shugo-io/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

## Configuration

Before running a miner, you will need register its hotkey to the subnet :

```text
btcli s register --wallet.name borgg --wallet.hotkey miner --netuid 234 --subtensor.network finney
```

You will also need to create a .env.miner environment file. It is necessary for you to provide the following :

```text
NETUID = # The subnet UID (integer)
SUBTENSOR_NETWORK = # The network name [test, finney, local]
SUBTENSOR_CHAIN_ENDPOINT = # The chain endpoint [test if running on test, finney if running on main, custom endpoint if running on local] 
WALLET_NAME = # Name of your wallet (coldkey) 
HOTKEY = # Name of your hotkey associated with above wallet
AXON_PORT = # TCP Port Number. The port must be open
KING_PUBLIC_IP = # Public IP of the receiver machine (king)
KING_PRIVATE_IP = # Private IP of the receiver machine (king)
KING_USERNAME = # Username of the king machine
MOAT_PRIVATE_IP = # Private IP of the miner machine (moat)
PRIVATE_KEY_PATH = # Private key generated for the machines' creation (king, attacker, benign) on your specific provider
```

## Miner SSH Access Requirement

To participate in the challenge, all miners must have original access to both the king and traffic generator machines (whether personal machines or VPS). Additionally, miners must provide restricted SSH access to these machines for the validator, ensuring that all machines are within the **same private network**. This setup is a critical requirement for the challenge to proceed. Failure to provide the required restricted SSH access within the same private network will result in the miner being ineligible to participate.

## Running

1. After setting up the environment file, create a new CSV file named "trafficgen_machines.csv" and populate it with the details of your traffic generator machines. The CSV format should include the following columns:

    public_ip,username,private_ip

    141.95.103.227,ubuntu,10.1.3.71

    141.95.110.186,ubuntu,10.1.2.86
    ...
    

2. Start your miner instance with sudo privileges to ensure it has the necessary permissions to forward packets to the King machine:

```bash
pm2 start "sudo python3 neurons/miner.py" --name miner
```

3. Check if the instance is correctly running:

```bash
pm2 list 
```

4. To view logs and monitor the miner’s activity:

```bash
pm2 logs miner
```
