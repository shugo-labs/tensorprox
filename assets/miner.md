# Miners

🐧 **Required OS:** Ubuntu 22.04  |  🐍 **Required Python:** Python 3.10

## Compute Requirements

### 🛡️ What the Miner Firewall Does ?

The Miner machine acts as a real-time traffic firewall during challenge rounds:

- 🕵️‍♂️ Sniffs live traffic using tools like libpcap, AF_PACKET, nfqueue, or raw sockets
- 🤖 Analyzes packets on the fly using a lightweight ML or rule-based DDoS detection model
- 🚦 Makes immediate decisions to allow, block, or drop traffic
- 🔌 Listens on multiple interfaces (e.g., gre-tgen-0, gre-tgen-1, ...) — one per traffic generator

| Resource  | Requirement   |
|-----------|---------------|
| VRAM      | None          |
| vCPU      | 8 vCPU        |
| RAM       | 8 GB          |
| Storage   | 80 GB         |
| Network   | >= 1 Gbps     |

## 🚀 Scalable Participation

Miners must provide SSH access to the traffic generation and King machines (minimum set to 2 tgens + 1 King).
However, they can start with machines of any size or capacity. The traffic generation automatically scales to the capability of the machines, ensuring lightweight traffic on lower-tier setups and progressively increasing load as performance scales.
This makes it possible to get started with even modest VPS or home lab machines, while encouraging scale-up for higher rewards.

## 🔧 Installation

1. Update system packages and install Python (3.10) pip:

```bash
sudo apt update && sudo apt install python3-pip -y && sudo apt install python3-venv -y
```

2. Install npm and pm2 for process management:

```bash
sudo apt install npm -y && sudo npm install -g pm2 
```

3. Create and activate virtual environment:

```bash
python3 -m venv tp && source tp/bin/activate
```

4. Clone the repository and install the required pip dependencies:

```bash
git clone https://github.com/shugo-labs/tensorprox.git
cd tensorprox
pip install -r requirements.txt
```

## 🧩 Configuration

1. Before running a miner, you will need to register its hotkey to the subnet:

If you haven't created a coldkey/hotkey wallet pair yet, check [here](https://docs.bittensor.com/btcli)

```bash
btcli s register --wallet.name borgg --wallet.hotkey miner --netuid 91 --subtensor.network finney
```

⚠️ To help decentralization, we strongly encourage using a local Subtensor network.
👉 See [this guide](https://docs.bittensor.com/subtensor-nodes/)

2. You must create a .env.miner environment file in your project directory. It is necessary for you to provide the following:

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
KING_INTERFACE = # Interface on the King machine that has the private IP address assigned
MOAT_PRIVATE_IP = # Private IP of the miner machine (moat)
MOAT_INTERFACE =  # Interface on the Moat machine that has the private IP address assigned
PRIVATE_KEY_PATH = # Private key generated for the machines' creation (king, tgens) on your specific provider
```

3. Also, make sure to include your WANDB_API_KEY in the .env file :

```text
WANDB_API_KEY="YOUR_API_KEY"
```


## 📌 Miner SSH Access Requirement

To participate, all miners must have original SSH access to both the king and traffic generator machines (whether personal machines or VPS). Additionally, miners must provide restricted SSH access to these machines for the validator, and most importantly ensure that all machines are within the **same private network**. This setup is a critical requirement for the challenge to proceed.

## 🖥️ Running

1. After setting up the environment file, create a new CSV file named "trafficgen_machines.csv" in the base directory (~/tensorprox)

```text
public_ip,username,private_ip
141.95.103.227,ubuntu,10.1.3.71
141.95.110.186,ubuntu,10.1.2.86 ...
```

2. Start your miner instance with sudo privileges to ensure it has the necessary permissions to forward packets to the King machine:

```bash
pm2 start "python3 neurons/miner.py" --name miner
```

3. Check if the instance is correctly running:

```bash
pm2 list
```

4. To view logs and monitor the miner's activity:

```bash
pm2 logs miner
```