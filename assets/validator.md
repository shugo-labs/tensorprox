# VALIDATORS

## Compute Requirements

⚙️ Assumptions

Miners: 256 total, evenly distributed across active validators

Machines per Miner: At least 3 (2 traffic generators + 1 king)

Active Validator Scenario: Only 1 validator is active

➡️ Resulting Load:
1 validator × 256 miners × 3 machines = 768 simultaneous SSH connections

| Resource  | Requirement   |
|-----------|---------------|
| VRAM      | None          |
| vCPU      | 32 vCPU       |
| RAM       | 96 GB         |
| Storage   | 150 GB        |
| Network   | >= 1 Gbps     |


## Installation

Update system packages and install Python pip/venv :

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

Before running a validator, you will need to create a .env.validator environment file. It is necessary for you to provide the following :

```text
NETUID = # The subnet UID (integer)
SUBTENSOR_NETWORK = # The network name [test, finney, local]
SUBTENSOR_CHAIN_ENDPOINT = # The chain endpoint [test if running on test, finney if running on main, custom endpoint if running on local]
WALLET_NAME = # Name of your wallet (coldkey)
HOTKEY = # Name of your hotkey associated with above wallet
AXON_PORT = # TCP Port Number. The port must be open
```

🔔 **Nota Bene**:

For proper operation, the validator must ensure that the following ports are open: **AXON_PORT**, **AXON_PORT + UID** and **AXON_PORT + UID + 1** !

While **AXON_PORT** is used for axon serving, ports **AXON_PORT + UID** and **AXON_PORT +UID + 1** are critical for synchronizing the active validator count across the network. Failing to expose these ports may lead to incomplete peer discovery or inconsistent validator state.


## Running

After creating the above environment file, run :

```bash
pm2 start "python3 neurons/validator.py" --name validator
```

Check if the instance is correctly running :

```bash
pm2 list
```

To see logs :

```bash
pm2 logs validator
```
