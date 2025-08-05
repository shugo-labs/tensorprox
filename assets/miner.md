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

Miners must provide access to the traffic generation and King machines via Service Accounts on Cloud Providers. 
However, they can insert machines of any size or capacity into their .env.miner files. The traffic generation automatically scales to the capability of the machines, ensuring lightweight traffic on lower-tier setups and progressively increasing load as performance scales.
This makes it possible to get started with even modest VPS, while encouraging scale-up for higher rewards.

## 📐 Set up your miner 
tensorprox supports running a miner on these Providers:  

[Google Cloud Platform (GCP)](https://github.com/shugo-labs/tensorprox/blob/main/assets/gcp_setup.md)  

[Amazon Web Services (AWS)](https://github.com/shugo-labs/tensorprox/blob/main/assets/aws_setup.md)  


Click the respective Link to get their setup instructions. 
