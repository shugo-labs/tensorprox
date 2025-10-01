#!/bin/bash
# Web Client Bootstrap - Modular Setup Orchestrator
# Installs L3/L4 traffic generation and capture tools

set -e

SETUP_DIR="/root/setup"
SCRIPTS_DIR="/root"

mkdir -p ${SETUP_DIR}
cd ${SETUP_DIR}

# Download modular setup scripts
cat > ${SETUP_DIR}/setup-traffic-tools.sh <<'SETUP_TRAFFIC_EOF'
#!/bin/bash
# Install L3/L4 traffic generation tools
set -e

echo "[$(date)] Installing traffic generation tools..."

# Update package list
apt-get update

# Install base networking tools
apt-get install -y curl wget netcat-openbsd tcpdump net-tools iputils-ping

# Install hping3 for advanced packet crafting
echo "[$(date)] Installing hping3..."
apt-get install -y hping3

# Install iperf3 for bandwidth testing
echo "[$(date)] Installing iperf3..."
apt-get install -y iperf3

# Install Python3 and pip for scapy
echo "[$(date)] Installing Python3 and scapy..."
apt-get install -y python3 python3-pip python3-dev

# Install scapy for custom packet generation
pip3 install --upgrade scapy

echo "[$(date)] Traffic generation tools installed successfully"
echo "  - hping3: $(hping3 --version 2>&1 | head -1)"
echo "  - iperf3: $(iperf3 --version | head -1)"
echo "  - scapy: $(python3 -c 'import scapy; print(scapy.__version__)')"

SETUP_TRAFFIC_EOF

chmod +x ${SETUP_DIR}/setup-traffic-tools.sh

# Create traffic generator script
cat > ${SCRIPTS_DIR}/traffic-generator.sh <<'TRAFFIC_GEN_EOF'
#!/bin/bash
# L3/L4 Traffic Generator
# Usage: ./traffic-generator.sh <target_ip> [options]

set -e

TARGET_IP="$1"
PROTOCOL="${2:-both}"  # tcp, udp, or both
DURATION="${3:-60}"    # seconds
PORT="${4:-80}"        # destination port

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target_ip> [protocol:tcp|udp|both] [duration:seconds] [port]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100                    # Send TCP+UDP for 60s to port 80"
    echo "  $0 192.168.1.100 tcp 30 443         # Send TCP for 30s to port 443"
    echo "  $0 192.168.1.100 udp 120 53         # Send UDP for 120s to port 53"
    exit 1
fi

RESULTS_DIR="/root/results"
mkdir -p ${RESULTS_DIR}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="${RESULTS_DIR}/traffic_${TARGET_IP}_${TIMESTAMP}.log"

echo "========================================" | tee ${RESULT_FILE}
echo "Traffic Generator Started" | tee -a ${RESULT_FILE}
echo "Target: ${TARGET_IP}:${PORT}" | tee -a ${RESULT_FILE}
echo "Protocol: ${PROTOCOL}" | tee -a ${RESULT_FILE}
echo "Duration: ${DURATION}s" | tee -a ${RESULT_FILE}
echo "Started: $(date)" | tee -a ${RESULT_FILE}
echo "========================================" | tee -a ${RESULT_FILE}

# Start packet capture in background
echo "[$(date)] Starting packet capture..." | tee -a ${RESULT_FILE}
CAPTURE_FILE="${RESULTS_DIR}/capture_${TARGET_IP}_${TIMESTAMP}.pcap"
timeout $((DURATION + 10)) tcpdump -i any -w ${CAPTURE_FILE} "host ${TARGET_IP}" 2>/dev/null &
TCPDUMP_PID=$!

sleep 2  # Let tcpdump start

# Function to send TCP traffic
send_tcp() {
    echo "[$(date)] Sending TCP traffic to ${TARGET_IP}:${PORT}..." | tee -a ${RESULT_FILE}

    # Using hping3 for TCP SYN flood
    timeout ${DURATION} hping3 -S -p ${PORT} --flood ${TARGET_IP} 2>&1 | head -20 | tee -a ${RESULT_FILE} &
    TCP_PID=$!

    # Also send some actual HTTP requests
    for i in $(seq 1 10); do
        curl -m 5 -v http://${TARGET_IP}:${PORT} >> ${RESULT_FILE} 2>&1 || true
        sleep $((DURATION / 10))
    done &

    wait ${TCP_PID} 2>/dev/null || true
}

# Function to send UDP traffic
send_udp() {
    echo "[$(date)] Sending UDP traffic to ${TARGET_IP}:${PORT}..." | tee -a ${RESULT_FILE}

    # Using hping3 for UDP flood
    timeout ${DURATION} hping3 --udp -p ${PORT} --flood ${TARGET_IP} 2>&1 | head -20 | tee -a ${RESULT_FILE} &
    UDP_PID=$!

    wait ${UDP_PID} 2>/dev/null || true
}

# Send traffic based on protocol selection
case "${PROTOCOL}" in
    tcp)
        send_tcp
        ;;
    udp)
        send_udp
        ;;
    both)
        send_tcp &
        send_udp &
        wait
        ;;
    *)
        echo "ERROR: Unknown protocol: ${PROTOCOL}" | tee -a ${RESULT_FILE}
        exit 1
        ;;
esac

echo "[$(date)] Traffic generation completed" | tee -a ${RESULT_FILE}

# Wait for tcpdump to finish
sleep 2
kill ${TCPDUMP_PID} 2>/dev/null || true
wait ${TCPDUMP_PID} 2>/dev/null || true

# Analyze capture
if [ -f "${CAPTURE_FILE}" ]; then
    echo "" | tee -a ${RESULT_FILE}
    echo "========================================" | tee -a ${RESULT_FILE}
    echo "Packet Capture Summary" | tee -a ${RESULT_FILE}
    echo "========================================" | tee -a ${RESULT_FILE}
    tcpdump -r ${CAPTURE_FILE} -nn 2>/dev/null | head -50 | tee -a ${RESULT_FILE}

    PACKET_COUNT=$(tcpdump -r ${CAPTURE_FILE} 2>/dev/null | wc -l)
    echo "" | tee -a ${RESULT_FILE}
    echo "Total packets captured: ${PACKET_COUNT}" | tee -a ${RESULT_FILE}
    echo "Capture file: ${CAPTURE_FILE}" | tee -a ${RESULT_FILE}
fi

echo "" | tee -a ${RESULT_FILE}
echo "========================================" | tee -a ${RESULT_FILE}
echo "Results saved to: ${RESULT_FILE}" | tee -a ${RESULT_FILE}
echo "Finished: $(date)" | tee -a ${RESULT_FILE}
echo "========================================" | tee -a ${RESULT_FILE}

TRAFFIC_GEN_EOF

chmod +x ${SCRIPTS_DIR}/traffic-generator.sh

# Create result collector script
cat > ${SCRIPTS_DIR}/result-collector.sh <<'RESULT_COLLECTOR_EOF'
#!/bin/bash
# Result Collector - Retrieve and display traffic generation results

RESULTS_DIR="/root/results"

if [ ! -d "${RESULTS_DIR}" ]; then
    echo "No results directory found"
    exit 1
fi

# List available results
echo "========================================="
echo "Available Traffic Generation Results"
echo "========================================="
ls -lht ${RESULTS_DIR}/*.log 2>/dev/null || echo "No log files found"

echo ""
echo "========================================="
echo "Available Packet Captures"
echo "========================================="
ls -lht ${RESULTS_DIR}/*.pcap 2>/dev/null || echo "No capture files found"

# Display latest result if available
LATEST_LOG=$(ls -t ${RESULTS_DIR}/*.log 2>/dev/null | head -1)
if [ -n "${LATEST_LOG}" ]; then
    echo ""
    echo "========================================="
    echo "Latest Result: ${LATEST_LOG}"
    echo "========================================="
    cat ${LATEST_LOG}
fi

RESULT_COLLECTOR_EOF

chmod +x ${SCRIPTS_DIR}/result-collector.sh

# Execute traffic tools installation
${SETUP_DIR}/setup-traffic-tools.sh

# Create MOTD
cat > /etc/motd <<'MOTD_EOF'
========================================
Tensorprox Web Client - Traffic Generator
========================================

L3/L4 Traffic Generation Tools Installed:
  - hping3  : Advanced packet crafting
  - iperf3  : Bandwidth testing
  - scapy   : Custom packet generation
  - tcpdump : Packet capture

Usage:
  Generate traffic:
    /root/traffic-generator.sh <target_ip> [protocol] [duration] [port]

  View results:
    /root/result-collector.sh

  Examples:
    /root/traffic-generator.sh 192.168.1.100
    /root/traffic-generator.sh 192.168.1.100 tcp 30 443
    /root/traffic-generator.sh 192.168.1.100 udp 120 53

Results stored in: /root/results/
========================================
MOTD_EOF

echo "[$(date)] Web Client setup complete" | tee -a /var/log/bootstrap.log
