#!/bin/bash
machine_name="$1"
challenge_duration="$2"
label_hashes="$3"
playlist_json=$(echo "$4" | jq '.' 2>/dev/null)
king_ip="$5"
traffic_gen_path="$6"

# Set up logging to file descriptor 3
LOG_DIR="/tmp/challenge_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/challenge_${machine_name}_$(date +%Y%m%d_%H%M%S).log"
exec 3>"$LOG_FILE"

# Log function that writes to fd3
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S.%3N')] $1" >&3
}

# Log initial parameters
log "=== Challenge execution started ==="
log "Machine: $machine_name"
log "Duration: $challenge_duration seconds"
log "King IP: $king_ip"
log "Traffic gen path: $traffic_gen_path"
log "Label hashes: $label_hashes"
log "Playlist provided: $([ "$playlist_json" != "null" ] && echo "yes" || echo "no")"
log "Script PID: $$"
log "User: $(whoami)"
log "Working directory: $(pwd)"

# Build grep patterns for counting occurrences of each label
benign_pattern=$(echo "$label_hashes" | jq -r '.BENIGN | join("|")' 2>&3)
jq_exit_code=$?
log "jq exit code for BENIGN: $jq_exit_code"

udp_flood_pattern=$(echo "$label_hashes" | jq -r '.UDP_FLOOD | join("|")' 2>&3)
jq_exit_code=$?
log "jq exit code for UDP_FLOOD: $jq_exit_code"

tcp_syn_flood_pattern=$(echo "$label_hashes" | jq -r '.TCP_SYN_FLOOD | join("|")' 2>&3)
jq_exit_code=$?
log "jq exit code for TCP_SYN_FLOOD: $jq_exit_code"

INTERFACE_IP=$(ip -4 addr show ipip-"$machine_name" 2>&3 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
interface_exit_code=$?
log "Interface query exit code: $interface_exit_code"

log "Pattern - BENIGN: $benign_pattern"
log "Pattern - UDP_FLOOD: $udp_flood_pattern"
log "Pattern - TCP_SYN_FLOOD: $tcp_syn_flood_pattern"
log "Interface IP: $INTERFACE_IP"

# Check if interface exists
if ip link show ipip-"$machine_name" >/dev/null 2>&3; then
    log "Interface ipip-$machine_name exists"
else
    log "ERROR: Interface ipip-$machine_name does not exist"
fi

# Default RTT value
rtt_avg=1000000000

# Define the traffic filtering
filter_traffic="(tcp or udp) and dst host $king_ip"
log "Traffic filter: $filter_traffic"

# Add buffer to ensure late packets are counted
if [ "$machine_name" == "king" ]; then
    timeout_duration=$((challenge_duration + 1))
    log "King machine detected - timeout set to $timeout_duration seconds (duration + 1)"
else
    timeout_duration=$challenge_duration
    log "Non-king machine - timeout set to $timeout_duration seconds"
fi

# Traffic generation for tgen machines
if [[ "$machine_name" == tgen* ]]; then
    log "=== Starting traffic generation for $machine_name ==="
    log "Checking traffic generator path: $traffic_gen_path"
    
    if [ -f "$traffic_gen_path" ]; then
        log "Traffic generator script exists"
    else
        log "ERROR: Traffic generator script not found at $traffic_gen_path"
    fi
    
    # Check if we have sudo permissions
    if sudo -n true 2>&3; then
        log "Sudo permissions available"
    else
        log "WARNING: Sudo permissions may not be available"
    fi
    
    # Start traffic generator with playlist via stdin 
    log "Starting traffic generator process..."
    nohup bash -c "echo '$playlist_json' | sudo python3 $traffic_gen_path --playlist /dev/stdin --receiver-ips $king_ip --interface ipip-$machine_name" > /tmp/traffic_generator_${machine_name}.log 2>&1 &
    tgen_pid=$!
    log "Traffic generator started with PID: $tgen_pid"
    
    # Give it a moment to start
    sleep 1
    
    # Check if process is still running
    if ps -p $tgen_pid > /dev/null 2>&3; then
        log "Traffic generator process is running"
    else
        log "ERROR: Traffic generator process died immediately"
        log "Check /tmp/traffic_generator_${machine_name}.log for details"
    fi
else
    log "Not a tgen machine - skipping traffic generation"
fi

log "=== Starting packet capture ==="
log "Interface: gre-moat"
log "Filter: $filter_traffic"
log "Timeout: $timeout_duration seconds"

# Check if gre-moat interface exists
if ip link show gre-moat >/dev/null 2>&3; then
    log "Interface gre-moat exists"
    log "Interface details: $(ip addr show gre-moat 2>&3 | grep -E 'state|inet' | tr '\n' ' ')"
else
    log "ERROR: Interface gre-moat does not exist"
fi

# Check tcpdump availability
if command -v tcpdump >/dev/null 2>&3; then
    log "tcpdump is available"
else
    log "ERROR: tcpdump command not found"
fi

# Create error log for tcpdump
TCPDUMP_ERROR_LOG="/tmp/tcpdump_error_${machine_name}_$(date +%Y%m%d_%H%M%S).log"

log "Starting tcpdump capture..."
# Use fast tcpdump with custom gawk processing and capture output directly
counts=$(sudo timeout "$timeout_duration" tcpdump -A -l -i "gre-moat" "$filter_traffic" 2>"$TCPDUMP_ERROR_LOG" | \
gawk -v benign_pat="$benign_pattern" -v udp_pat="$udp_flood_pattern" -v tcp_pat="$tcp_syn_flood_pattern" '
BEGIN {
    udp_flood = 0;
    tcp_syn_flood = 0;
}
{
    # Store line for benign uniqueness check
    if ($0 ~ benign_pat) {
        # Create a hash of the payload for uniqueness check
        payload = $0;
        # Store unique benign payloads
        if (!(payload in benign_payloads)) {
            benign_payloads[payload] = 1;
        }
    }
    
    # Count all occurrences for UDP flood (no uniqueness check)
    if ($0 ~ udp_pat) {
        udp_flood++;
    }
    
    # Count all occurrences for TCP SYN flood (no uniqueness check)
    if ($0 ~ tcp_pat) {
        tcp_syn_flood++;
    }
}
END {
    # Count the unique benign payloads
    benign = 0;
    for (payload in benign_payloads) {
        benign++;
    }
    
    printf "BENIGN:%d, UDP_FLOOD:%d, TCP_SYN_FLOOD:%d", benign, udp_flood, tcp_syn_flood;
}' 2>&3)

tcpdump_exit_code=$?
log "tcpdump exit code: $tcpdump_exit_code"
log "Packet counts: $counts"

# Check if tcpdump produced any errors
if [ -s "$TCPDUMP_ERROR_LOG" ]; then
    log "tcpdump errors detected - see $TCPDUMP_ERROR_LOG"
    log "First few error lines: $(head -3 "$TCPDUMP_ERROR_LOG" | tr '\n' ' ')"
else
    log "No tcpdump errors detected"
fi

# Measure RTT if the machine is tgen
if [[ "$machine_name" == tgen* ]]; then
    log "=== Starting RTT measurement ==="
    log "Pinging from $INTERFACE_IP to $king_ip"
    
    # Create error log for ping
    PING_ERROR_LOG="/tmp/ping_error_${machine_name}_$(date +%Y%m%d_%H%M%S).log"

    # Start ping in background and capture output using process substitution
    ping_output=$(ping -I "$INTERFACE_IP" -c 10 "$king_ip" 2>"$PING_ERROR_LOG")
    ping_exit_code=$?
    log "Ping exit code: $ping_exit_code"

    # Log ping output for debugging
    if [ -n "$ping_output" ]; then
        log "Ping output received ($(echo "$ping_output" | wc -l) lines)"
    else
        log "WARNING: No ping output received"
    fi

    # Check for ping errors
    if [ -s "$PING_ERROR_LOG" ]; then
        log "Ping errors: $(cat "$PING_ERROR_LOG" | tr '\n' ' ')"
    fi

    # Extract average RTT from the ping output
    extracted_rtt=$(echo "$ping_output" | grep -oP 'rtt min/avg/max/mdev = \d+\.\d+/(\d+\.\d+)' | awk -F'/' '{print $5}')

    # Update rtt_avg only if extracted_rtt is not empty
    if [[ ! -z "$extracted_rtt" ]]; then
        rtt_avg=$extracted_rtt
        log "Extracted average RTT: $rtt_avg ms"
    else
        log "WARNING: Could not extract RTT from ping output, using default: $rtt_avg"
    fi

    # Output the counts along with the average RTT
    final_output="$counts, AVG_RTT:$rtt_avg"
    log "Final output: $final_output"
    echo "$counts, AVG_RTT:$rtt_avg"
else
    # Output just the counts if the machine is king
    final_output="$counts"
    log "Final output: $final_output"
    echo "$counts"
fi

log "=== Challenge execution completed ==="
log "Script exit code: 0"

# Close logging file descriptor
exec 3>&-

exit 0
