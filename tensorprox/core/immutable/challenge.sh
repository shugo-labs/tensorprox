#!/bin/bash

machine_name="$1"
challenge_duration="$2"
label_hashes="$3"
playlist_json=$(echo "$4" | jq '.' 2>/dev/null)
king_ip="$5"
traffic_gen_path="$6"
tcp_server_path="$7"

# Build grep patterns for counting occurrences of each label
benign_pattern=$(echo "$label_hashes" | jq -r '.BENIGN | join("|")')
udp_flood_pattern=$(echo "$label_hashes" | jq -r '.UDP_FLOOD | join("|")')
tcp_syn_flood_pattern=$(echo "$label_hashes" | jq -r '.TCP_SYN_FLOOD | join("|")')
INTERFACE_IP=$(ip -4 addr show ipip-"$machine_name" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Default values for counts
benign_count=0
udp_flood_count=0
tcp_syn_flood_count=0

# Default RTT value
rtt_avg=1000000000

# Define the traffic filtering
filter_traffic="(tcp or udp) and dst host $king_ip"

# Add 2 second buffer to ensure late packets are counted 
if [ "$machine_name" == "king" ]; then
    timeout_duration=$((challenge_duration + 1))
    nohup python3 "$tcp_server_path" > /tmp/tcp_server.log 2>&1 &
else
    timeout_duration=$challenge_duration
fi

# Traffic generation for tgen machines
if [[ "$machine_name" == tgen* ]]; then

    # Dump playlist into temporary json file
    echo "$playlist_json" > /tmp/playlist.json

    # Start traffic generator with the playlist
    nohup python3 $traffic_gen_path --playlist /tmp/playlist.json --receiver-ips $king_ip --interface ipip-$machine_name > /tmp/traffic_generator.log 2>&1 &

    # Start continuous ping in background
    nohup ping -I "$INTERFACE_IP" -c "$challenge_duration" "$king_ip" > /tmp/rtt.txt 2>&1 &

fi

sudo timeout "$timeout_duration" tcpdump -A -l -i "gre-moat" "$filter_traffic" 2>/dev/null | \
    awk 'BEGIN { benign=0; udp_flood=0; tcp_syn_flood=0 } 
    {
        if ($0 ~ /'"$udp_flood_pattern"'/) udp_flood++;
        else if ($0 ~ /'"$tcp_syn_flood_pattern"'/) tcp_syn_flood++;
        else if ($0 ~ /'"$benign_pattern"'/) benign++;
    }
    END { print "BENIGN:"benign", UDP_FLOOD:"udp_flood", TCP_SYN_FLOOD:"tcp_syn_flood }' > /tmp/counts.txt &

wait  # Ensure tcpdump finishes before reading counts

# Read counts from /tmp/counts.txt
counts=$(cat /tmp/counts.txt)

# Measure RTT if the machine is tgen
if [[ "$machine_name" == tgen* ]]; then

    # Extract average RTT from the ping output (assuming the ping command ran successfully)
    extracted_rtt=$(grep -oP 'rtt min/avg/max/mdev = \d+\.\d+/(\d+\.\d+)' /tmp/rtt.txt | awk -F'/' '{print $5}')

    # Update rtt_avg only if extracted_rtt is not empty
    if [[ ! -z "$extracted_rtt" ]]; then
        rtt_avg=$extracted_rtt
    fi

    # Output the counts along with the average RTT
    echo "$counts, AVG_RTT:$rtt_avg"
else
    # Output just the counts if the machine is king
    echo "$counts"
fi

# If king machine, stop the TCP server gracefully
if [ "$machine_name" == "king" ]; then
    # Gracefully stop all matching tcp_server.py processes
    pkill -f "python3 $tcp_server_path" &>/dev/null || true
    sleep 2
    # Force kill if still running
    pkill -9 -f "python3 $tcp_server_path" &>/dev/null || true
else
    # Gracefully stop all matching traffic_generator.py processes for tgens
    pkill -f "python3 $traffic_gen_path" &>/dev/null || true
    sleep 2
    # Force kill if still running
    pkill -9 -f "python3 $traffic_gen_path" &>/dev/null || true
fi

# Delete temporary files
rm -f /tmp/playlist.json
rm -f /tmp/rtt.txt
rm -f /tmp/counts.txt