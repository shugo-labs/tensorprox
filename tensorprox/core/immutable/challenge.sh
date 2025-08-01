#!/bin/bash

machine_name="$1"
challenge_duration="$2"
label_hashes="$3"
playlist_json=$(echo "$4" | jq '.' 2>/dev/null)
king_ip="$5"
traffic_gen_path="$6"

# Build grep patterns for counting occurrences of each label
benign_pattern=$(echo "$label_hashes" | jq -r '.BENIGN | join("|")')
udp_flood_pattern=$(echo "$label_hashes" | jq -r '.UDP_FLOOD | join("|")')
tcp_syn_flood_pattern=$(echo "$label_hashes" | jq -r '.TCP_SYN_FLOOD | join("|")')
INTERFACE_IP=$(ip -4 addr show ipip-"$machine_name" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Default RTT value
rtt_avg=1000000000

# Define the traffic filtering
filter_traffic="(tcp or udp) and dst host $king_ip"

# Add buffer to ensure late packets are counted
if [ "$machine_name" == "king" ]; then
    timeout_duration=$((challenge_duration + 2))
else
    timeout_duration=$challenge_duration
fi

# Traffic generation for tgen machines
if [[ "$machine_name" == tgen* ]]; then
    # Dump playlist into temporary json file
    echo "$playlist_json" > /tmp/playlist.json

    # Start traffic generator with the playlist
    # The traffic generator expects the new playlist structure with separate benign and attack playlists
    sudo nohup python3 $traffic_gen_path --playlist /tmp/playlist.json --receiver-ips $king_ip --interface ipip-$machine_name > /tmp/traffic_generator.log 2>&1 &

    # Start continuous ping in background
    nohup ping -I "$INTERFACE_IP" -c "$challenge_duration" "$king_ip" > /tmp/rtt.txt 2>&1 &
fi

# Use fast tcpdump with custom gawk processing to handle uniqueness for benign only
# Both TCP and UDP benign traffic use the same label hash
sudo timeout "$timeout_duration" tcpdump -A -l -i "gre-moat" "$filter_traffic" 2>/dev/null | \
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
}' > /tmp/counts.txt &

wait  # Ensure tcpdump finishes before reading counts

# Read counts from /tmp/counts.txt
counts=$(cat /tmp/counts.txt)

# Measure RTT if the machine is tgen
if [[ "$machine_name" == tgen* ]]; then
    # Extract average RTT from the ping output
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

# Delete temporary files
rm -f /tmp/playlist.json
rm -f /tmp/rtt.txt
rm -f /tmp/counts.txt

exit 0
