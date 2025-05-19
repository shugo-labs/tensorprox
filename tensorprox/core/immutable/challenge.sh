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

# Define the traffic filtering - pre-filter as much as possible at tcpdump level
filter_traffic="(tcp or udp) and dst host $king_ip"

# Add buffer to ensure late packets are counted
if [ "$machine_name" == "king" ]; then
    timeout_duration=$((challenge_duration + 1))
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

# Create a temporary file for patterns
echo "$benign_pattern" > /tmp/benign_pattern.txt
echo "$udp_flood_pattern" > /tmp/udp_flood_pattern.txt
echo "$tcp_syn_flood_pattern" > /tmp/tcp_syn_flood_pattern.txt

# Optimized approach: Use Perl instead of AWK for faster hash computation
# Perl has built-in MD5 without calling external commands
sudo timeout "$timeout_duration" tshark -i "gre-moat" -f "$filter_traffic" -T fields -e data 2>/dev/null | \
perl -w -MDigest::MD5=md5_hex -e '
use strict;
use Digest::MD5 qw(md5_hex);

# Read pattern files
open(my $benign_fh, "<", "/tmp/benign_pattern.txt") or die "Cannot open benign pattern file";
my $benign_pat = <$benign_fh>;
chomp($benign_pat);
close($benign_fh);

open(my $udp_fh, "<", "/tmp/udp_flood_pattern.txt") or die "Cannot open UDP pattern file";
my $udp_pat = <$udp_fh>;
chomp($udp_pat);
close($udp_fh);

open(my $tcp_fh, "<", "/tmp/tcp_syn_flood_pattern.txt") or die "Cannot open TCP pattern file";
my $tcp_pat = <$tcp_fh>;
chomp($tcp_pat);
close($tcp_fh);

# Define counters and track unique payloads
my %seen_payloads = ();
my $benign = 0;
my $udp_flood = 0;
my $tcp_syn_flood = 0;

# Debug file
open(my $debug_fh, ">/tmp/payload_debug.txt");

# Process each payload directly from tshark
while (my $hex_payload = <STDIN>) {
    chomp($hex_payload);
    next if $hex_payload eq "";
    
    # Convert hex to ASCII
    my $full_payload = pack("H*", $hex_payload);
    
    # Extract just the application payload (skip the first 28 bytes which are headers)
    # The 28 bytes offset is based on the analysis of your packets
    my $app_payload = substr($full_payload, 28);
    
    print $debug_fh "FULL PACKET: [$full_payload]\n";
    print $debug_fh "APPLICATION PAYLOAD: [$app_payload]\n";
    
    # Skip if we have seen this application payload before
    if (exists $seen_payloads{$app_payload}) {
        print $debug_fh "DUPLICATE APP PAYLOAD SKIPPED: [$app_payload]\n";
        next;
    }
    
    # Mark this application payload as seen
    $seen_payloads{$app_payload} = 1;
    print $debug_fh "NEW UNIQUE APP PAYLOAD: [$app_payload]\n";
    
    # Now classify based on content patterns
    if ($app_payload =~ /$benign_pat/i) {
        $benign++;
        print $debug_fh "BENIGN UNIQUE: [$app_payload] COUNT: $benign\n";
    }
    elsif ($app_payload =~ /$udp_pat/i) {
        $udp_flood++;
        print $debug_fh "UDP UNIQUE: [$app_payload] COUNT: $udp_flood\n";
    }
    elsif ($app_payload =~ /$tcp_pat/i) {
        $tcp_syn_flood++;
        print $debug_fh "TCP UNIQUE: [$app_payload] COUNT: $tcp_syn_flood\n";
    }
}

close($debug_fh);
print "BENIGN:$benign, UDP_FLOOD:$udp_flood, TCP_SYN_FLOOD:$tcp_syn_flood\n";
' > /tmp/counts.txt &

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
rm -f /tmp/benign_pattern.txt
rm -f /tmp/udp_flood_pattern.txt
rm -f /tmp/tcp_syn_flood_pattern.txt

exit 0