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
sudo timeout "$timeout_duration" tcpdump -A -l -i "gre-moat" "$filter_traffic" 2>/dev/null | \
perl -w -MDigest::MD5=md5_hex -e '
    use strict;

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

    # Define counters
    my $benign = 0;
    my $udp_flood = 0;
    my $tcp_syn_flood = 0;

    # Define hash sets for seen packets
    my %seen_benign = ();
    my %seen_udp_flood = ();
    my %seen_tcp_syn_flood = ();

    # Extract only the hex data for fingerprinting
    sub extract_hex_data {
        my ($full_packet) = @_;
        my @hex_lines = ();
        
        # Extract lines that start with 0x (hex data)
        foreach my $line (split /\n/, $full_packet) {
            if ($line =~ /^\s*0x[0-9a-f]+:\s+((?:[0-9a-f]{2,4}\s+)+)/) {
                push @hex_lines, $1;
            }
        }
        
        # Join all hex data into a single string and remove whitespace
        my $hex_data = join("", @hex_lines);
        $hex_data =~ s/\s+//g;  # Remove all whitespace
        
        return $hex_data;
    }

    # Variables for packet processing
    my $current_packet = "";
    my $in_packet = 0;

    # Process each line from tcpdump
    while (my $line = <STDIN>) {
        chomp($line);
        
        # Check if this is the start of a new packet
        if ($line =~ /^[0-9]+:[0-9]+:[0-9]+\.[0-9]+ /) {
            # Process previous packet if exists
            if ($current_packet) {
                process_packet($current_packet);
            }
            
            # Start new packet
            $current_packet = "";
            $in_packet = 1;
        }
        elsif ($in_packet) {
            # Add line to current packet
            $current_packet .= "$line\n";
        }
    }

    # Process the last packet if any
    if ($current_packet) {
        process_packet($current_packet);
    }

    # Output results
    print "BENIGN:$benign, UDP_FLOOD:$udp_flood, TCP_SYN_FLOOD:$tcp_syn_flood\n";

    # Function to process a complete packet
    sub process_packet {
        my ($pkt) = @_;
        
        # Extract only hex data for fingerprinting
        my $hex_data = extract_hex_data($pkt);
        my $hash = md5_hex($hex_data);
        
        # Classify packet based on patterns
        if ($pkt =~ /$benign_pat/ && !exists $seen_benign{$hash}) {
            $seen_benign{$hash} = 1;
            $benign++;
        }
        elsif ($pkt =~ /$udp_pat/ && !exists $seen_udp_flood{$hash}) {
            $seen_udp_flood{$hash} = 1;
            $udp_flood++;
        }
        elsif ($pkt =~ /$tcp_pat/ && !exists $seen_tcp_syn_flood{$hash}) {
            $seen_tcp_syn_flood{$hash} = 1;
            $tcp_syn_flood++;
        }
    }
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