#!/bin/bash

# Variables
PCAP_FILE="udp_traffic_python.pcap" # Output pcap file name
INTERFACE="eth0"             # Replace with the correct network interface (use `ip route` to find it)


# Start tcpdump to capture UDP traffic in the background
echo "Starting tcpdump to capture UDP traffic..."
sudo tcpdump -i $INTERFACE udp -w $PCAP_FILE &
TCPDUMP_PID=$!

sleep 1

# Run the Python program
echo "Running the Python program..."
python tests-local/udp_tracker.py

# Get the PID of the Go program
PROG_PID=$!
echo "Python program PID: $PROG_PID"

# Wait for the Go program to finish
wait $PROG_PID

# Stop tcpdump after the Go program exits
echo "Stopping tcpdump..."
sudo kill $TCPDUMP_PID

echo "UDP traffic saved to $PCAP_FILE"
