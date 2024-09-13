#!/bin/bash

# Variables
GO_PROGRAM="./cmd/gotorrent"       # Replace with your Go program name
OUTPUT_BINARY="gotorrent.exe"   # Output binary name
PCAP_FILE="udp_traffic.pcap" # Output pcap file name
INTERFACE="eth0"             # Replace with the correct network interface (use `ip route` to find it)

# Build the Go program
echo "Building the Go program..."
go build -o $OUTPUT_BINARY $GO_PROGRAM

if [ $? -ne 0 ]; then
    echo "Failed to build the Go program. Exiting."
    exit 1
fi

# Start tcpdump to capture UDP traffic in the background
echo "Starting tcpdump to capture UDP traffic..."
sudo tcpdump -i $INTERFACE udp -w $PCAP_FILE &
TCPDUMP_PID=$!

sleep 1

# Run the Go program
echo "Running the Go program..."
./$OUTPUT_BINARY &

# Get the PID of the Go program
GO_PID=$!
echo "Go program PID: $GO_PID"

# Wait for the Go program to finish
wait $GO_PID

# Stop tcpdump after the Go program exits
echo "Stopping tcpdump..."
sudo kill $TCPDUMP_PID

echo "UDP traffic saved to $PCAP_FILE"
