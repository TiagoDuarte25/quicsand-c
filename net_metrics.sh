#!/bin/bash
# This script will collect network metrics

INTERFACE="enx00e54c360853"
PING_TARGET="8.8.8.8"  # You can change this to any reliable target
IPERF_SERVER="iperf3-server.example.com"  # Replace with a valid iperf3 server

# Function to calculate average latency and packet loss percentage using ping
calculate_latency_and_packet_loss() {
    ping_output=$(ping -c 10 $PING_TARGET)
    avg_latency=$(echo "$ping_output" | awk -F'/' 'END {print $5}')
    packet_loss=$(echo "$ping_output" | awk -F', ' '/packet loss/ {print $3}')
    echo "$avg_latency" "$packet_loss"
}

# Function to calculate throughput using iperf3
calculate_throughput() {
    iperf_output=$(iperf3 -c $IPERF_SERVER -t 10)
    throughput=$(echo "$iperf_output" | awk '/receiver/ {print $7 " " $8}')
    echo "$throughput"
}

# Print header
echo "Network Metrics"
echo "==============="
echo "Interface: $INTERFACE"
echo "Target: $PING_TARGET"
echo "Iperf Server: $IPERF_SERVER"
echo "-----------------------------------"

# Initialize previous values for RX and TX bytes
prev_rx_bytes=0
prev_tx_bytes=0

while :
do
    # Get the current network metrics
    rx_packets=$(cat /proc/net/dev | grep $INTERFACE | tr -s ' ' | cut -d ' ' -f 3)
    rx_bytes=$(cat /proc/net/dev | grep $INTERFACE | tr -s ' ' | cut -d ' ' -f 2)
    tx_packets=$(cat /proc/net/dev | grep $INTERFACE | tr -s ' ' | cut -d ' ' -f 11)
    tx_bytes=$(cat /proc/net/dev | grep $INTERFACE | tr -s ' ' | cut -d ' ' -f 10)

    # Calculate RX and TX rates
    if [ $prev_rx_bytes -ne 0 ] && [ $prev_tx_bytes -ne 0 ]; then
        rx_rate=$(echo "scale=2; ($rx_bytes - $prev_rx_bytes) / 1024" | bc)
        tx_rate=$(echo "scale=2; ($tx_bytes - $prev_tx_bytes) / 1024" | bc)
    else
        rx_rate=0
        tx_rate=0
    fi

    # Update previous values
    prev_rx_bytes=$rx_bytes
    prev_tx_bytes=$tx_bytes

    # Calculate latency and packet loss
    read avg_latency packet_loss < <(calculate_latency_and_packet_loss)

    # Calculate throughput
    throughput=$(calculate_throughput)

    # Print the network metrics
    echo "Received Packets: $rx_packets"
    echo "Received Bytes: $rx_bytes"
    echo "Transmitted Packets: $tx_packets"
    echo "Transmitted Bytes: $tx_bytes"
    echo "RX Rate: $rx_rate KiB/s"
    echo "TX Rate: $tx_rate KiB/s"
    echo "Average Latency: $avg_latency ms"
    echo "Packet Loss: $packet_loss"
    echo "Throughput: $throughput"
    echo "-----------------------------------"

    sleep 10
done

