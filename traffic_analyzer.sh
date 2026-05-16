#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name:   traffic_analyzer.sh
# Purpose:       Automated packet capture and protocol extraction using tshark
# Environment:   Kali Linux v2023.4
# Author:        Tanvir Rahyan Shayem
# Date:          May 16, 2026
# -----------------------------------------------------------------------------

# Define variables
INTERFACE="eth0"
TARGET_IP="192.168.1.105"
OUTPUT_PCAP="capture.pcap"

echo "==============================================================="
echo "   KALI LINUX AUTOMATED TRAFFIC ANALYSIS ENGINE (TSHARK)      "
echo "==============================================================="

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: Please run this script with sudo privileges."
  exit 1
fi

# Step 1: Initialize live capture
echo "[+] Initializing capture on interface: $INTERFACE"
echo "[+] Restricting target scope to host: $TARGET_IP"
echo "[*] Capturing packets... Press Ctrl+C to stop and analyze."

# Capture traffic matching the target host filter
tshark -i "$INTERFACE" -f "host $TARGET_IP" -w "$OUTPUT_PCAP" -q &
TSHARK_PID=$!

# Let capture run briefly for demonstration or wait for manual interrupt
trap "kill $TSHARK_PID; echo -e '\n[+] Capture stopped. Processing artifacts...'; analyze_pcap; exit" INT
wait $TSHARK_PID

analyze_pcap() {
    if [ ! -f "$OUTPUT_PCAP" ]; then
        echo "[-] Error: Capture file $OUTPUT_PCAP not found."
        return
    fi

    echo -e "\n==============================================================="
    echo "                 EXTRACTED NETWORK ARTIFACTS                   "
    echo "==============================================================="

    # Step 2: Extract cleartext FTP commands
    echo -e "\n[1] Extracting Plaintext FTP Authentication & Commands:"
    tshark -r "$OUTPUT_PCAP" -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null

    # Step 3: Extract HTTP Basic Authentication Headers
    echo -e "\n[2] Extracting HTTP Basic Authorization Headers:"
    tshark -r "$OUTPUT_PCAP" -Y "http.authorization" -T fields -e http.authorization 2>/dev/null

    # Step 4: Audit Address Resolution Protocol (ARP) Traffic
    echo -e "\n[3] Auditing ARP Traffic for Man-In-The-Middle (MITM) Anomalies:"
    tshark -r "$OUTPUT_PCAP" -Y "arp" -T fields -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 2>/dev/null

    echo "==============================================================="
    echo "[+] Analysis complete. Raw log saved to $OUTPUT_PCAP."
    echo "==============================================================="
}
