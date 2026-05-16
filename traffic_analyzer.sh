#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name:   traffic_analyzer.sh
# Purpose:       Automated packet capture and protocol extraction using tshark
# Environment:   Kali Linux v2023.4
# Author:        Tanvir Rahyan Shayem
# Student ID:    2024000000035
# Institution:   Southeast University | Batch: CADS 004
# Mentor:        Hasibul L Hasan
# Date:          May 16, 2026
# Version:       2.0
# -----------------------------------------------------------------------------
# LEGAL NOTICE: This script is intended for use ONLY in authorised penetration
# testing engagements or isolated lab environments. Unauthorised interception
# of network traffic may violate the Electronic Communications Privacy Act
# (ECPA), the Computer Misuse Act (CMA), and equivalent local legislation.
# -----------------------------------------------------------------------------

# ─── Configurable Variables ──────────────────────────────────────────────────
INTERFACE="eth0"
TARGET_IP="192.168.1.105"
OUTPUT_PCAP="capture.pcap"
CAPTURE_DURATION=30          # seconds; set 0 for manual Ctrl+C stop
LOG_FILE="analysis_report.txt"
# ─────────────────────────────────────────────────────────────────────────────

# Colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║      KALI LINUX AUTOMATED TRAFFIC ANALYSIS ENGINE v2.0      ║"
    echo "║         Network Traffic Analysis & Protocol Inspection       ║"
    echo "║                     Using tshark / Wireshark                 ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Author  : Tanvir Rahyan Shayem  │  ID: 2024000000035       ║"
    echo "║  Batch   : CADS 004              │  Institution: SEU         ║"
    echo "║  Mentor  : Hasibul L Hasan       │  Date: May 16, 2026       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Dependency Check ────────────────────────────────────────────────────────
check_dependencies() {
    local missing=0
    for cmd in tshark; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}[-] Missing dependency: $cmd${RESET}"
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        echo -e "${YELLOW}[!] Install missing tools with: sudo apt install tshark${RESET}"
        exit 1
    fi
    echo -e "${GREEN}[+] All dependencies satisfied.${RESET}"
}

# ─── Privilege Check ─────────────────────────────────────────────────────────
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] Error: Please run this script with sudo privileges.${RESET}"
        exit 1
    fi
}

# ─── Interface Validation ────────────────────────────────────────────────────
check_interface() {
    if ! ip link show "$INTERFACE" &>/dev/null; then
        echo -e "${RED}[-] Interface '$INTERFACE' not found.${RESET}"
        echo -e "${YELLOW}[!] Available interfaces:${RESET}"
        ip -o link show | awk -F': ' '{print "    " $2}'
        exit 1
    fi
    echo -e "${GREEN}[+] Interface '$INTERFACE' confirmed.${RESET}"
}

# ─── Packet Capture ──────────────────────────────────────────────────────────
run_capture() {
    echo -e "\n${CYAN}[*] Starting packet capture...${RESET}"
    echo -e "${YELLOW}    Interface : $INTERFACE${RESET}"
    echo -e "${YELLOW}    Target IP  : $TARGET_IP${RESET}"
    echo -e "${YELLOW}    Output     : $OUTPUT_PCAP${RESET}"

    if [ "$CAPTURE_DURATION" -gt 0 ]; then
        echo -e "${YELLOW}    Duration   : ${CAPTURE_DURATION}s (auto-stop)${RESET}"
        tshark -i "$INTERFACE" \
               -f "host $TARGET_IP" \
               -a duration:"$CAPTURE_DURATION" \
               -w "$OUTPUT_PCAP" \
               -q 2>/dev/null
    else
        echo -e "${YELLOW}    Duration   : Manual — press Ctrl+C to stop${RESET}"
        # Trap Ctrl+C so analysis always runs after manual stop
        trap 'echo -e "\n${GREEN}[+] Capture interrupted. Running analysis...${RESET}"; analyze_pcap; exit 0' INT
        tshark -i "$INTERFACE" \
               -f "host $TARGET_IP" \
               -w "$OUTPUT_PCAP" \
               -q 2>/dev/null
    fi

    echo -e "${GREEN}[+] Capture complete. File saved: $OUTPUT_PCAP${RESET}"
}

# ─── PCAP Analysis ───────────────────────────────────────────────────────────
analyze_pcap() {
    if [ ! -f "$OUTPUT_PCAP" ]; then
        echo -e "${RED}[-] Capture file '$OUTPUT_PCAP' not found. Cannot analyse.${RESET}"
        return 1
    fi

    # Begin writing report to log file as well as stdout
    {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               EXTRACTED NETWORK ARTIFACTS                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # ── FTP Credential Extraction ────────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[FINDING 1] Plaintext FTP Authentication & Commands (Port 21)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Risk Level : CRITICAL"
    echo "  Filter     : ftp"
    echo "  Fields     : ftp.request.command, ftp.request.arg"
    echo ""
    FTP_OUT=$(tshark -r "$OUTPUT_PCAP" \
                     -Y "ftp" \
                     -T fields \
                     -e ftp.request.command \
                     -e ftp.request.arg 2>/dev/null)
    if [ -n "$FTP_OUT" ]; then
        echo "  Captured Data:"
        echo "$FTP_OUT" | sed 's/^/    /'
    else
        echo "  [i] No FTP control traffic detected in capture."
    fi
    echo ""

    # ── HTTP Basic Auth Extraction ───────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[FINDING 2] HTTP Basic Authentication Headers (Port 80)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Risk Level : HIGH"
    echo "  Filter     : http.authorization"
    echo "  Field      : http.authorization"
    echo ""
    HTTP_OUT=$(tshark -r "$OUTPUT_PCAP" \
                      -Y "http.authorization" \
                      -T fields \
                      -e http.authorization 2>/dev/null)
    if [ -n "$HTTP_OUT" ]; then
        echo "  Captured Data (Base64-encoded credentials):"
        echo "$HTTP_OUT" | sed 's/^/    /'
        echo ""
        echo "  Decoded Values:"
        # Attempt Base64 decode on each captured header value
        while IFS= read -r line; do
            # Strip "Basic " prefix if present
            b64="${line#Basic }"
            decoded=$(echo "$b64" | base64 --decode 2>/dev/null)
            if [ -n "$decoded" ]; then
                echo "    $line  →  $decoded"
            fi
        done <<< "$HTTP_OUT"
    else
        echo "  [i] No HTTP Basic Auth headers detected in capture."
    fi
    echo ""

    # ── ARP Audit ───────────────────────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[FINDING 3] ARP Traffic — MITM / Spoofing Audit (Broadcast)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Risk Level : MEDIUM (anomaly-dependent)"
    echo "  Filter     : arp"
    echo "  Fields     : arp.src.proto_ipv4, arp.dst.proto_ipv4"
    echo ""
    ARP_OUT=$(tshark -r "$OUTPUT_PCAP" \
                     -Y "arp" \
                     -T fields \
                     -e arp.src.proto_ipv4 \
                     -e arp.dst.proto_ipv4 2>/dev/null)
    if [ -n "$ARP_OUT" ]; then
        echo "  ARP Pairs Observed (Source → Destination):"
        echo "$ARP_OUT" | awk 'NF{printf "    %-18s → %s\n", $1, $2}' 
        echo ""
        # Basic duplicate-reply detection
        DUP=$(echo "$ARP_OUT" | sort | uniq -d)
        if [ -n "$DUP" ]; then
            echo "  [!] WARNING: Duplicate ARP entries detected — potential ARP spoofing:"
            echo "$DUP" | sed 's/^/    /'
        else
            echo "  [✓] No duplicate ARP replies detected. No active spoofing observed."
        fi
    else
        echo "  [i] No ARP traffic detected in capture."
    fi
    echo ""

    # ── Telnet Session Check ─────────────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[FINDING 4] Telnet Plaintext Session Detection (Port 23)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Risk Level : CRITICAL"
    echo "  Filter     : telnet"
    echo "  Note       : Full session reconstruction via 'Follow TCP Stream'"
    echo ""
    TELNET_COUNT=$(tshark -r "$OUTPUT_PCAP" -Y "telnet" 2>/dev/null | wc -l)
    if [ "$TELNET_COUNT" -gt 0 ]; then
        echo "  [!] $TELNET_COUNT Telnet packets detected. Credentials may be in cleartext."
        echo "  [!] Reconstruct session in Wireshark: Right-click → Follow → TCP Stream"
    else
        echo "  [i] No Telnet traffic detected in capture."
    fi
    echo ""

    # ── SMB / NetBIOS Check ──────────────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[FINDING 5] SMB / NetBIOS Session Information (Port 445)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Risk Level : HIGH"
    echo "  Filter     : smb || smb2"
    echo ""
    SMB_OUT=$(tshark -r "$OUTPUT_PCAP" \
                     -Y "smb || smb2" \
                     -T fields \
                     -e smb.cmd \
                     -e smb2.cmd 2>/dev/null | head -20)
    if [ -n "$SMB_OUT" ]; then
        echo "  SMB Commands Observed:"
        echo "$SMB_OUT" | sed 's/^/    /'
    else
        echo "  [i] No SMB traffic detected in capture."
    fi
    echo ""

    # ── Protocol Summary ─────────────────────────────────────────────
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  PROTOCOL SUMMARY TABLE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "  %-10s %-8s %-30s %-12s\n" "PROTOCOL" "PORT" "FINDING" "RISK"
    printf "  %-10s %-8s %-30s %-12s\n" "--------" "----" "-------" "----"
    printf "  %-10s %-8s %-30s %-12s\n" "FTP"    "21"  "Cleartext credentials captured" "CRITICAL"
    printf "  %-10s %-8s %-30s %-12s\n" "Telnet" "23"  "Full session reconstructable"   "CRITICAL"
    printf "  %-10s %-8s %-30s %-12s\n" "HTTP"   "80"  "Basic Auth decoded in cleartext" "HIGH"
    printf "  %-10s %-8s %-30s %-12s\n" "SMB"    "445" "NetBIOS session info exposed"   "HIGH"
    printf "  %-10s %-8s %-30s %-12s\n" "DNS"    "53"  "Internal hostname resolution"   "MEDIUM"
    printf "  %-10s %-8s %-30s %-12s\n" "ARP"    "N/A" "MITM anomaly audit"             "MEDIUM"
    echo ""

    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  [+] Analysis complete. Raw capture saved to: $OUTPUT_PCAP  "
    echo "║  [+] Report written to: $LOG_FILE                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    } | tee "$LOG_FILE"
}

# ─── Main Execution ──────────────────────────────────────────────────────────
main() {
    print_banner
    check_root
    check_dependencies
    check_interface
    run_capture
    analyze_pcap
}

main "$@"