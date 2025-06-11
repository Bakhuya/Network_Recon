#!/bin/bash

#This is an Automated Network Mapping & Service Enumeration
# Developed by defcon_ke - A foundational tool.

# --- Configuration ---
# Directory to store all scan outputs
LOG_BASE_DIR="$HOME/recon_audits" # Change this to your preferred base directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_IP=""
SCAN_DIR=""
REPORT_FILE=""

# Nmap Timing Template: -T4 is aggressive but generally safe for speed. -T5 is faster but noisier.
NMAP_TIMING="-T4" 

# --- Functions ---

setup_environment() {
    # Create the base log directory if it doesn't exist
    mkdir -p "$LOG_BASE_DIR"

    # Create a unique directory for this specific scan
    SCAN_DIR="${LOG_BASE_DIR}/scan_${TIMESTAMP}_$(echo "$TARGET_IP" | tr './' '_')" 
    mkdir -p "$SCAN_DIR"

    # Define the report file path
    REPORT_FILE="${SCAN_DIR}/defcon.txt"

    echo "--- Network Recon Sentinel ---" | tee "$REPORT_FILE"
    echo "Scan started at: $(date)" | tee -a "$REPORT_FILE"
    echo "Target(s): $TARGET_IP" | tee -a "$REPORT_FILE"
    echo "Output directory: $SCAN_DIR" | tee -a "$REPORT_FILE"
    echo "Nmap Timing: ${NMAP_TIMING}" | tee -a "$REPORT_FILE"
    echo "------------------------------" | tee -a "$REPORT_FILE"
}

run_quick_scan() {
    echo "" | tee -a "$REPORT_FILE"
    echo "[*] Running Quick Scan (Top 1000 Ports)..." | tee -a "$REPORT_FILE"
    # -F : Fast mode (scans top 1000 ports)
    # -oA : Output in all formats
    NMAP_CMD="nmap ${NMAP_TIMING} -F -oA \"${SCAN_DIR}/quick_scan\" \"$TARGET_IP\""
    eval "$NMAP_CMD" | tee -a "$REPORT_FILE"
    echo "Quick scan complete." | tee -a "$REPORT_FILE"
}

run_detailed_scan() {
    echo "" | tee -a "$REPORT_FILE"
    echo "[*] Running Detailed Scan (Service Versions, OS Detection, Firewall Hints)..." | tee -a "$REPORT_FILE"

    NMAP_CMD="nmap ${NMAP_TIMING} -p- -sV -O --reason -oA \"${SCAN_DIR}/detailed_scan\" \"$TARGET_IP\""
    eval "$NMAP_CMD" | tee -a "$REPORT_FILE"
    echo "Detailed scan complete." | tee -a "$REPORT_FILE"
}

run_script_scan() {
    echo "" | tee -a "$REPORT_FILE"
    echo "[*] Running Nmap Script Scan (Default & Basic Vulnerability Scripts)..." | tee -a "$REPORT_FILE"
  .
    NMAP_CMD="nmap ${NMAP_TIMING} -sC --script vuln -oA \"${SCAN_DIR}/script_scan\" \"$TARGET_IP\""
    eval "$NMAP_CMD" | tee -a "$REPORT_FILE"
    echo "Script scan complete." | tee -a "$REPORT_FILE"
}

summarize_results() {
    echo "" | tee -a "$REPORT_FILE"
    echo "--- Scan Summary ---" | tee -a "$REPORT_FILE"

    # Get open ports from the detailed scan XML output for robust parsing
    # This will now include hosts in a subnet scan
    echo "[*] Hosts found and their open ports:" | tee -a "$REPORT_FILE"
    grep -oP 'host starttime="\K[^"]+"[^>]*>.*?<address addr="([^"]+)"' "${SCAN_DIR}/detailed_scan.xml" | while read -r line; do
        HOST_IP=$(echo "$line" | grep -oP 'addr="\K[^"]+')
        # Extract open ports for this specific host
        HOST_PORTS=$(grep -A 20 "<address addr=\"$HOST_IP\"" "${SCAN_DIR}/detailed_scan.xml" | grep -oP 'portid="\K\d+" state="open"' | cut -d'"' -f1 | paste -sd,)
        if [ -n "$HOST_PORTS" ]; then
            echo "  - Host: $HOST_IP (Open Ports: $HOST_PORTS)" | tee -a "$REPORT_FILE"
            # Get service details for this host and its open ports
            grep -A 20 "Host: $HOST_IP" "${SCAN_DIR}/detailed_scan.nmap" | grep -E "^\s*(${HOST_PORTS//,/|})/tcp" | tee -a "$REPORT_FILE"
        else
            echo "  - Host: $HOST_IP (No open ports found or not detailed in nmap output)" | tee -a "$REPORT_FILE"
        fi
    done
    echo "" | tee -a "$REPORT_FILE"

    # Check for web services (Port 80/443) on all found hosts
    echo "--- Web Service Check (across all scanned hosts) ---" | tee -a "$REPORT_FILE"
    WEB_SERVICES_FOUND=false
    grep -E "80/tcp.*open.*http|443/tcp.*open.*ssl/http" "${SCAN_DIR}/detailed_scan.nmap" | while read -r line; do
        HOST=$(echo "$line" | grep -oP 'Nmap scan report for \K\S+') # Extract IP from "Nmap scan report for X.X.X.X"
        PORT=$(echo "$line" | grep -oP '^\s*\K\d+')
        SERVICE=$(echo "$line" | grep -oP 'open\s+\S+\s+\K\S+')
        if [ -n "$HOST" ]; then
            echo "[*] Web Service: http://${HOST}:${PORT} (Service: ${SERVICE})" | tee -a "$REPORT_FILE"
            WEB_SERVICES_FOUND=true
        else
             echo "[*] Web Service: ${line}" | tee -a "$REPORT_FILE" # Fallback if host extraction fails
             WEB_SERVICES_FOUND=true
        fi
    done
    if [ "$WEB_SERVICES_FOUND" = false ]; then
        echo "No standard HTTP/HTTPS services found on any host." | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"

    # Firewall Detection Hints
    echo "--- Firewall/Filtering Hints ---" | tee -a "$REPORT_FILE"
    if grep -q "reason: filtered" "${SCAN_DIR}/detailed_scan.nmap"; then
        echo "[!] Some ports are reported as 'filtered', suggesting a firewall or packet filtering is present." | tee -a "$REPORT_FILE"
        echo "    Review '${SCAN_DIR}/detailed_scan.nmap' for --reason output details." | tee -a "$REPORT_FILE"
    else
        echo "[*] No 'filtered' ports explicitly found, but this doesn't guarantee no firewall." | tee -a "$REPORT_FILE"
    fi
    echo "" | tee -a "$REPORT_FILE"

    echo "Full Nmap outputs are located in: $SCAN_DIR" | tee -a "$REPORT_FILE"
    echo "Scan summary complete. Report saved to $REPORT_FILE" | tee -a "$REPORT_FILE"
}

# --- Main Execution ---
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip_or_range>"
    echo "Example: $0 192.168.1.1"
    echo "Example: $0 10.10.237.0/24" # This will scan the entire subnet
    exit 1
fi

TARGET_IP="$1"

# Basic check for Nmap
if ! command -v nmap &> /dev/null; then
    echo "Error: Nmap is not installed. Please install Nmap to run this script." | tee -a "$REPORT_FILE"
    exit 1
fi

setup_environment
run_quick_scan
run_detailed_scan
run_script_scan
summarize_results

echo "--- All scans finished ---" | tee -a "$REPORT_FILE"