Network Recon 
Automated Network Mapping & Vulnerability Detection Tool
The Network Recon is a powerful and efficient Bash script designed for comprehensive network reconnaissance. Built for cybersecurity professionals and enthusiasts, it automates various Nmap scans to identify open ports, detect service versions, fingerprint operating systems, and pinpoint basic vulnerabilities across target IP addresses or entire subnets. This tool streamlines the initial information gathering phase of penetration testing and vulnerability assessments, delivering organized and actionable intelligence.

✨ Features
Target Flexibility: Scans single IP addresses or entire CIDR ranges (e.g., 192.168.1.0/24).

Comprehensive Scanning:

Quick Scan (-F): Rapidly checks the top 1000 most common ports.

Detailed Scan (-p- -sV -O): Performs a full port scan (0-65535), identifies service versions, and attempts OS detection.

Vulnerability Script Scan (-sC --script vuln): Executes Nmap's default scripts and a selection of common vulnerability checks to identify known weaknesses.

Intelligent Output Management: Organizes all Nmap outputs (normal, XML, grepable) into a unique, timestamped directory for easy review.

Summarized Reporting: Generates a concise defcon.txt report summarizing open ports, identified services, web services (HTTP/HTTPS), and hints about firewall presence.

Performance Optimized: Configured with -T4 timing for a balance of speed and network impact.

🚀 Getting Started
To use the Network Recon, ensure you have Nmap installed on your system.

Prerequisites:

Nmap: Install Nmap if you haven't already.

Debian/Ubuntu: sudo apt update && sudo apt install nmap

Arch Linux: sudo pacman -S nmap

Fedora/RHEL: sudo dnf install nmap

macOS (with Homebrew): brew install nmap

Bash: The script runs on Bash (standard on most Linux/macOS systems).

Installation:

Clone the repository:

cd Network-Recon

Make the script executable:

chmod +x Network_recon.sh

💡 Usage
Run the script from your terminal, providing the target IP address or CIDR range as an argument.

./Network_recon.sh <target_ip_or_range>

Examples:

Scan a single IP address:

./recon_sentinel.sh 192.168.1.1

Scan an entire subnet:

./recon_sentinel.sh 10.10.237.0/24

Output:

All scan results, including the defcon.txt summary report, will be saved in a timestamped directory under ~/recon_audits/.

⚙️ Configuration (Optional)
You can customize the script by editing the recon.sh file:

LOG_BASE_DIR: Change the base directory where scan outputs are stored (default: ~/recon_audits).

NMAP_TIMING: Adjust Nmap's timing template (-T4 by default for aggressive speed). Consider -T2 for stealth or -T5 for maximum speed (can be very noisy).

📊 Output Example (defcon.txt snippet)
--- Network Recon Sentinel ---
Scan started at: 2024-06-11 14:30:00
Target(s): 10.11.227.75
Output directory: /home/youruser/recon_audits/scan_20240611_143000_10_10_237_72
Nmap Timing: -T4
------------------------------

[*] Running Quick Scan (Top 1000 Ports)...
... (Nmap output) ...
Quick scan complete.

... (Other scan outputs) ...

--- Scan Summary ---
[*] Hosts found and their open ports:
  - Host: 10.11.227.75 (Open Ports: 22,80,3306)
    22/tcp  open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
    80/tcp  open  http    Apache httpd 2.4.62 ((Debian))
    3306/tcp open mysql   MariaDB (unauthorized)

--- Web Service Check (across all scanned hosts) ---
[*] Web Service: http://10.11.227.75:80 (Service: http)

--- Firewall/Filtering Hints ---
[*] No 'filtered' ports explicitly found, but this doesn't guarantee no firewall.


📈 Future Enhancements (Ideas for Expansion)
External API Intergration

Advanced Reporting: Generate HTML or PDF reports with visualizations.

Notification System: Add options for email, Slack, or Telegram notifications on scan completion or critical findings.

Port Specific Scripting: Run more targeted Nmap scripts based on identified open ports (e.g., smb-enum-shares if 445/tcp is open).

Dockerization: Package the tool in a Docker container for easier deployment.

🤝 Contributing
Contributions are welcome! If you have ideas for improvements or find bugs, feel free to open an issue or submit a pull request.

📄 License
This project is licensed under the General Public License. See the LICENSE file for details.

📧 Contact
For any questions or feedback, feel free to reach out:

GitHub: @Bakhuya
