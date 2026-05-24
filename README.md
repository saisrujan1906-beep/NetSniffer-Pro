# NetSniffer Pro v3.1 🔐

> A real-time network packet sniffer, analyzer, and threat detector built in Python on Parrot OS.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Parrot%20OS-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-Educational-red)

---

## About

NetSniffer Pro is a powerful command-line network analysis tool built for security enthusiasts and professionals. It captures and analyzes live network traffic in real time, detects threats automatically, and generates detailed session reports with CSV export support.

Built entirely from scratch using Python and Scapy on Parrot OS.

---

## Features

- **Interface selector** — choose your network interface at startup
- **Live packet capture** — real-time packet sniffing with live counter and rate monitor
- **Advanced filtering** — filter by IP address, multiple ports, and protocol
- **30+ service labels** — automatic detection of HTTP, HTTPS, SSH, FTP, DNS, MySQL, RDP, VNC and more
- **Threat detection:**
  - Port scan detection
  - ARP spoofing detection
  - ICMP flood detection
- **Geo-IP lookup** — shows country, city and organization of each IP
- **Top talkers report** — shows the most active IPs in the session
- **Session duration timer** — tracks how long the capture ran
- **CSV export** — auto-saves packet logs and threat logs with timestamps
- **Color-coded CLI output** — green=TCP, cyan=DNS, yellow=UDP, blue=ICMP, red=threats

---

## Requirements

- Parrot OS / Kali Linux / any Debian-based Linux
- Python 3.x
- Scapy
- Colorama

---

## Installation

```bash
# Clone the repository
git clone https://github.com/saisrujan1906-beep/NetSniffer-Pro.git

# Move into the folder
cd NetSniffer-Pro

# Install required libraries
sudo pip3 install scapy colorama --break-system-packages
```

---

## Usage

```bash
sudo python3 sniffer.py
```

Then follow the interactive menu:

1. Select your network interface (e.g. eth0, enp0s3, wlan0)
2. Set IP filter — enter a specific IP or leave blank for ALL
3. Set port filter — single or multiple ports e.g. 80,443,53
4. Set protocol filter — TCP / UDP / ICMP / ALL
5. Set packet count — how many packets to capture
6. Enable or disable Geo-IP lookup

Press `Ctrl+C` at any time to stop the capture early and view the session report.

---

## Color Code Guide

| Color | Meaning |
|-------|---------|
| Green | TCP packets |
| Yellow | UDP packets |
| Blue | ICMP ping packets |
| Cyan | DNS queries |
| Red | Threats detected |

---

## Threat Detection

| Threat | How it works |
|--------|-------------|
| Port scan | Flags any IP hitting 15+ different ports |
| ARP spoofing | Detects when an IP suddenly changes its MAC address |
| ICMP flood | Flags any IP sending 20+ pings rapidly |

---

## Common Ports Reference

| Port | Service |
|------|---------|
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |
| 5900 | VNC |
| 8080 | HTTP-ALT |
| 27017 | MongoDB |

---

## Screenshots

### Startup & Interface Selection
![Startup](screenshots/startup_banner.png)

### Configuration Menu
![Config](screenshots/config_menu.png)

### Live Packet Capture
![Live Capture](screenshots/live_capture.png)

### Session Summary Report
![Summary](screenshots/summary_report.png)

---

## How It Works

1. The tool starts by scanning available network interfaces on your machine
2. You configure your capture session through an interactive menu
3. Scapy listens on your chosen interface and captures packets in real time
4. Each packet is analyzed — protocol identified, ports labeled, threats checked
5. At the end of the session a full summary report is printed and saved to CSV

---

## Project Structure

```
NetSniffer-Pro/
│
├── sniffer.py              # Main tool - packet capture & analysis
├── README.md               # Documentation
├── capture_*.csv           # Auto-generated packet capture logs
├── threats_*.csv           # Auto-generated threat detection logs
└── screenshots/
    ├── startup_banner.png  # Startup & interface selection
    ├── config_menu.png     # Configuration menu
    ├── live_capture.png    # Live packet capture output
    └── summary_report.png  # Session summary report
```

---

## Disclaimer

This tool is strictly for **educational and authorized network analysis only.**
Unauthorized interception of network traffic is illegal and punishable by law.
Only use this tool on networks you own or have explicit permission to monitor.
The author takes no responsibility for any misuse of this tool.

---

## Author

**Sai Srujan**
- GitHub: [@saisrujan1906-beep](https://github.com/saisrujan1906-beep)
