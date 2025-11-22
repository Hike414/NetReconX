# NetReconX

A hybrid cybersecurity tool combining functionalities of Nmap, Wireshark, Seeker, Zphisher, and Honeypot into a modular CLI and GUI framework.

## Features

- **Network Scanner**: Port scanning and service detection
- **Packet Sniffer**: Real-time network traffic analysis
- **Phishing Tool**: Template-based phishing campaigns with geolocation
- **Honeypot**: Multi-port honeypot with logging capabilities
- **Hybrid Interface**: Both CLI and GUI interfaces available

## Requirements

- Python 3.8+
- Nmap
- Wireshark/tshark
- Root/Administrator privileges (for some features)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Hike414/NetReconX.git
cd NetReconX
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies:
- Windows: Install Nmap and Wireshark
- Linux: `sudo apt-get install nmap wireshark`

## Usage

### CLI Interface

```bash
# Network scanning
python main.py scan --target 192.168.1.0/24

# Packet sniffing
python main.py sniff --iface eth0

# Phishing
python main.py phish --template instagram

# Honeypot
python main.py honeypot --start

# Launch GUI
python main.py gui
```

### GUI Interface

1. Launch the GUI:
```bash
python main.py gui
```

2. Use the tabbed interface to access different tools:
- Scanner: Enter target and start scan
- Sniffer: Select interface and start/stop capture
- Phisher: Select template and start campaign
- Honeypot: Start/stop honeypot service

## Configuration

Create a `.env` file in the project root with the following variables:
```
IPINFO_TOKEN=your_ipinfo_api_token
```

## Security Note

This tool is for educational and authorized testing purposes only. Unauthorized use against systems you don't own or have permission to test is illegal.

## License

MIT License

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. Use at your own risk. 