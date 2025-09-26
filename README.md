# Mischief Machine

A Flask-based web application for managing WiFi hotspot connections, VPN settings, and network controls.

![Mischief Machine Interface](interface-preview.png)

## Quick Start

### Prerequisites
- Python 3.6+
- NetworkManager (`nmcli`)
- `iptables` and `tc` for network controls

### Installation
```bash
git clone <repository-url>
cd mischief-machine
pip install -r requirements.txt
```

### Configuration
Edit `app.py` and update the interface variables:
```python
wifi_device = "wlan1"    # Your WiFi interface
wifi_hotspot = "wlan0"   # Your hotspot interface
```

### Run the Application
```bash
python app.py
```

Access the web interface at `http://localhost:80`

## Deployment

### Using the Deploy Script
```bash
./deploy.sh --host <remote_host> --dir <remote_directory>
```

**Examples:**
```bash
# Deploy to Raspberry Pi
./deploy.sh --host pi@192.168.1.100 --dir ~/mischief-machine

# Deploy with service restart
./deploy.sh --host pi@192.168.1.100 --dir ~/mischief-machine --service hotspot.service
```

**Deploy Script Options:**
- `--host <host>`: Remote host (required)
- `--dir <directory>`: Target directory (required)
- `--service <service>`: Systemd service name to restart
- `--clean`: Clean remote directory before deployment

### Manual Deployment
```bash
# Copy files
rsync -az --delete --exclude "*.pyc" --exclude "__pycache__/" --exclude ".git/" --exclude "venv/" ./ pi@192.168.1.100:~/mischief-machine/

# Setup on remote device
ssh pi@192.168.1.100
cd ~/mischief-machine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install system scripts
sudo cp start_hotspot.sh /usr/local/bin/start_hotspot.sh
sudo chmod +x /usr/local/bin/start_hotspot.sh
```

## Features

- **WiFi Management**: Scan and connect to available networks
- **Hotspot Monitoring**: View connected clients and their details
- **VPN Control**: Enable/disable VPN connections
- **Network Throttling**: Limit bandwidth to simulate slow connections
- **Network Blocking**: Block all network traffic
- **System Reset**: Reset all network configurations

## API Endpoints

- `GET /status` - Get current system status
- `GET /api/wlan0-status` - Get wlan0 interface status
- `GET /api/wlan1-status` - Get wlan1 interface status
- `POST /toggle_vpn` - Toggle VPN connection
- `POST /toggle_throttle` - Toggle network throttling
- `POST /toggle_block` - Toggle network blocking
- `POST /api/reset-system` - Reset all system settings