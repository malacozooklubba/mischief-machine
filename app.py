from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import subprocess

app = Flask(__name__)
app.secret_key = 'change-this-secret'  # replace with secure value in production

wifi_device = "wlan1"
wifi_hotspot = "wlan0"

throttle_enabled = False
block_enabled = False

def list_ssids():
    result = subprocess.check_output(["nmcli", "--colors", "no", "-m", "multiline", "--get-value", "SSID", "dev", "wifi", "list", "ifname", wifi_device])
    raw_ssids = result.decode().split('\n')
    ssids = []
    for ssid in raw_ssids:
        only_ssid = ssid.removeprefix("SSID:")
        if len(only_ssid) > 0:
            ssids.append(only_ssid)
    return ssids

def get_current_ssid():
    try:
        # Query active wifi connection for this interface
        result = subprocess.check_output([
            "nmcli", "-t", "-f", "active,ssid,device", "dev", "wifi"
        ])
        lines = result.decode().split('\n')
        for line in lines:
            if not line:
                continue
            parts = line.split(":")
            # Expected: active(yes/no):ssid:device
            if len(parts) >= 3 and parts[0] == "yes" and parts[2] == wifi_device:
                return parts[1]
    except Exception:
        pass
    return None

def get_hotspot_connections():
    connections = []
    try:
        # List active connections with fields we care about
        # Output: NAME:UUID:TYPE:DEVICE:ACTIVE
        out = subprocess.check_output([
            "nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,ACTIVE", "connection", "show", "--active"
        ]).decode()
        for line in out.split('\n'):
            if not line:
                continue
            parts = line.split(':')
            if len(parts) < 5:
                continue
            name, uuid, ctype, device, active = parts[:5]
            # Heuristics: include entries related to Hotspot
            if name == 'Hotspot' or device == 'Hotspot' or ctype == 'wifi' and device == wifi_device:
                connections.append({
                    'name': name,
                    'uuid': uuid,
                    'type': ctype,
                    'device': device,
                    'active': active == 'yes'
                })
    except Exception:
        pass
    return connections

def is_vpn_active(name: str = 'MyVPN'):
    """Return True if the connection 'name' is currently activated according to nmcli connection."""
    try:
        state = subprocess.check_output([
            'nmcli', '-t', '-g', 'GENERAL.STATE', 'connection', 'show', 'id', name
        ], stderr=subprocess.DEVNULL).decode().strip().lower()
        # Examples: "activated", "activated (path ...)", or "activated:..."
        return state.startswith('activated')
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False


def is_throttle_active(interface: str = wifi_hotspot):
    """Return True if traffic control is active on the interface."""
    try:
        result = subprocess.run([
            'tc', 'qdisc', 'show', 'dev', interface
        ], capture_output=True, text=True)
        # Check if HTB qdisc is present (our throttling setup)
        return result.returncode == 0 and 'htb' in result.stdout.lower()
    except Exception:
        return False


def is_block_active(interface: str = wifi_hotspot):
    """Return True if traffic blocking is active on the interface."""
    try:
        result = subprocess.run([
            'iptables', '-L', 'FORWARD', '-n', '--line-numbers'
        ], capture_output=True, text=True)
        # Check if REJECT rules are present (look for REJECT in the target column)
        lines = result.stdout.split('\n')
        for line in lines:
            # Look for lines that have REJECT in the target column (after the num column)
            parts = line.split()
            if len(parts) >= 2 and parts[1] == 'REJECT':
                return True
        return False
    except Exception:
        return False


def get_local_ip(interface: str = wifi_device):
    """Get the local IP address of the specified interface."""
    try:
        result = subprocess.check_output([
            'ip', 'addr', 'show', interface
        ], stderr=subprocess.DEVNULL).decode()
        for line in result.split('\n'):
            if 'inet ' in line and not '127.0.0.1' in line:
                # Extract IP from line like "    inet 192.168.4.1/24 brd 192.168.4.255 scope global wlan0"
                parts = line.strip().split()
                for part in parts:
                    if part.startswith('inet') and '/' in part:
                        return part.split('/')[0]
        return None
    except Exception:
        return None

def get_hotspot_clients(ap_interface: str = wifi_hotspot):
    clients = []
    mac_to_ip = {}
    leases_mac_to_name = {}
    # Build MAC->IP table from neighbor/ARP info (check all, not just one dev)
    try:
        neigh = subprocess.check_output(['ip', 'neigh', 'show']).decode()
        for line in neigh.split('\n'):
            line = line.strip()
            if not line:
                continue
            # Example: 192.168.4.12 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            parts = line.split()
            if len(parts) >= 5 and parts[2] == 'lladdr':
                ip_addr = parts[0]
                mac_addr = parts[3].lower()
                mac_to_ip[mac_addr] = ip_addr
    except Exception:
        pass

    # Try dnsmasq leases from common locations
    lease_paths = [
        '/var/lib/misc/dnsmasq.leases',
        '/var/lib/NetworkManager/dnsmasq-shared.leases'
    ]
    for lease_path in lease_paths:
        try:
            with open(lease_path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    # ts mac ip host clientid
                    if len(parts) >= 4:
                        leases_mac_to_name[parts[1].lower()] = parts[3]
        except Exception:
            continue
    try:
        out = subprocess.check_output([
            'iw', 'dev', ap_interface, 'station', 'dump'
        ]).decode()
        current = None
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('Station '):
                # Start a new client record
                mac = line.split()[1]
                if current:
                    clients.append(current)
                current = { 'mac': mac }
            elif current is not None:
                if line.startswith('signal:'):
                    # e.g., signal: -47 [-47] dBm
                    parts = line.split()
                    if len(parts) >= 2:
                        current['signal_dbm'] = parts[1]
                elif line.startswith('rx bitrate:'):
                    current['rx_bitrate'] = line.split('rx bitrate:')[-1].strip()
                elif line.startswith('tx bitrate:'):
                    current['tx_bitrate'] = line.split('tx bitrate:')[-1].strip()
                elif line.startswith('connected time:'):
                    current['connected_time'] = line.split('connected time:')[-1].strip()
        if current:
            clients.append(current)
    except Exception:
        pass
    # Resolve display names and human-friendly metadata
    def classify_device(name_or_mac: str) -> str:
        n = (name_or_mac or '').lower()
        if any(k in n for k in ['iphone', 'ipad', 'ios']):
            return 'iPhone/iPad'
        if any(k in n for k in ['android', 'pixel', 'samsung', 'oneplus']):
            return 'Android phone'
        if any(k in n for k in ['macbook', 'imac', 'mac']):
            return 'Mac computer'
        if any(k in n for k in ['windows', 'win', 'surface']):
            return 'Windows computer'
        if any(k in n for k in ['tv', 'chromecast', 'roku', 'firestick']):
            return 'TV / Streaming device'
        if any(k in n for k in ['tablet', 'ipad', 'tab']):
            return 'Tablet'
        return 'Device'

    def signal_quality(dbm: str) -> str:
        try:
            v = int(dbm)
        except Exception:
            return 'Signal: —'
        if v >= -50:
            return 'Excellent signal'
        if v >= -60:
            return 'Good signal'
        if v >= -70:
            return 'Fair signal'
        return 'Weak signal'

    def pretty_duration(raw: str) -> str:
        # raw like "432 seconds" or "12 hours 3 minutes"
        try:
            if 'second' in raw:
                secs = int(raw.split()[0])
                mins = secs // 60
                if mins < 1:
                    return 'Just connected'
                if mins < 60:
                    return f'{mins} min'
                hrs = mins // 60
                return f'{hrs} hr'
            return raw
        except Exception:
            return raw or 'Online'

    resolved = []
    for c in clients:
        mac = c.get('mac', '').lower()
        ip = mac_to_ip.get(mac)
        name = None
        # Prefer leases hostname if non-asterisk
        candidate = leases_mac_to_name.get(mac)
        if candidate and candidate != '*':
            name = candidate
        # Fallback to reverse DNS (getent hosts)
        if not name and ip:
            try:
                host_out = subprocess.check_output(['getent', 'hosts', ip]).decode().strip()
                if host_out:
                    name = host_out.split()[-1]
            except Exception:
                pass
        # Final fallback: mDNS/Avahi if available
        if not name and ip:
            try:
                avahi = subprocess.check_output(['avahi-resolve-address', ip], stderr=subprocess.DEVNULL).decode().strip()
                if avahi:
                    segs = avahi.split('\t')
                    if len(segs) >= 2:
                        name = segs[1]
            except Exception:
                pass
        c['ip'] = ip
        display_name = name or ''
        if not display_name or display_name == '*' or display_name == mac:
            display_name = classify_device(name or mac)
        c['name'] = display_name
        c['subtitle'] = f"{pretty_duration(c.get('connected_time',''))} · {signal_quality(c.get('signal_dbm',''))}"
        resolved.append(c)
    return resolved

@app.route('/')
def index():
    ctx = build_context()
    return render_template('index.html', **ctx)


def build_context():
    ssids = list_ssids()
    current_ssid = get_current_ssid()
    hotspot_connections = get_hotspot_connections()
    hotspot_clients = get_hotspot_clients(wifi_hotspot)
    vpn_enabled_current = is_vpn_active()
    throttle_enabled_current = is_throttle_active()
    block_enabled_current = is_block_active()
    local_ip = get_local_ip(wifi_device)
    return {
        'ssids': ssids,
        'current_ssid': current_ssid,
        'vpn_enabled': vpn_enabled_current,
        'throttle_enabled': throttle_enabled_current,
        'block_enabled': block_enabled_current,
        'hotspot_connections': hotspot_connections,
        'hotspot_clients': hotspot_clients,
        'local_ip': local_ip,
    }


@app.route('/status')
def status():
    try:
        data = {
            'current_ssid': get_current_ssid(),
            'vpn_enabled': is_vpn_active(),
            'throttle_enabled': is_throttle_active(),
            'block_enabled': is_block_active(),
            'hotspot_clients': get_hotspot_clients(wifi_hotspot)
        }
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/submit',methods=['POST'])
def submit():
    if request.method == 'POST':
        print(*list(request.form.keys()), sep = ", ")
        ssid = request.form['ssid']
        password = request.form['password']
        connection_command = ["nmcli", "--colors", "no", "device", "wifi", "connect", ssid, "ifname", wifi_device]
        if len(password) > 0:
          connection_command.append("password")
          connection_command.append(password)
        result = subprocess.run(connection_command, capture_output=True)
        if result.stderr:
            flash(result.stderr.decode(), 'error')
        elif result.stdout:
            flash(f"Connected to {ssid}", 'success')
        else:
            flash('Failed to connect.', 'error')

        return redirect(url_for('index'))


@app.route('/toggle_vpn', methods=['POST'])
def toggle_vpn():
    values = request.form.getlist('enabled')
    should_enable = '1' in values
    wants_json = 'application/json' in (request.headers.get('Accept') or '')
    try:
        if should_enable:
            result = subprocess.run(["nmcli", "connection", "up", "MyVPN"], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.decode() or result.stdout.decode() or 'Failed to start VPN')
        else:
            result = subprocess.run(["nmcli", "connection", "down", "MyVPN"], capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.decode() or result.stdout.decode() or 'Failed to stop VPN')
    except Exception as e:
        if wants_json:
            return jsonify({'error': f"VPN toggle error: {e}"}), 400
        flash(f"VPN toggle error: {e}", 'error')
        return redirect(url_for('index'))
    if wants_json:
        # Reflect the intended target state immediately; background poll will reconcile actual state
        return jsonify({'ok': True, 'vpn_enabled': should_enable})
    return redirect(url_for('index'))


@app.route('/toggle_throttle', methods=['POST'])
def toggle_throttle():
    global throttle_enabled
    values = request.form.getlist('enabled')
    should_enable = '1' in values
    wants_json = 'application/json' in (request.headers.get('Accept') or '')
    
    try:
        if should_enable:
            print(f"Enabling throttling on {wifi_hotspot}...")
            # First clear any existing rules
            subprocess.run(['tc', 'qdisc', 'del', 'dev', wifi_hotspot, 'root'], check=False)
            
            # Enable throttling: limit to 20kbps (very slow for debugging)
            # Create HTB root qdisc
            result1 = subprocess.run([
                'tc', 'qdisc', 'add', 'dev', wifi_hotspot, 'root', 'handle', '1:', 'htb', 'default', '1'
            ], capture_output=True, text=True)
            print(f"HTB qdisc result: {result1.returncode}, {result1.stderr}")
            
            # Create main class with very low rate
            result2 = subprocess.run([
                'tc', 'class', 'add', 'dev', wifi_hotspot, 'parent', '1:', 'classid', '1:1', 'htb', 'rate', '20kbps', 'ceil', '20kbps'
            ], capture_output=True, text=True)
            print(f"HTB class result: {result2.returncode}, {result2.stderr}")
            
            # Add delay and packet loss for more realistic slow network
            result3 = subprocess.run([
                'tc', 'qdisc', 'add', 'dev', wifi_hotspot, 'parent', '1:1', 'handle', '10:', 'netem', 'delay', '500ms', 'loss', '5%'
            ], capture_output=True, text=True)
            print(f"Netem result: {result3.returncode}, {result3.stderr}")
            
            throttle_enabled = True
        else:
            print(f"Disabling throttling on {wifi_hotspot}...")
            # Disable throttling: remove traffic control
            result = subprocess.run(['tc', 'qdisc', 'del', 'dev', wifi_hotspot, 'root'], capture_output=True, text=True)
            print(f"Remove qdisc result: {result.returncode}, {result.stderr}")
            throttle_enabled = False
    except subprocess.CalledProcessError as e:
        if wants_json:
            return jsonify({'error': f"Throttle toggle error: {e}"}), 400
        flash(f"Throttle toggle error: {e}", 'error')
        return redirect(url_for('index'))
    except Exception as e:
        if wants_json:
            return jsonify({'error': f"Throttle toggle error: {e}"}), 400
        flash(f"Throttle toggle error: {e}", 'error')
        return redirect(url_for('index'))
    
    if wants_json:
        return jsonify({'ok': True, 'throttle_enabled': throttle_enabled})
    return redirect(url_for('index'))


@app.route('/toggle_block', methods=['POST'])
def toggle_block():
    global block_enabled
    values = request.form.getlist('enabled')
    should_enable = '1' in values
    wants_json = 'application/json' in (request.headers.get('Accept') or '')
    
    try:
        if should_enable:
            print(f"Enabling network blocking on {wifi_hotspot}...")
            # Block all forwarded traffic on {wifi_hotspot} with immediate REJECT (not DROP)
            subprocess.run([
                'iptables', '-I', 'FORWARD', '-i', wifi_hotspot, '-j', 'REJECT', '--reject-with', 'icmp-host-unreachable'
            ], check=True)
            subprocess.run([
                'iptables', '-I', 'FORWARD', '-o', wifi_hotspot, '-j', 'REJECT', '--reject-with', 'icmp-host-unreachable'
            ], check=True)
            block_enabled = True
        else:
            print(f"Disabling network blocking on {wifi_hotspot}...")
            # flush all FORWARD rules and restore basic ones
            subprocess.run(['iptables', '-F', 'FORWARD'], check=False)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=False)
            
            block_enabled = False
    except subprocess.CalledProcessError as e:
        if wants_json:
            return jsonify({'error': f"Block toggle error: {e}"}), 400
        flash(f"Block toggle error: {e}", 'error')
        return redirect(url_for('index'))
    except Exception as e:
        if wants_json:
            return jsonify({'error': f"Block toggle error: {e}"}), 400
        flash(f"Block toggle error: {e}", 'error')
        return redirect(url_for('index'))
    
    if wants_json:
        return jsonify({'ok': True, 'block_enabled': block_enabled})
    return redirect(url_for('index'))

@app.route('/api/wlan0-status', methods=['GET'])
def get_wlan0_status():
    """Get WLAN0 interface status, IP address, and SSID"""
    try:
        # Check if wlan0 interface exists and is up
        result = subprocess.check_output(['ip', 'link', 'show', wifi_hotspot], stderr=subprocess.DEVNULL)
        status = "Connected" if b"state UP" in result else "Disconnected"
        
        # Get IP address and SSID if interface is up
        ip_address = "Not assigned"
        ssid = "Not connected"
        
        if status == "Connected":
            try:
                # Get IP address
                ip_result = subprocess.check_output(['ip', 'addr', 'show', wifi_hotspot], stderr=subprocess.DEVNULL)
                import re
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.decode())
                if ip_match:
                    ip_address = ip_match.group(1)
                
                # Get SSID using nmcli
                ssid_result = subprocess.check_output([
                    'nmcli', '-t', '-f', 'active,ssid,device', 'dev', 'wifi'
                ], stderr=subprocess.DEVNULL)
                
                lines = ssid_result.decode().split('\n')
                for line in lines:
                    if not line:
                        continue
                    parts = line.split(":")
                    # Expected: active(yes/no):ssid:device
                    if len(parts) >= 3 and parts[0] == "yes" and parts[2] == wifi_hotspot:
                        ssid = parts[1] if parts[1] else "Unknown"
                        break
            except:
                pass
        
        return jsonify({
            'status': status,
            'ip': ip_address,
            'ssid': ssid
        })
    except subprocess.CalledProcessError:
        return jsonify({
            'status': 'Interface not found',
            'ip': 'N/A',
            'ssid': 'N/A'
        })
    except Exception as e:
        return jsonify({
            'status': 'Error',
            'ip': 'Unable to detect',
            'ssid': 'Unable to detect'
        }), 500

@app.route('/api/wlan1-status', methods=['GET'])
def get_wlan1_status():
    """Get WLAN1 interface status, IP address, and SSID"""
    try:
        # Check if wlan1 interface exists and is up
        result = subprocess.check_output(['ip', 'link', 'show', wifi_device], stderr=subprocess.DEVNULL)
        status = "Connected" if b"state UP" in result else "Disconnected"
        
        # Get IP address and SSID if interface is up
        ip_address = "Not assigned"
        ssid = "Not connected"
        
        if status == "Connected":
            try:
                # Get IP address
                ip_result = subprocess.check_output(['ip', 'addr', 'show', wifi_device], stderr=subprocess.DEVNULL)
                import re
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.decode())
                if ip_match:
                    ip_address = ip_match.group(1)
                
                # Get SSID using nmcli
                ssid_result = subprocess.check_output([
                    'nmcli', '-t', '-f', 'active,ssid,device', 'dev', 'wifi'
                ], stderr=subprocess.DEVNULL)
                
                lines = ssid_result.decode().split('\n')
                for line in lines:
                    if not line:
                        continue
                    parts = line.split(":")
                    # Expected: active(yes/no):ssid:device
                    if len(parts) >= 3 and parts[0] == "yes" and parts[2] == wifi_device:
                        ssid = parts[1] if parts[1] else "Unknown"
                        break
            except:
                pass
        
        return jsonify({
            'status': status,
            'ip': ip_address,
            'ssid': ssid
        })
    except subprocess.CalledProcessError:
        return jsonify({
            'status': 'Interface not found',
            'ip': 'N/A',
            'ssid': 'N/A'
        })
    except Exception as e:
        return jsonify({
            'status': 'Error',
            'ip': 'Unable to detect',
            'ssid': 'Unable to detect'
        }), 500

@app.route('/api/reset-system', methods=['POST'])
def reset_system():
    """Reset all system settings and connections"""
    try:
        subprocess.run(['nmcli', 'connection', 'down', 'id', 'MyVPN'], check=False)
        
        # Reset network manager
        subprocess.run(['nmcli', 'networking', 'off'], check=False)
        subprocess.run(['nmcli', 'networking', 'on'], check=False)
        
        # Clear any throttling or blocking rules
        subprocess.run(['tc', 'qdisc', 'del', 'dev', wifi_device, 'root'], check=False)
        subprocess.run(['iptables', '-F'], check=False)
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=False)

        subprocess.run(['nmcli', 'connection', 'up', 'Hotspot'], check=False)
        subprocess.run(['nmcli', 'connection', 'up', 'MyVPN'], check=False)
        
        return jsonify({'success': True, 'message': 'System reset completed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)