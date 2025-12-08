import subprocess
import re
import platform
from typing import Optional, Dict

class MacLocator:
    def __init__(self):
        self.system = platform.system().lower()
    
    def get_local_mac(self) -> Optional[str]:
        """Get local MAC address"""
        try:
            if self.system == "windows":
                result = subprocess.run(['getmac', '/v'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Ethernet' in line or 'Wi-Fi' in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0)
            
            elif self.system == "linux":
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'link/ether' in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0)
            
            elif self.system == "darwin":  # macOS
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'ether' in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0)
        
        except Exception:
            pass
        
        return None
    
    def get_arp_table(self) -> list:
        """Get ARP table entries"""
        arp_entries = []
        
        try:
            if self.system == "windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'dynamic' in line or 'static' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            arp_entries.append({'ip': ip, 'mac': mac})
            
            elif self.system in ["linux", "darwin"]:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '(' in line and ')' in line:
                        match = re.search(r'(\S+) \((\S+)\) at (\S+)', line)
                        if match:
                            hostname = match.group(1)
                            ip = match.group(2)
                            mac = match.group(3)
                            arp_entries.append({'hostname': hostname, 'ip': ip, 'mac': mac})
        
        except Exception:
            pass
        
        return arp_entries
    
    def mac_vendor_lookup(self, mac: str) -> Optional[str]:
        """Simple MAC vendor lookup (first 3 octets)"""
        # This is a simplified version - in practice you'd use a MAC vendor database
        vendor_prefixes = {
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:03:FF': 'Microsoft Hyper-V',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi Foundation',
            '28:CD:C1': 'Raspberry Pi Foundation',
            'B8:AE:ED': 'Raspberry Pi Foundation',
            'E4:5F:01': 'Google',
            '3C:37:86': 'Google',
            'A4:C1:61': 'Google',
        }
        
        # Normalize MAC format
        mac_clean = mac.upper().replace('-', ':')
        if len(mac_clean) >= 8:
            prefix = mac_clean[:8]
            return vendor_prefixes.get(prefix, 'Unknown')
        
        return 'Unknown'
    
    def scan_network_for_macs(self, network_range: str) -> list:
        """Scan network for MAC addresses (requires nmap)"""
        devices = []
        
        try:
            # Try to use nmap for network scanning
            result = subprocess.run(['nmap', '-sn', network_range], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse nmap output for MAC addresses
                mac_pattern = r'MAC Address: ([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}) \(([^)]+)\)'
                ip_pattern = r'Nmap scan report for ([^)]+) \(([\d.]+)\)'
                
                lines = result.stdout.split('\n')
                current_ip = None
                
                for line in lines:
                    ip_match = re.search(ip_pattern, line)
                    if ip_match:
                        current_ip = ip_match.group(2)
                    
                    mac_match = re.search(mac_pattern, line)
                    if mac_match and current_ip:
                        mac = mac_match.group(0).split(' ')[2]
                        vendor = mac_match.group(3)
                        devices.append({'ip': current_ip, 'mac': mac, 'vendor': vendor})
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback to ARP table if nmap not available
            arp_entries = self.get_arp_table()
            for entry in arp_entries:
                vendor = self.mac_vendor_lookup(entry['mac'])
                entry['vendor'] = vendor
                devices.append(entry)
        
        return devices
    
    def validate_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))
