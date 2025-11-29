import socket
import threading
import time
import concurrent.futures
from typing import List, Dict, Optional

class PortScanner:
    def __init__(self, max_threads: int = 50):
        self.max_threads = max_threads
    
    def ping_host(self, host: str, timeout: int = 5) -> bool:
        """Check if host is up using TCP connection to echo port"""
        try:
            with socket.create_connection((host, 7), timeout=timeout):
                return True
        except (socket.timeout, socket.error, OSError):
            try:
                with socket.create_connection((host, 80), timeout=timeout):
                    return True
            except (socket.timeout, socket.error, OSError):
                return False
    
    def scan_port(self, host: str, port: int, timeout: int = 3) -> Optional[Dict]:
        """Scan a single port"""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                
                return {
                    'port': port,
                    'status': 'open',
                    'service': service
                }
        except (socket.timeout, socket.error, OSError):
            return None
    
    def scan_range(self, host: str, start_port: int, end_port: int) -> List[Dict]:
        """Scan a range of ports"""
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for port in range(start_port, end_port + 1):
                future = executor.submit(self.scan_port, host, port)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def scan_common_ports(self, host: str) -> List[Dict]:
        """Scan common ports (1-5000)"""
        return self.scan_range(host, 1, 5000)
    
    def scan_custom_ports(self, host: str, ports: List[int]) -> List[Dict]:
        """Scan custom list of ports"""
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for port in ports:
                future = executor.submit(self.scan_port, host, port)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports, key=lambda x: x['port'])
