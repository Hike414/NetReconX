import socket
import threading
import json
from datetime import datetime
from typing import Dict, List
import os

class Honeypot:
    def __init__(self):
        self.ports = [21, 22, 23, 80, 443, 3306, 3389]  # Common ports to monitor
        self.sockets = []
        self.connections = []
        self.logs = []
        self.is_running = False
    
    def start(self):
        """Start the honeypot server"""
        try:
            self.is_running = True
            
            # Create sockets for each port
            for port in self.ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', port))
                sock.listen(5)
                self.sockets.append(sock)
                
                # Start listener thread for this port
                thread = threading.Thread(target=self._listen_port, args=(sock, port))
                thread.daemon = True
                thread.start()
            
            print(f"Honeypot started on ports: {self.ports}")
            
        except Exception as e:
            print(f"Error starting honeypot: {str(e)}")
    
    def stop(self):
        """Stop the honeypot server"""
        self.is_running = False
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets = []
        print("Honeypot stopped")
    
    def _listen_port(self, sock: socket.socket, port: int):
        """Listen for connections on a specific port"""
        while self.is_running:
            try:
                conn, addr = sock.accept()
                self._handle_connection(conn, addr, port)
            except:
                break
    
    def _handle_connection(self, conn: socket.socket, addr: tuple, port: int):
        """Handle incoming connection"""
        try:
            # Log the connection
            connection_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': addr[0],
                'source_port': addr[1],
                'destination_port': port,
                'data': []
            }
            
            # Add to active connections
            self.connections.append(conn)
            
            # Send fake banner
            if port == 22:
                conn.send(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\n')
            elif port == 21:
                conn.send(b'220 FTP Server Ready\n')
            elif port == 80:
                conn.send(b'HTTP/1.1 200 OK\nServer: Apache/2.4.41\n\n')
            
            # Log any data received
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                connection_data['data'].append(data.decode('utf-8', errors='ignore'))
            
            # Add to logs
            self.logs.append(connection_data)
            self._save_logs()
            
        except Exception as e:
            print(f"Error handling connection: {str(e)}")
        finally:
            try:
                conn.close()
                if conn in self.connections:
                    self.connections.remove(conn)
            except:
                pass
    
    def _save_logs(self):
        """Save honeypot logs to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"honeypot_logs_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.logs, f, indent=4)
        
        print(f"Honeypot logs saved to {filename}")
    
    def get_logs(self) -> List[Dict]:
        """Get list of all honeypot logs"""
        return self.logs
    
    def get_active_connections(self) -> int:
        """Get number of active connections"""
        return len(self.connections) 