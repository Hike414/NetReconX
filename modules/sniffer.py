import pyshark
import threading
import json
from datetime import datetime
from typing import Dict, Callable
import os

class Sniffer:
    def __init__(self):
        self.capture = None
        self.is_running = False
        self.packet_count = 0
        self.packets = []
        self.callbacks = []
        
    def start(self, interface: str, output_file: str = None):
        """Start packet capture on specified interface"""
        try:
            if output_file:
                self.capture = pyshark.LiveCapture(
                    interface=interface,
                    output_file=output_file
                )
            else:
                self.capture = pyshark.LiveCapture(interface=interface)
            
            self.is_running = True
            self.packet_count = 0
            self.packets = []
            
            # Start capture in a separate thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.start()
            
            print(f"Started packet capture on interface {interface}")
            
        except Exception as e:
            print(f"Error starting capture: {str(e)}")
    
    def stop(self):
        """Stop packet capture"""
        if self.capture and self.is_running:
            self.is_running = False
            self.capture.close()
            print("Packet capture stopped")
    
    def _capture_packets(self):
        """Internal method to capture packets"""
        try:
            for packet in self.capture.sniff_continuously():
                if not self.is_running:
                    break
                    
                self.packet_count += 1
                packet_data = self._parse_packet(packet)
                self.packets.append(packet_data)
                
                # Notify callbacks
                for callback in self.callbacks:
                    callback(packet_data)
                    
        except Exception as e:
            print(f"Error during packet capture: {str(e)}")
    
    def _parse_packet(self, packet) -> Dict:
        """Parse packet into dictionary format"""
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'protocol': packet.highest_layer,
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'destination_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'source_port': packet[packet.highest_layer].srcport if hasattr(packet[packet.highest_layer], 'srcport') else None,
            'destination_port': packet[packet.highest_layer].dstport if hasattr(packet[packet.highest_layer], 'dstport') else None,
            'length': packet.length
        }
        return packet_data
    
    def register_callback(self, callback: Callable):
        """Register a callback function to be called for each packet"""
        self.callbacks.append(callback)
    
    def get_packet_count(self) -> int:
        """Get total number of packets captured"""
        return self.packet_count
    
    def get_packets(self) -> list:
        """Get list of all captured packets"""
        return self.packets
    
    def save_packets(self, filename: str = None):
        """Save captured packets to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"packet_capture_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.packets, f, indent=4)
        
        print(f"Packet capture saved to {filename}") 