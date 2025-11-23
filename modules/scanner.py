import nmap
import json
from datetime import datetime
from typing import Dict, List

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
        
    def scan(self, target: str) -> Dict:
        """Perform network scan on specified target"""
        try:
            print(f"Starting scan on {target}...")
            self.nm.scan(hosts=target, arguments='-sV -sS -T4')
            
            for host in self.nm.all_hosts():
                self.results[host] = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    self.results[host]['protocols'][proto] = {}
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        self.results[host]['protocols'][proto][port] = {
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port]['name'],
                            'version': self.nm[host][proto][port].get('version', 'unknown')
                        }
            
            # Save results to file
            self._save_results()
            return self.results
            
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            return {}
    
    def _save_results(self):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"Scan results saved to {filename}")
    
    def get_results(self) -> Dict:
        """Return the scan results"""
        return self.results 