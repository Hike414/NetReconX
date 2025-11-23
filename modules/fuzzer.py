import socket
import threading
import time
import random
import string
from typing import List, Dict, Optional

class Fuzzer:
    def __init__(self):
        self.payloads = self._generate_payloads()
    
    def _generate_payloads(self) -> List[str]:
        """Generate common fuzzing payloads"""
        payloads = []
        
        # Buffer overflow payloads
        for size in [100, 500, 1000, 2000, 5000]:
            payloads.append('A' * size)
        
        # Format string payloads
        payloads.extend(['%s', '%x', '%n', '%p', '%d'] * 10)
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "admin' #",
            "' OR 'x'='x",
        ]
        payloads.extend(sql_payloads)
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]
        payloads.extend(xss_payloads)
        
        # Directory traversal
        dt_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        payloads.extend(dt_payloads)
        
        # Command injection
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(id)",
        ]
        payloads.extend(cmd_payloads)
        
        return payloads
    
    def fuzz_http(self, host: str, port: int = 80, path: str = "/", ssl: bool = False) -> Dict:
        """Fuzz HTTP server"""
        results = {
            'host': host,
            'port': port,
            'vulnerabilities': []
        }
        
        protocol = "https" if ssl else "http"
        base_url = f"{protocol}://{host}:{port}{path}"
        
        for payload in self.payloads[:50]:  # Limit for testing
            try:
                # Test GET parameter
                test_url = f"{base_url}?test={payload}"
                
                # Test POST parameter
                test_data = f"test={payload}"
                
                # Test User-Agent header
                test_headers = {'User-Agent': payload}
                
                # Test Cookie
                test_cookie = f"test={payload}"
                
                # Here you would make actual HTTP requests and check responses
                # For now, just log what would be tested
                results['vulnerabilities'].append({
                    'type': 'fuzz_test',
                    'payload': payload[:100],  # Truncate for readability
                    'tests': ['GET', 'POST', 'User-Agent', 'Cookie']
                })
                
            except Exception as e:
                results['vulnerabilities'].append({
                    'type': 'error',
                    'payload': payload[:100],
                    'error': str(e)
                })
        
        return results
    
    def fuzz_ftp(self, host: str, port: int = 21) -> Dict:
        """Fuzz FTP server"""
        results = {
            'host': host,
            'port': port,
            'vulnerabilities': []
        }
        
        for payload in self.payloads[:30]:  # Limit for testing
            try:
                # Test USER command
                # Test PASS command
                # Test other FTP commands with payload
                
                results['vulnerabilities'].append({
                    'type': 'ftp_fuzz',
                    'payload': payload[:100],
                    'commands': ['USER', 'PASS', 'CWD', 'LIST']
                })
                
            except Exception as e:
                results['vulnerabilities'].append({
                    'type': 'error',
                    'payload': payload[:100],
                    'error': str(e)
                })
        
        return results
    
    def fuzz_custom(self, target: str, data_template: str) -> Dict:
        """Fuzz custom protocol/service"""
        results = {
            'target': target,
            'vulnerabilities': []
        }
        
        for payload in self.payloads[:20]:  # Limit for testing
            try:
                # Replace placeholder in template with payload
                fuzzed_data = data_template.replace('{PAYLOAD}', payload)
                
                results['vulnerabilities'].append({
                    'type': 'custom_fuzz',
                    'payload': payload[:100],
                    'data_length': len(fuzzed_data)
                })
                
            except Exception as e:
                results['vulnerabilities'].append({
                    'type': 'error',
                    'payload': payload[:100],
                    'error': str(e)
                })
        
        return results
