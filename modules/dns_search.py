import dns.resolver
import dns.exception
import socket
import threading
import requests
import time
from typing import List, Dict, Optional
import concurrent.futures

class DNSSearch:
    def __init__(self, dns_server: str = "8.8.8.8", max_threads: int = 15):
        self.dns_server = dns_server
        self.max_threads = max_threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
    def search_ns(self, domain: str) -> List[str]:
        """Search for NS records"""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except dns.exception.DNSException:
            return []
    
    def search_mx(self, domain: str) -> List[str]:
        """Search for MX records"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [str(rdata) for rdata in answers]
        except dns.exception.DNSException:
            return []
    
    def brute_subdomains(self, domain: str, wordlist: List[str]) -> List[str]:
        """Brute force subdomains using wordlist"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    found_subdomains.extend([f"{full_domain} -> {answer}" for answer in answers])
            except dns.exception.DNSException:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(check_subdomain, wordlist)
        
        return found_subdomains
    
    def reverse_dns_range(self, ip_range: str) -> List[str]:
        """Perform reverse DNS lookup on IP range"""
        results = []
        
        def reverse_lookup(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results.append(f"{ip} -> {hostname}")
            except socket.herror:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(reverse_lookup, ip_range)
        
        return results
    
    def shodan_search(self, domain: str, api_key: str) -> List[Dict]:
        """Search domain on Shodan (requires API key)"""
        try:
            api = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={domain}")
            if api.status_code == 200:
                return api.json().get('matches', [])
        except Exception:
            pass
        return []
