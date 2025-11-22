#!/usr/bin/env python3
import typer
from typing import Optional
import sys
from pathlib import Path

# Import modules
from modules.scanner import Scanner
from modules.sniffer import Sniffer
from modules.phisher import Phisher
from modules.honeypot import Honeypot
from gui.main_window import MainWindow

# Import pentbox tools
from modules.dns_search import DNSSearch
from modules.port_scanner import PortScanner
from modules.fuzzer import Fuzzer
from modules.net_dos import NetDoS
from modules.mac_locator import MacLocator
from modules.http_brute_dir import HTTPBruteDir
from modules.http_brute_files import HTTPBruteFiles
from modules.base64_tool import Base64Tool
from modules.digest_tool import DigestTool
from modules.hash_cracker import HashCracker
from modules.secure_password import SecurePassword

app = typer.Typer()

@app.command()
def scan(target: str = typer.Option(..., help="Target IP or network range")):
    """Run network scan on specified target"""
    scanner = Scanner()
    scanner.scan(target)

@app.command()
def sniff(interface: str = typer.Option(..., help="Network interface to sniff")):
    """Start packet sniffing on specified interface"""
    sniffer = Sniffer()
    sniffer.start(interface)

@app.command()
def phish(template: str = typer.Option(..., help="Phishing template to use")):
    """Start phishing campaign with specified template"""
    phisher = Phisher()
    phisher.start(template)

@app.command()
def honeypot(start: bool = typer.Option(False, help="Start honeypot")):
    """Start/stop honeypot service"""
    honeypot = Honeypot()
    if start:
        honeypot.start()
    else:
        honeypot.stop()

@app.command()
def gui():
    """Launch GUI interface"""
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

# DNS Search Commands
@app.command()
def dns_search(domain: str = typer.Option(..., help="Domain to search"),
               bruteforce: bool = typer.Option(False, help="Enable subdomain bruteforce")):
    """DNS enumeration and subdomain search"""
    dns = DNSSearch()
    
    print(f"[*] Searching DNS records for {domain}")
    
    # NS records
    ns_records = dns.search_ns(domain)
    if ns_records:
        print("\nNS Records:")
        for ns in ns_records:
            print(f"  {ns}")
    
    # MX records
    mx_records = dns.search_mx(domain)
    if mx_records:
        print("\nMX Records:")
        for mx in mx_records:
            print(f"  {mx}")
    
    # Subdomain bruteforce
    if bruteforce:
        print("\n[*] Starting subdomain bruteforce...")
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
        found = dns.brute_subdomains(domain, common_subdomains)
        if found:
            print("Found subdomains:")
            for sub in found:
                print(f"  {sub}")
        else:
            print("No subdomains found")

# Port Scanner Commands
@app.command()
def port_scan(target: str = typer.Option(..., help="Target IP or hostname"),
              ports: str = typer.Option("1-5000", help="Port range (e.g., 1-1000 or 80,443,8080)")):
    """TCP port scanning"""
    scanner = PortScanner()
    
    print(f"[*] Pinging {target}...")
    if not scanner.ping_host(target):
        print("[!] Host appears to be down")
        return
    
    print("[*] Host is up, starting port scan...")
    
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        results = scanner.scan_range(target, start, end)
    else:
        port_list = [int(p.strip()) for p in ports.split(',')]
        results = scanner.scan_custom_ports(target, port_list)
    
    if results:
        print("\nOpen ports:")
        for port in results:
            print(f"  {port['port']}/tcp - {port['service']}")
    else:
        print("No open ports found")

# Fuzzer Commands
@app.command()
def fuzz(target: str = typer.Option(..., help="Target host"),
         port: int = typer.Option(80, help="Target port"),
         service: str = typer.Option("http", help="Service type (http, ftp)")):
    """Fuzzing for vulnerabilities"""
    fuzzer = Fuzzer()
    
    print(f"[*] Starting {service.upper()} fuzzing on {target}:{port}")
    
    if service.lower() == 'http':
        results = fuzzer.fuzz_http(target, port)
    elif service.lower() == 'ftp':
        results = fuzzer.fuzz_ftp(target, port)
    else:
        print(f"[!] Unsupported service: {service}")
        return
    
    print(f"\n[*] Fuzzing completed. Tested {len(results['vulnerabilities'])} payloads")
    print("[*] Check logs for detailed results")

# DoS Commands
@app.command()
def dos(target: str = typer.Option(..., help="Target host"),
         port: int = typer.Option(80, help="Target port"),
         method: str = typer.Option("tcp", help="DoS method (tcp, udp, http)"),
         threads: int = typer.Option(50, help="Number of threads"),
         duration: int = typer.Option(60, help="Duration in seconds")):
    """Denial of Service testing (USE RESPONSIBLY)"""
    dos_tool = NetDoS()
    
    print(f"[!] WARNING: You are about to start a DoS attack against {target}:{port}")
    print(f"[!] This is for educational/testing purposes only")
    print(f"[!] Starting {method.upper()} flood for {duration} seconds with {threads} threads")
    
    if method.lower() == 'tcp':
        results = dos_tool.tcp_flood(target, port, threads, duration)
    elif method.lower() == 'udp':
        results = dos_tool.udp_flood(target, port, threads, duration)
    elif method.lower() == 'http':
        results = dos_tool.http_flood(target, port, '/', threads, duration)
    else:
        print(f"[!] Unsupported method: {method}")
        return
    
    print(f"[*] Attack completed")
    print(f"    Packets/Requests sent: {results.get('packets_sent', results.get('requests_sent', 0))}")
    print(f"    Actual duration: {results['actual_duration']:.2f} seconds")

# MAC Locator Commands
@app.command()
def mac_locate(action: str = typer.Option("local", help="Action: local, arp, scan"),
              target: str = typer.Option("", help="Target for network scan")):
    """MAC address location and vendor lookup"""
    locator = MacLocator()
    
    if action == 'local':
        mac = locator.get_local_mac()
        if mac:
            vendor = locator.mac_vendor_lookup(mac)
            print(f"Local MAC: {mac} ({vendor})")
        else:
            print("Could not determine local MAC address")
    
    elif action == 'arp':
        arp_table = locator.get_arp_table()
        if arp_table:
            print("ARP Table:")
            for entry in arp_table:
                vendor = locator.mac_vendor_lookup(entry['mac'])
                if 'hostname' in entry:
                    print(f"  {entry['hostname']} - {entry['ip']} -> {entry['mac']} ({vendor})")
                else:
                    print(f"  {entry['ip']} -> {entry['mac']} ({vendor})")
        else:
            print("No ARP entries found")
    
    elif action == 'scan' and target:
        print(f"[*] Scanning network {target} for MAC addresses...")
        devices = locator.scan_network_for_macs(target)
        if devices:
            print("Found devices:")
            for device in devices:
                print(f"  {device['ip']} -> {device['mac']} ({device.get('vendor', 'Unknown')})")
        else:
            print("No devices found or nmap not available")
    
    else:
        print("[!] Invalid action or missing target for scan")

# HTTP Brute Commands
@app.command()
def http_brute_dirs(url: str = typer.Option(..., help="Target URL"),
                   threads: int = typer.Option(20, help="Number of threads")):
    """HTTP directory bruteforce"""
    brute = HTTPBruteDir(max_threads=threads)
    
    print(f"[*] Starting directory bruteforce on {url}")
    results = brute.brute_force(url)
    
    if results:
        print(f"\nFound {len(results)} directories/files:")
        for result in results:
            print(f"  {result['url']} - {result['status_code']} ({result['type']})")
    else:
        print("No directories found")

@app.command()
def http_brute_files(url: str = typer.Option(..., help="Target URL"),
                     threads: int = typer.Option(20, help="Number of threads")):
    """HTTP file bruteforce"""
    brute = HTTPBruteFiles(max_threads=threads)
    
    print(f"[*] Starting file bruteforce on {url}")
    results = brute.brute_force(url)
    
    if results:
        print(f"\nFound {len(results)} files:")
        for result in results:
            print(f"  {result['url']} - {result['status_code']} ({result['file_type']})")
    else:
        print("No files found")

# Cryptography Commands
@app.command()
def b64_encode(data: str = typer.Option(..., help="Data to encode")):
    """Base64 encode data"""
    encoded = Base64Tool.encode(data)
    print(f"Encoded: {encoded}")

@app.command()
def b64_decode(data: str = typer.Option(..., help="Base64 data to decode")):
    """Base64 decode data"""
    decoded = Base64Tool.decode(data)
    print(f"Decoded: {decoded}")

@app.command()
def hash_data(data: str = typer.Option(..., help="Data to hash"),
             algorithm: str = typer.Option("sha256", help="Hash algorithm")):
    """Calculate hash of data"""
    hash_func = getattr(DigestTool, algorithm, None)
    if hash_func:
        result = hash_func(data)
        print(f"{algorithm.upper()}: {result}")
    else:
        print(f"[!] Unsupported algorithm: {algorithm}")

@app.command()
def crack_hash(hash_value: str = typer.Option(..., help="Hash to crack"),
               wordlist: str = typer.Option("", help="Wordlist file path"),
               hash_type: str = typer.Option("", help="Hash type (auto-detect if empty)")):
    """Crack hash using wordlist"""
    cracker = HashCracker()
    
    if wordlist:
        result = cracker.dictionary_attack(hash_value, wordlist, hash_type or None)
    else:
        # Use built-in small wordlist for demo
        common_passwords = ['password', '123456', 'admin', 'test', 'guest']
        result = cracker.crack_hash(hash_value, common_passwords, hash_type or None)
    
    if result['status'] == 'success':
        print(f"[+] Hash cracked!")
        print(f"    Hash: {result['hash']}")
        print(f"    Type: {result['type']}")
        print(f"    Plaintext: {result['plaintext']}")
    else:
        print(f"[-] Hash not cracked")
        print(f"    Hash: {hash_value}")
        print(f"    Type: {result.get('type', 'unknown')}")

@app.command()
def generate_password(length: int = typer.Option(12, help="Password length")):
    """Generate secure password"""
    sec_pass = SecurePassword()
    password = sec_pass.generate_password(length)
    strength = sec_pass.check_password_strength(password)
    
    print(f"Generated Password: {password}")
    print(f"Strength: {strength['strength']} (Score: {strength['score']}/{strength['max_score']})")
    print(f"Entropy: {strength['entropy']} bits")
    
    if strength['feedback']:
        print("Feedback:")
        for feedback in strength['feedback']:
            print(f"  - {feedback}")

@app.command()
def check_password_strength(password: str = typer.Option(..., help="Password to check")):
    """Check password strength"""
    sec_pass = SecurePassword()
    strength = sec_pass.check_password_strength(password)
    crack_time = sec_pass.estimate_crack_time(password)
    
    print(f"Password: {password}")
    print(f"Strength: {strength['strength']} (Score: {strength['score']}/{strength['max_score']})")
    print(f"Length: {strength['length']}")
    print(f"Entropy: {strength['entropy']} bits")
    
    print("\nCrack time estimates:")
    for scenario, data in crack_time['scenarios'].items():
        print(f"  {scenario.replace('_', ' ').title()}: {data['readable']}")
    
    if strength['feedback']:
        print("\nFeedback:")
        for feedback in strength['feedback']:
            print(f"  - {feedback}")

if __name__ == "__main__":
    app()