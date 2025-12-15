from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                            QPushButton, QTabWidget, QLabel, QLineEdit,
                            QTextEdit, QComboBox, QMessageBox, QSpinBox,
                            QCheckBox, QProgressBar, QGroupBox, QGridLayout,
                            QFileDialog, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import os

# Import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.scanner import Scanner
from modules.sniffer import Sniffer
from modules.phisher import Phisher
from modules.honeypot import Honeypot

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

class ScannerThread(QThread):
    finished = pyqtSignal(dict)
    
    def __init__(self, target):
        super().__init__()
        self.target = target
    
    def run(self):
        scanner = Scanner()
        results = scanner.scan(self.target)
        self.finished.emit(results)

class DNSThread(QThread):
    finished = pyqtSignal(dict)
    
    def __init__(self, domain, bruteforce=False):
        super().__init__()
        self.domain = domain
        self.bruteforce = bruteforce
    
    def run(self):
        dns = DNSSearch()
        results = {
            'ns_records': dns.search_ns(self.domain),
            'mx_records': dns.search_mx(self.domain)
        }
        if self.bruteforce:
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
            results['subdomains'] = dns.brute_subdomains(self.domain, common_subdomains)
        self.finished.emit(results)

class PortScanThread(QThread):
    finished = pyqtSignal(list)
    
    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = ports
    
    def run(self):
        scanner = PortScanner()
        if '-' in self.ports:
            start, end = map(int, self.ports.split('-'))
            results = scanner.scan_range(self.target, start, end)
        else:
            port_list = [int(p.strip()) for p in self.ports.split(',')]
            results = scanner.scan_custom_ports(self.target, port_list)
        self.finished.emit(results)

class HTTPBruteThread(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(int)
    
    def __init__(self, url, tool_type, threads=20):
        super().__init__()
        self.url = url
        self.tool_type = tool_type
        self.threads = threads
    
    def run(self):
        if self.tool_type == 'dirs':
            brute = HTTPBruteDir(max_threads=self.threads)
            results = brute.brute_force(self.url)
        else:
            brute = HTTPBruteFiles(max_threads=self.threads)
            results = brute.brute_force(self.url)
        self.finished.emit(results)

class HashCrackThread(QThread):
    finished = pyqtSignal(dict)
    
    def __init__(self, hash_value, wordlist=None, hash_type=''):
        super().__init__()
        self.hash_value = hash_value
        self.wordlist = wordlist
        self.hash_type = hash_type
    
    def run(self):
        cracker = HashCracker()
        if self.wordlist:
            result = cracker.dictionary_attack(self.hash_value, self.wordlist, self.hash_type or None)
        else:
            common_passwords = ['password', '123456', 'admin', 'test', 'guest']
            result = cracker.crack_hash(self.hash_value, common_passwords, self.hash_type or None)
        self.finished.emit(result)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetReconX - Enhanced with PentBox Tools")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize modules
        self.scanner = Scanner()
        self.sniffer = Sniffer()
        self.phisher = Phisher()
        self.honeypot = Honeypot()
        
        # Initialize pentbox tools
        self.dns_search = DNSSearch()
        self.port_scanner = PortScanner()
        self.fuzzer = Fuzzer()
        self.net_dos = NetDoS()
        self.mac_locator = MacLocator()
        self.http_brute_dir = HTTPBruteDir()
        self.http_brute_files = HTTPBruteFiles()
        self.base64_tool = Base64Tool()
        self.digest_tool = DigestTool()
        self.hash_cracker = HashCracker()
        self.secure_password = SecurePassword()
        
        self._init_ui()
    
    def _init_ui(self):
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Add original tabs
        tabs.addTab(self._create_scanner_tab(), "Scanner")
        tabs.addTab(self._create_sniffer_tab(), "Sniffer")
        tabs.addTab(self._create_phisher_tab(), "Phisher")
        tabs.addTab(self._create_honeypot_tab(), "Honeypot")
        
        # Add new pentbox tool tabs
        tabs.addTab(self._create_dns_tab(), "DNS Search")
        tabs.addTab(self._create_port_scan_tab(), "Port Scanner")
        tabs.addTab(self._create_fuzzer_tab(), "Fuzzer")
        tabs.addTab(self._create_dos_tab(), "DoS Testing")
        tabs.addTab(self._create_mac_tab(), "MAC Locator")
        tabs.addTab(self._create_http_brute_tab(), "HTTP Brute")
        tabs.addTab(self._create_crypto_tab(), "Cryptography")
    
    def _create_scanner_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        self.target_input = QLineEdit()
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Scan button
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self._start_scan)
        layout.addWidget(scan_btn)
        
        # Results display
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        layout.addWidget(self.scan_results)
        
        return widget
    
    def _create_dns_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Domain input
        domain_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        self.dns_domain_input = QLineEdit()
        domain_layout.addWidget(domain_label)
        domain_layout.addWidget(self.dns_domain_input)
        layout.addLayout(domain_layout)
        
        # Options
        options_layout = QHBoxLayout()
        self.dns_bruteforce_check = QCheckBox("Subdomain Bruteforce")
        options_layout.addWidget(self.dns_bruteforce_check)
        layout.addLayout(options_layout)
        
        # Search button
        dns_btn = QPushButton("Start DNS Search")
        dns_btn.clicked.connect(self._start_dns_search)
        layout.addWidget(dns_btn)
        
        # Results display
        self.dns_results = QTextEdit()
        self.dns_results.setReadOnly(True)
        layout.addWidget(self.dns_results)
        
        return widget
    
    def _create_port_scan_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target and ports input
        input_layout = QGridLayout()
        
        target_label = QLabel("Target:")
        self.port_target_input = QLineEdit()
        input_layout.addWidget(target_label, 0, 0)
        input_layout.addWidget(self.port_target_input, 0, 1)
        
        ports_label = QLabel("Ports (1-5000 or 80,443,8080):")
        self.port_range_input = QLineEdit("1-1000")
        input_layout.addWidget(ports_label, 1, 0)
        input_layout.addWidget(self.port_range_input, 1, 1)
        
        layout.addLayout(input_layout)
        
        # Scan button
        port_scan_btn = QPushButton("Start Port Scan")
        port_scan_btn.clicked.connect(self._start_port_scan)
        layout.addWidget(port_scan_btn)
        
        # Results display
        self.port_results = QTextEdit()
        self.port_results.setReadOnly(True)
        layout.addWidget(self.port_results)
        
        return widget
    
    def _create_fuzzer_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Input fields
        input_layout = QGridLayout()
        
        target_label = QLabel("Target:")
        self.fuzzer_target_input = QLineEdit()
        input_layout.addWidget(target_label, 0, 0)
        input_layout.addWidget(self.fuzzer_target_input, 0, 1)
        
        port_label = QLabel("Port:")
        self.fuzzer_port_input = QSpinBox()
        self.fuzzer_port_input.setRange(1, 65535)
        self.fuzzer_port_input.setValue(80)
        input_layout.addWidget(port_label, 1, 0)
        input_layout.addWidget(self.fuzzer_port_input, 1, 1)
        
        service_label = QLabel("Service:")
        self.fuzzer_service_combo = QComboBox()
        self.fuzzer_service_combo.addItems(['http', 'ftp'])
        input_layout.addWidget(service_label, 2, 0)
        input_layout.addWidget(self.fuzzer_service_combo, 2, 1)
        
        layout.addLayout(input_layout)
        
        # Fuzz button
        fuzz_btn = QPushButton("Start Fuzzing")
        fuzz_btn.clicked.connect(self._start_fuzzing)
        layout.addWidget(fuzz_btn)
        
        # Results display
        self.fuzzer_results = QTextEdit()
        self.fuzzer_results.setReadOnly(True)
        layout.addWidget(self.fuzzer_results)
        
        return widget
    
    def _create_dos_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Warning label
        warning_label = QLabel("WARNING: DoS tools are for educational testing only!")
        warning_label.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(warning_label)
        
        # Input fields
        input_layout = QGridLayout()
        
        target_label = QLabel("Target:")
        self.dos_target_input = QLineEdit()
        input_layout.addWidget(target_label, 0, 0)
        input_layout.addWidget(self.dos_target_input, 0, 1)
        
        port_label = QLabel("Port:")
        self.dos_port_input = QSpinBox()
        self.dos_port_input.setRange(1, 65535)
        self.dos_port_input.setValue(80)
        input_layout.addWidget(port_label, 1, 0)
        input_layout.addWidget(self.dos_port_input, 1, 1)
        
        method_label = QLabel("Method:")
        self.dos_method_combo = QComboBox()
        self.dos_method_combo.addItems(['tcp', 'udp', 'http'])
        input_layout.addWidget(method_label, 2, 0)
        input_layout.addWidget(self.dos_method_combo, 2, 1)
        
        threads_label = QLabel("Threads:")
        self.dos_threads_input = QSpinBox()
        self.dos_threads_input.setRange(1, 1000)
        self.dos_threads_input.setValue(50)
        input_layout.addWidget(threads_label, 3, 0)
        input_layout.addWidget(self.dos_threads_input, 3, 1)
        
        duration_label = QLabel("Duration (sec):")
        self.dos_duration_input = QSpinBox()
        self.dos_duration_input.setRange(1, 300)
        self.dos_duration_input.setValue(60)
        input_layout.addWidget(duration_label, 4, 0)
        input_layout.addWidget(self.dos_duration_input, 4, 1)
        
        layout.addLayout(input_layout)
        
        # DoS button
        dos_btn = QPushButton("Start DoS Test")
        dos_btn.clicked.connect(self._start_dos)
        dos_btn.setStyleSheet("background-color: orange;")
        layout.addWidget(dos_btn)
        
        # Results display
        self.dos_results = QTextEdit()
        self.dos_results.setReadOnly(True)
        layout.addWidget(self.dos_results)
        
        return widget
    
    def _create_mac_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Action selection
        action_layout = QHBoxLayout()
        action_label = QLabel("Action:")
        self.mac_action_combo = QComboBox()
        self.mac_action_combo.addItems(['local', 'arp', 'scan'])
        action_layout.addWidget(action_label)
        action_layout.addWidget(self.mac_action_combo)
        layout.addLayout(action_layout)
        
        # Target for scan
        target_layout = QHBoxLayout()
        target_label = QLabel("Target (for scan):")
        self.mac_target_input = QLineEdit()
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.mac_target_input)
        layout.addLayout(target_layout)
        
        # Execute button
        mac_btn = QPushButton("Execute")
        mac_btn.clicked.connect(self._start_mac_locate)
        layout.addWidget(mac_btn)
        
        # Results display
        self.mac_results = QTextEdit()
        self.mac_results.setReadOnly(True)
        layout.addWidget(self.mac_results)
        
        return widget
    
    def _create_http_brute_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # URL input
        url_layout = QHBoxLayout()
        url_label = QLabel("URL:")
        self.http_url_input = QLineEdit()
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.http_url_input)
        layout.addLayout(url_layout)
        
        # Options
        options_layout = QGridLayout()
        
        brute_type_label = QLabel("Type:")
        self.http_brute_type_combo = QComboBox()
        self.http_brute_type_combo.addItems(['dirs', 'files'])
        options_layout.addWidget(brute_type_label, 0, 0)
        options_layout.addWidget(self.http_brute_type_combo, 0, 1)
        
        threads_label = QLabel("Threads:")
        self.http_threads_input = QSpinBox()
        self.http_threads_input.setRange(1, 100)
        self.http_threads_input.setValue(20)
        options_layout.addWidget(threads_label, 1, 0)
        options_layout.addWidget(self.http_threads_input, 1, 1)
        
        layout.addLayout(options_layout)
        
        # Brute button
        http_brute_btn = QPushButton("Start HTTP Brute")
        http_brute_btn.clicked.connect(self._start_http_brute)
        layout.addWidget(http_brute_btn)
        
        # Progress bar
        self.http_progress = QProgressBar()
        layout.addWidget(self.http_progress)
        
        # Results display
        self.http_results = QTextEdit()
        self.http_results.setReadOnly(True)
        layout.addWidget(self.http_results)
        
        return widget
    
    def _create_crypto_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Create crypto tools group
        crypto_group = QGroupBox("Cryptography Tools")
        crypto_layout = QGridLayout(crypto_group)
        
        # Base64 section
        base64_label = QLabel("Base64:")
        self.base64_input = QLineEdit()
        base64_encode_btn = QPushButton("Encode")
        base64_decode_btn = QPushButton("Decode")
        
        crypto_layout.addWidget(base64_label, 0, 0)
        crypto_layout.addWidget(self.base64_input, 0, 1, 1, 2)
        crypto_layout.addWidget(base64_encode_btn, 0, 3)
        crypto_layout.addWidget(base64_decode_btn, 0, 4)
        
        # Hash section
        hash_label = QLabel("Hash:")
        self.hash_input = QLineEdit()
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItems(['md5', 'sha1', 'sha256', 'sha384', 'sha512'])
        hash_btn = QPushButton("Hash")
        
        crypto_layout.addWidget(hash_label, 1, 0)
        crypto_layout.addWidget(self.hash_input, 1, 1)
        crypto_layout.addWidget(self.hash_algo_combo, 1, 2)
        crypto_layout.addWidget(hash_btn, 1, 3)
        
        # Hash cracker section
        crack_label = QLabel("Crack Hash:")
        self.crack_hash_input = QLineEdit()
        crack_btn = QPushButton("Crack")
        
        crypto_layout.addWidget(crack_label, 2, 0)
        crypto_layout.addWidget(self.crack_hash_input, 2, 1, 1, 2)
        crypto_layout.addWidget(crack_btn, 2, 3)
        
        # Password generator section
        pass_label = QLabel("Password:")
        self.pass_length_input = QSpinBox()
        self.pass_length_input.setRange(4, 64)
        self.pass_length_input.setValue(12)
        pass_gen_btn = QPushButton("Generate")
        
        crypto_layout.addWidget(pass_label, 3, 0)
        crypto_layout.addWidget(self.pass_length_input, 3, 1)
        crypto_layout.addWidget(pass_gen_btn, 3, 2)
        crypto_layout.addWidget(QLabel(""), 3, 3)  # Spacer
        
        layout.addWidget(crypto_group)
        
        # Connect buttons
        base64_encode_btn.clicked.connect(self._base64_encode)
        base64_decode_btn.clicked.connect(self._base64_decode)
        hash_btn.clicked.connect(self._hash_data)
        crack_btn.clicked.connect(self._crack_hash)
        pass_gen_btn.clicked.connect(self._generate_password)
        
        # Results display
        self.crypto_results = QTextEdit()
        self.crypto_results.setReadOnly(True)
        layout.addWidget(self.crypto_results)
        
        return widget
    
    def _create_sniffer_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        # TODO: Add network interfaces
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        layout.addLayout(interface_layout)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_sniff_btn = QPushButton("Start Sniffing")
        self.stop_sniff_btn = QPushButton("Stop Sniffing")
        self.start_sniff_btn.clicked.connect(self._start_sniffing)
        self.stop_sniff_btn.clicked.connect(self._stop_sniffing)
        button_layout.addWidget(self.start_sniff_btn)
        button_layout.addWidget(self.stop_sniff_btn)
        layout.addLayout(button_layout)
        
        # Packet display
        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        layout.addWidget(self.packet_display)
        
        return widget
    
    def _create_phisher_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Template selection
        template_layout = QHBoxLayout()
        template_label = QLabel("Template:")
        self.template_combo = QComboBox()
        # TODO: Add phishing templates
        template_layout.addWidget(template_label)
        template_layout.addWidget(self.template_combo)
        layout.addLayout(template_layout)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_phish_btn = QPushButton("Start Phishing")
        self.stop_phish_btn = QPushButton("Stop Phishing")
        self.start_phish_btn.clicked.connect(self._start_phishing)
        self.stop_phish_btn.clicked.connect(self._stop_phishing)
        button_layout.addWidget(self.start_phish_btn)
        button_layout.addWidget(self.stop_phish_btn)
        layout.addLayout(button_layout)
        
        # Results display
        self.phish_results = QTextEdit()
        self.phish_results.setReadOnly(True)
        layout.addWidget(self.phish_results)
        
        return widget
    
    def _create_honeypot_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_honeypot_btn = QPushButton("Start Honeypot")
        self.stop_honeypot_btn = QPushButton("Stop Honeypot")
        self.start_honeypot_btn.clicked.connect(self._start_honeypot)
        self.stop_honeypot_btn.clicked.connect(self._stop_honeypot)
        button_layout.addWidget(self.start_honeypot_btn)
        button_layout.addWidget(self.stop_honeypot_btn)
        layout.addLayout(button_layout)
        
        # Log display
        self.honeypot_logs = QTextEdit()
        self.honeypot_logs.setReadOnly(True)
        layout.addWidget(self.honeypot_logs)
        
        return widget
    
    # Event handlers
    def _start_scan(self):
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        self.scan_results.clear()
        self.scan_results.append("Starting scan...")
        
        # Start scan in separate thread
        self.scanner_thread = ScannerThread(target)
        self.scanner_thread.finished.connect(self._update_scan_results)
        self.scanner_thread.start()
    
    def _update_scan_results(self, results):
        self.scan_results.clear()
        self.scan_results.append(str(results))
    
    def _start_dns_search(self):
        domain = self.dns_domain_input.text()
        if not domain:
            QMessageBox.warning(self, "Error", "Please enter a domain")
            return
        
        self.dns_results.clear()
        self.dns_results.append(f"Starting DNS search for {domain}...")
        
        bruteforce = self.dns_bruteforce_check.isChecked()
        self.dns_thread = DNSThread(domain, bruteforce)
        self.dns_thread.finished.connect(self._update_dns_results)
        self.dns_thread.start()
    
    def _update_dns_results(self, results):
        self.dns_results.clear()
        
        if results['ns_records']:
            self.dns_results.append("NS Records:")
            for ns in results['ns_records']:
                self.dns_results.append(f"  {ns}")
        
        if results['mx_records']:
            self.dns_results.append("\nMX Records:")
            for mx in results['mx_records']:
                self.dns_results.append(f"  {mx}")
        
        if 'subdomains' in results and results['subdomains']:
            self.dns_results.append("\nFound Subdomains:")
            for sub in results['subdomains']:
                self.dns_results.append(f"  {sub}")
    
    def _start_port_scan(self):
        target = self.port_target_input.text()
        ports = self.port_range_input.text()
        
        if not target or not ports:
            QMessageBox.warning(self, "Error", "Please enter target and ports")
            return
        
        self.port_results.clear()
        self.port_results.append(f"Scanning {target} ports {ports}...")
        
        self.port_scan_thread = PortScanThread(target, ports)
        self.port_scan_thread.finished.connect(self._update_port_results)
        self.port_scan_thread.start()
    
    def _update_port_results(self, results):
        self.port_results.clear()
        if results:
            self.port_results.append("Open Ports:")
            for port in results:
                self.port_results.append(f"  {port['port']}/tcp - {port['service']}")
        else:
            self.port_results.append("No open ports found")
    
    def _start_fuzzing(self):
        target = self.fuzzer_target_input.text()
        port = self.fuzzer_port_input.value()
        service = self.fuzzer_service_combo.currentText()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        self.fuzzer_results.clear()
        self.fuzzer_results.append(f"Starting {service} fuzzing on {target}:{port}...")
        
        # Run fuzzing in main thread for simplicity (can be moved to separate thread)
        try:
            if service == 'http':
                results = self.fuzzer.fuzz_http(target, port)
            else:
                results = self.fuzzer.fuzz_ftp(target, port)
            
            self.fuzzer_results.append(f"Fuzzing completed. Tested {len(results['vulnerabilities'])} payloads")
            self.fuzzer_results.append("Check detailed logs for vulnerabilities")
        except Exception as e:
            self.fuzzer_results.append(f"Error: {str(e)}")
    
    def _start_dos(self):
        target = self.dos_target_input.text()
        port = self.dos_port_input.value()
        method = self.dos_method_combo.currentText()
        threads = self.dos_threads_input.value()
        duration = self.dos_duration_input.value()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        # Confirm DoS attack
        reply = QMessageBox.question(self, "Confirm", 
                                   f"Start {method.upper()} DoS test against {target}:{port}?\n"
                                   "This is for educational purposes only!",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            return
        
        self.dos_results.clear()
        self.dos_results.append(f"Starting {method} DoS test...")
        
        try:
            if method == 'tcp':
                results = self.net_dos.tcp_flood(target, port, threads, duration)
            elif method == 'udp':
                results = self.net_dos.udp_flood(target, port, threads, duration)
            else:
                results = self.net_dos.http_flood(target, port, '/', threads, duration)
            
            self.dos_results.append("Attack completed")
            self.dos_results.append(f"Packets/Requests: {results.get('packets_sent', results.get('requests_sent', 0))}")
            self.dos_results.append(f"Duration: {results['actual_duration']:.2f} seconds")
        except Exception as e:
            self.dos_results.append(f"Error: {str(e)}")
    
    def _start_mac_locate(self):
        action = self.mac_action_combo.currentText()
        target = self.mac_target_input.text()
        
        self.mac_results.clear()
        
        try:
            if action == 'local':
                mac = self.mac_locator.get_local_mac()
                if mac:
                    vendor = self.mac_locator.mac_vendor_lookup(mac)
                    self.mac_results.append(f"Local MAC: {mac} ({vendor})")
                else:
                    self.mac_results.append("Could not determine local MAC address")
            
            elif action == 'arp':
                arp_table = self.mac_locator.get_arp_table()
                if arp_table:
                    self.mac_results.append("ARP Table:")
                    for entry in arp_table:
                        vendor = self.mac_locator.mac_vendor_lookup(entry['mac'])
                        if 'hostname' in entry:
                            self.mac_results.append(f"  {entry['hostname']} - {entry['ip']} -> {entry['mac']} ({vendor})")
                        else:
                            self.mac_results.append(f"  {entry['ip']} -> {entry['mac']} ({vendor})")
                else:
                    self.mac_results.append("No ARP entries found")
            
            elif action == 'scan' and target:
                self.mac_results.append(f"Scanning network {target}...")
                devices = self.mac_locator.scan_network_for_macs(target)
                if devices:
                    self.mac_results.append("Found devices:")
                    for device in devices:
                        self.mac_results.append(f"  {device['ip']} -> {device['mac']} ({device.get('vendor', 'Unknown')})")
                else:
                    self.mac_results.append("No devices found or nmap not available")
            else:
                self.mac_results.append("Invalid action or missing target")
        
        except Exception as e:
            self.mac_results.append(f"Error: {str(e)}")
    
    def _start_http_brute(self):
        url = self.http_url_input.text()
        brute_type = self.http_brute_type_combo.currentText()
        threads = self.http_threads_input.value()
        
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL")
            return
        
        self.http_results.clear()
        self.http_progress.setValue(0)
        self.http_results.append(f"Starting HTTP {brute_type} brute force on {url}...")
        
        self.http_brute_thread = HTTPBruteThread(url, brute_type, threads)
        self.http_brute_thread.finished.connect(self._update_http_results)
        self.http_brute_thread.start()
    
    def _update_http_results(self, results):
        self.http_progress.setValue(100)
        self.http_results.clear()
        
        if results:
            self.http_results.append(f"Found {len(results)} items:")
            for result in results:
                if 'type' in result:  # Directory brute
                    self.http_results.append(f"  {result['url']} - {result['status_code']} ({result['type']})")
                else:  # File brute
                    self.http_results.append(f"  {result['url']} - {result['status_code']} ({result['file_type']})")
        else:
            self.http_results.append("No items found")
    
    def _base64_encode(self):
        data = self.base64_input.text()
        if data:
            encoded = self.base64_tool.encode(data)
            self.crypto_results.append(f"Base64 Encoded: {encoded}")
    
    def _base64_decode(self):
        data = self.base64_input.text()
        if data:
            decoded = self.base64_tool.decode(data)
            self.crypto_results.append(f"Base64 Decoded: {decoded}")
    
    def _hash_data(self):
        data = self.hash_input.text()
        algorithm = self.hash_algo_combo.currentText()
        
        if data:
            hash_func = getattr(self.digest_tool, algorithm)
            result = hash_func(data)
            self.crypto_results.append(f"{algorithm.upper()}: {result}")
    
    def _crack_hash(self):
        hash_value = self.crack_hash_input.text()
        if not hash_value:
            return
        
        self.crypto_results.append(f"Cracking hash: {hash_value}...")
        
        self.hash_crack_thread = HashCrackThread(hash_value)
        self.hash_crack_thread.finished.connect(self._update_crack_results)
        self.hash_crack_thread.start()
    
    def _update_crack_results(self, result):
        if result['status'] == 'success':
            self.crypto_results.append(f"[+] Hash cracked!")
            self.crypto_results.append(f"    Type: {result['type']}")
            self.crypto_results.append(f"    Plaintext: {result['plaintext']}")
        else:
            self.crypto_results.append(f"[-] Hash not cracked")
    
    def _generate_password(self):
        length = self.pass_length_input.value()
        password = self.secure_password.generate_password(length)
        strength = self.secure_password.check_password_strength(password)
        
        self.crypto_results.append(f"Generated Password: {password}")
        self.crypto_results.append(f"Strength: {strength['strength']} (Score: {strength['score']}/{strength['max_score']})")
        self.crypto_results.append(f"Entropy: {strength['entropy']} bits")
    
    def _start_sniffing(self):
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Error", "Please select an interface")
            return
        
        self.sniffer.start(interface)
        self.packet_display.append("Started sniffing on " + interface)
    
    def _stop_sniffing(self):
        self.sniffer.stop()
        self.packet_display.append("Stopped sniffing")
    
    def _start_phishing(self):
        template = self.template_combo.currentText()
        if not template:
            QMessageBox.warning(self, "Error", "Please select a template")
            return
        
        self.phisher.start(template)
        self.phish_results.append("Started phishing with template: " + template)
    
    def _stop_phishing(self):
        self.phisher.stop()
        self.phish_results.append("Stopped phishing")
    
    def _start_honeypot(self):
        self.honeypot.start()
        self.honeypot_logs.append("Started honeypot")
    
    def _stop_honeypot(self):
        self.honeypot.stop()
        self.honeypot_logs.append("Stopped honeypot")
