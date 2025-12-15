from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                            QPushButton, QTabWidget, QLabel, QLineEdit,
                            QTextEdit, QComboBox, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import os

# Import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.scanner import Scanner
from modules.sniffer import Sniffer
from modules.phisher import Phisher
from modules.honeypot import Honeypot

class ScannerThread(QThread):
    finished = pyqtSignal(dict)
    
    def __init__(self, target):
        super().__init__()
        self.target = target
    
    def run(self):
        scanner = Scanner()
        results = scanner.scan(self.target)
        self.finished.emit(results)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetReconX")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize modules
        self.scanner = Scanner()
        self.sniffer = Sniffer()
        self.phisher = Phisher()
        self.honeypot = Honeypot()
        
        self._init_ui()
    
    def _init_ui(self):
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Add tabs
        tabs.addTab(self._create_scanner_tab(), "Scanner")
        tabs.addTab(self._create_sniffer_tab(), "Sniffer")
        tabs.addTab(self._create_phisher_tab(), "Phisher")
        tabs.addTab(self._create_honeypot_tab(), "Honeypot")
    
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