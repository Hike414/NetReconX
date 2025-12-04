import requests
import urllib.parse
import threading
import concurrent.futures
from typing import List, Dict, Optional
import time

class HTTPBruteDir:
    def __init__(self, max_threads: int = 20, timeout: int = 5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.common_dirs = [
            'admin', 'administrator', 'wp-admin', 'wp-login', 'login',
            'panel', 'cpanel', 'control', 'dashboard', 'config',
            'test', 'dev', 'staging', 'backup', 'old', 'tmp',
            'files', 'uploads', 'download', 'images', 'css', 'js',
            'phpmyadmin', 'mysql', 'database', 'db', 'api',
            'mail', 'email', 'webmail', 'ftp', 'ssh', 'telnet',
            'private', 'secure', 'hidden', 'secret', 'internal',
            'logs', 'error', 'access', 'cache', 'temp', 'tmp',
            'bin', 'etc', 'var', 'usr', 'home', 'root',
            'docs', 'documentation', 'help', 'support', 'faq',
            'search', 'index', 'home', 'default', 'welcome',
            'forum', 'blog', 'news', 'shop', 'store', 'cart',
            'account', 'profile', 'user', 'member', 'guest',
            'public', 'www', 'web', 'site', 'html', 'htm',
            'cgi-bin', 'scripts', 'programs', 'tools', 'utilities',
            'backup', 'bak', 'old', 'copy', 'orig', 'save',
            'install', 'setup', 'upgrade', 'update', 'patch',
            'maintenance', 'offline', 'down', 'error', 'forbidden'
        ]
    
    def brute_force(self, base_url: str, wordlist: Optional[List[str]] = None, 
                   user_agent: str = "NetReconX/1.0") -> List[Dict]:
        """Brute force directories on web server"""
        results = []
        
        # Normalize URL
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Use provided wordlist or default common directories
        directories = wordlist if wordlist else self.common_dirs
        
        def check_directory(directory):
            try:
                url = urllib.parse.urljoin(base_url, directory)
                headers = {'User-Agent': user_agent}
                
                response = requests.get(url, headers=headers, timeout=self.timeout, 
                                      allow_redirects=False, verify=False)
                
                # Check for interesting response codes
                if response.status_code in [200, 201, 202, 203, 204, 205, 206]:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'type': 'directory'
                    }
                elif response.status_code in [401, 403]:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'type': 'protected'
                    }
                elif response.status_code == 301 or response.status_code == 302:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'location': response.headers.get('Location', ''),
                        'type': 'redirect'
                    }
                
            except requests.exceptions.RequestException:
                pass
            
            return None
        
        # Use ThreadPoolExecutor for concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_dir = {executor.submit(check_directory, directory): directory 
                           for directory in directories}
            
            for future in concurrent.futures.as_completed(future_to_dir):
                result = future.result()
                if result:
                    results.append(result)
        
        return sorted(results, key=lambda x: x['url'])
    
    def recursive_brute(self, base_url: str, max_depth: int = 2, 
                       wordlist: Optional[List[str]] = None) -> List[Dict]:
        """Recursive directory brute forcing"""
        all_results = []
        urls_to_check = [(base_url, 0)]  # (url, depth)
        checked_urls = set()
        
        while urls_to_check:
            current_url, depth = urls_to_check.pop(0)
            
            if current_url in checked_urls or depth >= max_depth:
                continue
            
            checked_urls.add(current_url)
            
            # Brute force current URL
            results = self.brute_force(current_url, wordlist)
            all_results.extend(results)
            
            # Add found directories for next level
            for result in results:
                if result['status_code'] == 200 and result['type'] == 'directory':
                    urls_to_check.append((result['url'], depth + 1))
        
        return all_results
    
    def save_results(self, results: List[Dict], filename: str):
        """Save results to file"""
        with open(filename, 'w') as f:
            f.write("URL,Status Code,Size,Type\n")
            for result in results:
                url = result['url']
                status = result['status_code']
                size = result['size']
                rtype = result['type']
                
                if 'location' in result:
                    f.write(f"{url},{status},{size},{rtype},Location: {result['location']}\n")
                else:
                    f.write(f"{url},{status},{size},{rtype}\n")
