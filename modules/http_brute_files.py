import requests
import urllib.parse
import threading
import concurrent.futures
from typing import List, Dict, Optional
import time
import mimetypes

class HTTPBruteFiles:
    def __init__(self, max_threads: int = 20, timeout: int = 5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.common_files = [
            # Web config files
            'web.config', '.htaccess', '.htpasswd', 'config.ini', 'config.php',
            'config.inc', 'config.cfg', 'settings.ini', 'settings.php',
            'database.ini', 'database.php', 'db.ini', 'db.php',
            
            # Backup files
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.bak',
            'dump.sql', 'database.sql', 'db.sql', 'backup.tar',
            'www.zip', 'site.zip', 'web.zip', 'files.zip',
            
            # Log files
            'access.log', 'error.log', 'debug.log', 'apache.log',
            'nginx.log', 'php.log', 'mysql.log', 'system.log',
            
            # Sensitive files
            'passwords.txt', 'passwords.lst', 'users.txt', 'users.lst',
            'admin.txt', 'admin.lst', 'config.txt', 'secrets.txt',
            'private.key', 'public.key', 'id_rsa', 'id_dsa',
            '.env', '.git/config', '.svn/entries',
            
            # Common web files
            'index.html', 'index.php', 'index.htm', 'default.html',
            'home.html', 'main.html', 'welcome.html', 'test.html',
            'robots.txt', 'sitemap.xml', 'favicon.ico', 'crossdomain.xml',
            
            # Development files
            'README.md', 'README.txt', 'CHANGELOG.md', 'LICENSE',
            'composer.json', 'package.json', 'requirements.txt',
            'Dockerfile', 'docker-compose.yml', '.gitignore',
            
            # CMS files
            'wp-config.php', 'wp-login.php', 'xmlrpc.php',
            'joomla.xml', 'configuration.php', 'settings.php',
            'drupal.ini', 'settings.local.php',
            
            # Source code files
            'source.zip', 'src.zip', 'code.zip', 'app.zip',
            'scripts.js', 'style.css', 'main.css', 'app.js',
            
            # Document files
            'document.pdf', 'manual.pdf', 'guide.pdf', 'help.pdf',
            'report.doc', 'report.docx', 'data.xls', 'data.xlsx',
            
            # Database files
            'database.mdb', 'database.db', 'data.db', 'app.db',
            'sqlite.db', 'sqlite3.db',
            
            # Temporary files
            'temp.tmp', 'temp.txt', 'tmp.tmp', 'cache.tmp',
            'session.tmp', 'upload.tmp', 'file.tmp'
        ]
        
        # File extensions to try
        self.extensions = [
            '', '.txt', '.php', '.html', '.htm', '.asp', '.aspx',
            '.jsp', '.js', '.css', '.xml', '.json', '.yml', '.yaml',
            '.ini', '.cfg', '.conf', '.log', '.bak', '.backup',
            '.old', '.orig', '.save', '.tmp', '.temp', '.swp',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.sql',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
            '.mdb', '.db', '.sqlite', '.sqlite3', '.key', '.pem'
        ]
    
    def brute_force(self, base_url: str, wordlist: Optional[List[str]] = None,
                   extensions: Optional[List[str]] = None,
                   user_agent: str = "NetReconX/1.0") -> List[Dict]:
        """Brute force files on web server"""
        results = []
        
        # Normalize URL
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Use provided wordlist or default common files
        files = wordlist if wordlist else self.common_files
        ext_list = extensions if extensions else self.extensions
        
        # Generate all file combinations
        file_combinations = []
        for file_name in files:
            for ext in ext_list:
                if not file_name.endswith(ext):
                    file_combinations.append(file_name + ext)
                else:
                    file_combinations.append(file_name)
        
        def check_file(file_path):
            try:
                url = urllib.parse.urljoin(base_url, file_path)
                headers = {'User-Agent': user_agent}
                
                response = requests.get(url, headers=headers, timeout=self.timeout,
                                      allow_redirects=False, verify=False)
                
                # Check for interesting response codes
                if response.status_code in [200, 201, 202, 203, 204, 205, 206]:
                    # Determine file type
                    content_type = response.headers.get('Content-Type', '')
                    file_type = self._determine_file_type(file_path, content_type)
                    
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'content_type': content_type,
                        'file_type': file_type,
                        'filename': file_path
                    }
                elif response.status_code in [401, 403]:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'content_type': response.headers.get('Content-Type', ''),
                        'file_type': 'protected',
                        'filename': file_path
                    }
                elif response.status_code == 301 or response.status_code == 302:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'location': response.headers.get('Location', ''),
                        'file_type': 'redirect',
                        'filename': file_path
                    }
                
            except requests.exceptions.RequestException:
                pass
            
            return None
        
        # Use ThreadPoolExecutor for concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_file = {executor.submit(check_file, file_path): file_path
                             for file_path in file_combinations}
            
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                if result:
                    results.append(result)
        
        return sorted(results, key=lambda x: x['url'])
    
    def _determine_file_type(self, filename: str, content_type: str) -> str:
        """Determine file type based on filename and content type"""
        # Check by content type first
        if 'text/html' in content_type:
            return 'html'
        elif 'text/css' in content_type:
            return 'css'
        elif 'text/javascript' in content_type or 'application/javascript' in content_type:
            return 'javascript'
        elif 'application/json' in content_type:
            return 'json'
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return 'xml'
        elif 'application/pdf' in content_type:
            return 'pdf'
        elif 'application/zip' in content_type:
            return 'zip'
        elif 'image/' in content_type:
            return 'image'
        elif 'video/' in content_type:
            return 'video'
        elif 'audio/' in content_type:
            return 'audio'
        
        # Check by extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        
        if ext in ['php', 'phtml', 'php3', 'php4', 'php5']:
            return 'php'
        elif ext in ['asp', 'aspx']:
            return 'asp'
        elif ext in ['jsp']:
            return 'jsp'
        elif ext in ['html', 'htm']:
            return 'html'
        elif ext in ['css']:
            return 'css'
        elif ext in ['js']:
            return 'javascript'
        elif ext in ['json']:
            return 'json'
        elif ext in ['xml']:
            return 'xml'
        elif ext in ['txt', 'log', 'conf', 'cfg', 'ini']:
            return 'text'
        elif ext in ['sql']:
            return 'sql'
        elif ext in ['zip', 'tar', 'gz', 'rar', '7z']:
            return 'archive'
        elif ext in ['pdf']:
            return 'pdf'
        elif ext in ['doc', 'docx']:
            return 'document'
        elif ext in ['xls', 'xlsx']:
            return 'spreadsheet'
        elif ext in ['mdb', 'db', 'sqlite', 'sqlite3']:
            return 'database'
        elif ext in ['key', 'pem', 'crt', 'cert']:
            return 'certificate'
        elif ext in ['bak', 'backup', 'old', 'orig', 'save']:
            return 'backup'
        
        return 'unknown'
    
    def save_results(self, results: List[Dict], filename: str):
        """Save results to file"""
        with open(filename, 'w') as f:
            f.write("URL,Status Code,Size,Content Type,File Type,Filename\n")
            for result in results:
                url = result['url']
                status = result['status_code']
                size = result['size']
                content_type = result.get('content_type', '')
                file_type = result['file_type']
                filename = result['filename']
                
                if 'location' in result:
                    f.write(f"{url},{status},{size},{content_type},{file_type},{filename},Location: {result['location']}\n")
                else:
                    f.write(f"{url},{status},{size},{content_type},{file_type},{filename}\n")
