import hashlib
import hmac
from typing import Union, Dict

class DigestTool:
    @staticmethod
    def md5(data: Union[str, bytes]) -> str:
        """Calculate MD5 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def sha1(data: Union[str, bytes]) -> str:
        """Calculate SHA1 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha1(data).hexdigest()
    
    @staticmethod
    def sha256(data: Union[str, bytes]) -> str:
        """Calculate SHA256 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha384(data: Union[str, bytes]) -> str:
        """Calculate SHA384 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha384(data).hexdigest()
    
    @staticmethod
    def sha512(data: Union[str, bytes]) -> str:
        """Calculate SHA512 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha512(data).hexdigest()
    
    @staticmethod
    def ripemd160(data: Union[str, bytes]) -> str:
        """Calculate RIPEMD-160 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            return hashlib.new('ripemd160', data).hexdigest()
        except ValueError:
            return "RIPEMD-160 not available in this Python installation"
    
    @staticmethod
    def hash_file(file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate hash of a file"""
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'ripemd160': lambda: hashlib.new('ripemd160')
        }
        
        if algorithm not in hash_algorithms:
            return f"Unsupported algorithm: {algorithm}"
        
        try:
            hasher = hash_algorithms[algorithm]()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error hashing file: {str(e)}"
    
    @staticmethod
    def hmac_hash(data: Union[str, bytes], key: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """Calculate HMAC hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in hash_algorithms:
            return f"Unsupported algorithm: {algorithm}"
        
        return hmac.new(key, data, hash_algorithms[algorithm]).hexdigest()
    
    @staticmethod
    def hash_all(data: Union[str, bytes]) -> Dict[str, str]:
        """Calculate all supported hashes for data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        results = {
            'md5': DigestTool.md5(data),
            'sha1': DigestTool.sha1(data),
            'sha256': DigestTool.sha256(data),
            'sha384': DigestTool.sha384(data),
            'sha512': DigestTool.sha512()
        }
        
        # Try RIPEMD-160 if available
        ripemd_result = DigestTool.ripemd160(data)
        if not ripemd_result.startswith("RIPEMD-160"):
            results['ripemd160'] = ripemd_result
        
        return results
