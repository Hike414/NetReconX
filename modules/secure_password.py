import secrets
import string
import hashlib
import re
from typing import List, Dict, Tuple, Optional

class SecurePassword:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '123456789', 'guest', 'qwerty',
            '1234567890', '1234567', '12345678', '12345', '111111',
            '12345678910', '1234', 'abc123', '123123', 'password1',
            'admin', 'qwerty123', '1q2w3e4r', '123123123', 'qwertyuiop',
            'password123', '1234', '111111', '12345', 'dragon',
            'master', 'hello', 'freedom', 'whatever', 'qazwsx',
            'trustno1', '123qwe', '1q2w3e', 'zxcvbnm', '123abc'
        ]
    
    def generate_password(self, length: int = 12, use_upper: bool = True,
                          use_lower: bool = True, use_digits: bool = True,
                          use_symbols: bool = True, exclude_ambiguous: bool = False) -> str:
        """Generate secure random password"""
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        charset = ''
        if use_lower:
            charset += string.ascii_lowercase
        if use_upper:
            charset += string.ascii_uppercase
        if use_digits:
            charset += string.digits
        if use_symbols:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if exclude_ambiguous:
            ambiguous = '0O1lI'
            charset = ''.join(c for c in charset if c not in ambiguous)
        
        if not charset:
            raise ValueError("At least one character type must be selected")
        
        # Ensure password contains at least one character from each selected type
        password_chars = []
        if use_lower:
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password_chars.append(secrets.choice(string.digits))
        if use_symbols:
            password_chars.append(secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?'))
        
        # Fill remaining length with random characters
        remaining_length = length - len(password_chars)
        password_chars.extend(secrets.choice(charset) for _ in range(remaining_length))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def generate_passphrase(self, word_count: int = 4, separator: str = '-',
                          capitalize: bool = False, include_numbers: bool = False) -> str:
        """Generate passphrase using common words"""
        word_list = [
            'apple', 'banana', 'computer', 'dragon', 'elephant', 'forest',
            'garden', 'house', 'island', 'jungle', 'kitchen', 'mountain',
            'nature', 'ocean', 'palace', 'quantum', 'rainbow', 'sunset',
            'tiger', 'umbrella', 'village', 'waterfall', 'xylophone', 'yellow',
            'zebra', 'butterfly', 'chocolate', 'diamond', 'emerald', 'fountain',
            'galaxy', 'harmony', 'infinity', 'journey', 'kingdom', 'lighthouse',
            'miracle', 'nebula', 'orchestra', 'paradise', 'quantum', 'rainforest',
            'symphony', 'treasure', 'universe', 'volcano', 'whisper', 'crystal'
        ]
        
        words = [secrets.choice(word_list) for _ in range(word_count)]
        
        if capitalize:
            words = [word.capitalize() for word in words]
        
        if include_numbers:
            words = [f"{word}{secrets.choice('0123456789')}" for word in words]
        
        return separator.join(words)
    
    def check_password_strength(self, password: str) -> Dict:
        """Check password strength and provide feedback"""
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Include lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Include uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Include numbers")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 1
        else:
            feedback.append("Include special characters")
        
        # Common password check
        if password.lower() in self.common_passwords:
            score = max(0, score - 3)
            feedback.append("Password is too common")
        
        # Pattern checks
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 1
            feedback.append("Avoid repeated characters")
        
        if re.search(r'123456|qwerty|asdfgh|zxcvbn', password.lower()):  # Common patterns
            score -= 1
            feedback.append("Avoid common keyboard patterns")
        
        # Determine strength level
        if score >= 7:
            strength = "Very Strong"
        elif score >= 5:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        elif score >= 1:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        # Calculate entropy (simplified)
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 25
        
        entropy = length * (charset_size.bit_length() if charset_size > 0 else 0)
        
        return {
            'password': password,
            'strength': strength,
            'score': score,
            'max_score': 8,
            'entropy': entropy,
            'length': length,
            'feedback': feedback
        }
    
    def estimate_crack_time(self, password: str) -> Dict:
        """Estimate password cracking time"""
        # Calculate character set size
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 25
        
        if charset_size == 0:
            return {'error': 'Invalid password'}
        
        # Calculate combinations
        combinations = charset_size ** len(password)
        
        # Different attack scenarios (assumptions per second)
        scenarios = {
            'offline_slow': 1000,  # 1K hashes/sec
            'offline_fast': 1000000000,  # 1B hashes/sec (GPU)
            'online': 100,  # 100 attempts/sec
            'rate_limited': 1  # 1 attempt/sec
        }
        
        results = {}
        for scenario, rate in scenarios.items():
            seconds = combinations / rate
            
            if seconds < 60:
                time_str = f"{seconds:.2f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds/60:.2f} minutes"
            elif seconds < 86400:
                time_str = f"{seconds/3600:.2f} hours"
            elif seconds < 31536000:
                time_str = f"{seconds/86400:.2f} days"
            else:
                time_str = f"{seconds/31536000:.2f} years"
            
            results[scenario] = {
                'seconds': seconds,
                'readable': time_str,
                'rate': rate
            }
        
        return {
            'password_length': len(password),
            'charset_size': charset_size,
            'combinations': combinations,
            'scenarios': results
        }
    
    def hash_password(self, password: str, salt: Optional[str] = None,
                     algorithm: str = 'sha256', iterations: int = 100000) -> Dict:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        if algorithm == 'sha256':
            hash_func = hashlib.sha256
        elif algorithm == 'sha512':
            hash_func = hashlib.sha512
        else:
            return {'error': 'Unsupported algorithm'}
        
        hash_bytes = hashlib.pbkdf2_hmac(
            algorithm.replace('sha', 'sha'),
            password_bytes,
            salt_bytes,
            iterations
        )
        
        return {
            'algorithm': algorithm,
            'iterations': iterations,
            'salt': salt,
            'hash': hash_bytes.hex(),
            'full_hash': f"${algorithm}${iterations}${salt}${hash_bytes.hex()}"
        }
