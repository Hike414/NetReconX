import hashlib
import threading
import concurrent.futures
from typing import List, Dict, Optional, Union
import time

class HashCracker:
    def __init__(self, max_threads: int = 10):
        self.max_threads = max_threads
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'ripemd160': lambda: hashlib.new('ripemd160')
        }
    
    def detect_hash_type(self, hash_string: str) -> List[str]:
        """Detect possible hash types based on length and format"""
        hash_string = hash_string.lower()
        possible_types = []
        
        # Remove common prefixes
        if hash_string.startswith('$1$'):
            possible_types.append('md5')
        elif hash_string.startswith('$5$'):
            possible_types.append('sha256')
        elif hash_string.startswith('$6$'):
            possible_types.append('sha512')
        elif hash_string.startswith('$apr1$'):
            possible_types.append('md5_apr1')
        
        # Check by length
        length = len(hash_string)
        if length == 32:
            possible_types.append('md5')
        elif length == 40:
            possible_types.append('sha1')
        elif length == 64:
            possible_types.append('sha256')
        elif length == 96:
            possible_types.append('sha384')
        elif length == 128:
            possible_types.append('sha512')
        elif length == 40:  # RIPEMD-160 also produces 40 chars
            possible_types.append('ripemd160')
        
        return possible_types
    
    def crack_hash(self, hash_string: str, wordlist: List[str], 
                   hash_type: Optional[str] = None) -> Dict:
        """Crack hash using wordlist"""
        hash_string = hash_string.lower()
        
        # Detect hash type if not specified
        if not hash_type:
            possible_types = self.detect_hash_type(hash_string)
            if not possible_types:
                return {'status': 'error', 'message': 'Unknown hash type'}
            hash_type = possible_types[0]
        
        # Verify hash type is supported
        if hash_type not in self.hash_algorithms:
            return {'status': 'error', 'message': f'Unsupported hash type: {hash_type}'}
        
        def check_word(word):
            try:
                if hash_type == 'ripemd160':
                    hasher = hashlib.new('ripemd160')
                    hasher.update(word.encode('utf-8'))
                    word_hash = hasher.hexdigest()
                else:
                    hasher = self.hash_algorithms[hash_type]()
                    hasher.update(word.encode('utf-8'))
                    word_hash = hasher.hexdigest()
                
                if word_hash == hash_string:
                    return word
            except Exception:
                pass
            return None
        
        # Use ThreadPoolExecutor for parallel cracking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_word = {executor.submit(check_word, word): word for word in wordlist}
            
            for future in concurrent.futures.as_completed(future_to_word):
                result = future.result()
                if result:
                    return {
                        'status': 'success',
                        'hash': hash_string,
                        'type': hash_type,
                        'plaintext': result,
                        'wordlist_size': len(wordlist)
                    }
        
        return {
            'status': 'not_found',
            'hash': hash_string,
            'type': hash_type,
            'wordlist_size': len(wordlist)
        }
    
    def crack_multiple_hashes(self, hashes: List[str], wordlist: List[str]) -> Dict:
        """Crack multiple hashes"""
        results = {}
        
        for hash_string in hashes:
            result = self.crack_hash(hash_string, wordlist)
            results[hash_string] = result
        
        return results
    
    def generate_wordlist_variations(self, base_word: str) -> List[str]:
        """Generate common password variations"""
        variations = [base_word]
        
        # Common transformations
        variations.extend([
            base_word.capitalize(),
            base_word.upper(),
            base_word.lower(),
            base_word + '1',
            base_word + '123',
            base_word + '2023',
            base_word + '2024',
            '1' + base_word,
            '123' + base_word,
            base_word + '!',
            base_word + '@',
            base_word + '#',
            base_word + '$',
        ])
        
        # Leet speak variations
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leet_word = base_word
        for char, replacement in leet_map.items():
            leet_word = leet_word.replace(char, replacement)
        variations.append(leet_word)
        
        # Reverse
        variations.append(base_word[::-1])
        
        return list(set(variations))  # Remove duplicates
    
    def dictionary_attack(self, hash_string: str, dictionary_file: str,
                         hash_type: Optional[str] = None) -> Dict:
        """Dictionary attack using file"""
        try:
            with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            return self.crack_hash(hash_string, wordlist, hash_type)
        
        except FileNotFoundError:
            return {'status': 'error', 'message': f'Dictionary file not found: {dictionary_file}'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error reading dictionary: {str(e)}'}
    
    def brute_force_attack(self, hash_string: str, max_length: int = 8,
                          charset: str = 'abcdefghijklmnopqrstuvwxyz0123456789',
                          hash_type: Optional[str] = None) -> Dict:
        """Brute force attack (limited to reasonable lengths)"""
        if max_length > 8:
            return {'status': 'error', 'message': 'Brute force limited to max 8 characters for performance'}
        
        def generate_combinations(charset, max_length):
            if max_length == 0:
                yield ''
            else:
                for char in charset:
                    for combo in generate_combinations(charset, max_length - 1):
                        yield char + combo
        
        def check_word(word):
            try:
                if hash_type == 'ripemd160':
                    hasher = hashlib.new('ripemd160')
                    hasher.update(word.encode('utf-8'))
                    word_hash = hasher.hexdigest()
                else:
                    hasher = self.hash_algorithms[hash_type]()
                    hasher.update(word.encode('utf-8'))
                    word_hash = hasher.hexdigest()
                
                if word_hash == hash_string:
                    return word
            except Exception:
                pass
            return None
        
        # Detect hash type if not specified
        if not hash_type:
            possible_types = self.detect_hash_type(hash_string)
            if not possible_types:
                return {'status': 'error', 'message': 'Unknown hash type'}
            hash_type = possible_types[0]
        
        # Generate and test combinations
        for length in range(1, max_length + 1):
            for word in generate_combinations(charset, length):
                result = check_word(word)
                if result:
                    return {
                        'status': 'success',
                        'hash': hash_string,
                        'type': hash_type,
                        'plaintext': result,
                        'method': 'brute_force'
                    }
        
        return {
            'status': 'not_found',
            'hash': hash_string,
            'type': hash_type,
            'method': 'brute_force',
            'max_length': max_length
        }
