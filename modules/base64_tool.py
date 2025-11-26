import base64
from typing import Union

class Base64Tool:
    @staticmethod
    def encode(data: Union[str, bytes]) -> str:
        """Encode data to Base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode(data: str) -> str:
        """Decode Base64 data"""
        try:
            decoded_bytes = base64.b64decode(data)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            return f"Error decoding: {str(e)}"
    
    @staticmethod
    def encode_url_safe(data: Union[str, bytes]) -> str:
        """Encode data to URL-safe Base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_url_safe(data: str) -> str:
        """Decode URL-safe Base64 data"""
        try:
            decoded_bytes = base64.urlsafe_b64decode(data)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            return f"Error decoding: {str(e)}"
    
    @staticmethod
    def encode_file(file_path: str) -> str:
        """Encode file to Base64"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            return base64.b64encode(file_data).decode('utf-8')
        except Exception as e:
            return f"Error encoding file: {str(e)}"
    
    @staticmethod
    def decode_to_file(encoded_data: str, output_path: str) -> bool:
        """Decode Base64 data and save to file"""
        try:
            decoded_bytes = base64.b64decode(encoded_data)
            with open(output_path, 'wb') as f:
                f.write(decoded_bytes)
            return True
        except Exception as e:
            print(f"Error decoding to file: {str(e)}")
            return False
