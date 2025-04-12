import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Blowfish, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class BaseCipher:
    """Base class for all cipher implementations"""
    
    def __init__(self, key):
        """Initialize with a key"""
        self.key = self._derive_key(key)
    
    def _derive_key(self, key):
        """Convert a user-provided key into a fixed-length key suitable for the cipher"""
        # using SHA-256 to derive a fixed length key
        return hashlib.sha256(key.encode()).digest()
    
    def encrypt(self, plaintext):
        """Encrypt text and return a base64 encoded string"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext):
        """Decrypt base64 encoded ciphertext and return plaintext"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def encrypt_file(self, file_content):
        """Encrypt binary file content"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt_file(self, encrypted_content):
        """Decrypt binary file content"""
        raise NotImplementedError("Subclasses must implement this method")


class AESCipher(BaseCipher):
    """Implementation of AES-256 encryption"""
    
    def __init__(self, key):
        super().__init__(key)
        # AES-256 requires a 32-byte key, which we get from SHA-256
        self.block_size = 16  # AES block size in bytes
    
    def encrypt(self, plaintext):
        """Encrypt text and return a base64 encoded string"""
        # generate a random IV
        iv = os.urandom(self.block_size)
        
        # create an encryptor object
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()
        
        # pad the plaintext to be a multiple of block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # combine IV and ciphertext and encode with base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        return encrypted_data
    
    def decrypt(self, ciphertext):
        """Decrypt base64 encoded ciphertext and return plaintext"""
        # decode the base64 ciphertext
        encrypted_data = base64.b64decode(ciphertext)
        
        # extract IV (first block_size bytes)
        iv = encrypted_data[:self.block_size]
        actual_ciphertext = encrypted_data[self.block_size:]
        
        # create a decryptor object
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        
        # decrypt the ciphertext
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, file_content):
        """Encrypt binary file content"""
        # generate a random IV
        iv = os.urandom(self.block_size)
        
        # create an encryptor object
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()
        
        # pad the file content to be a multiple of block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_content) + padder.finalize()
        
        # encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_file(self, encrypted_content):
        """Decrypt binary file content"""
        # extract IV (first block_size bytes)
        iv = encrypted_content[:self.block_size]
        actual_ciphertext = encrypted_content[self.block_size:]
        
        # create a decryptor object
        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        
        # decrypt the ciphertext
        padded_content = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        content = unpadder.update(padded_content) + unpadder.finalize()
        
        return content


class BlowfishCipher(BaseCipher):
    """Implementation of Blowfish encryption"""
    
    def __init__(self, key):
        super().__init__(key)
        # blowfish can use variable length keys, but we'll use a 32-byte key for consistency
        self.block_size = 8  # blowfish block size in bytes
    
    def encrypt(self, plaintext):
        """Encrypt text and return a base64 encoded string"""
        # generate a random IV
        iv = get_random_bytes(self.block_size)
        
        # create a Blowfish cipher object in CBC mode
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        
        # pad the plaintext to be a multiple of block size
        padded_data = pad(plaintext.encode(), self.block_size)
        
        # encrypt the padded data
        ciphertext = cipher.encrypt(padded_data)
        
        # combine IV and ciphertext and encode with base64
        encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
        return encrypted_data
    
    def decrypt(self, ciphertext):
        """Decrypt base64 encoded ciphertext and return plaintext"""
        # decode the base64 ciphertext
        encrypted_data = base64.b64decode(ciphertext)
        
        # extract IV (first block_size bytes)
        iv = encrypted_data[:self.block_size]
        actual_ciphertext = encrypted_data[self.block_size:]
        
        # create a Blowfish cipher object in CBC mode
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        
        # decrypt the ciphertext
        padded_plaintext = cipher.decrypt(actual_ciphertext)
        
        # unpad the decrypted data
        plaintext = unpad(padded_plaintext, self.block_size)
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, file_content):
        """Encrypt binary file content"""
        # generate a random IV
        iv = get_random_bytes(self.block_size)
        
        # create a Blowfish cipher object in CBC mode
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        
        # pad the file content to be a multiple of block size
        padded_data = pad(file_content, self.block_size)
        
        # encrypt the padded data
        ciphertext = cipher.encrypt(padded_data)
        
        # return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_file(self, encrypted_content):
        """Decrypt binary file content"""
        # extract IV (first block_size bytes)
        iv = encrypted_content[:self.block_size]
        actual_ciphertext = encrypted_content[self.block_size:]
        
        # create a blowfish cipher object in CBC mode
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        
        # decrypt the ciphertext
        padded_content = cipher.decrypt(actual_ciphertext)
        
        # unpad the decrypted data
        content = unpad(padded_content, self.block_size)
        
        return content


class ChaCha20Cipher(BaseCipher):
    """Implementation of ChaCha20 encryption"""
    
    def __init__(self, key):
        super().__init__(key)
        # ChaCha20 uses a 32-byte key (256 bits)
    
    def encrypt(self, plaintext):
        """Encrypt text and return a base64 encoded string"""
        # generate a random nonce
        nonce = get_random_bytes(12)  # 96-bit nonce for ChaCha20-Poly1305
        
        # create a ChaCha20-Poly1305 cipher object
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        
        # convert plaintext to bytes
        plaintext_bytes = plaintext.encode()
        
        # encrypt the data and get the tag
        ciphertext = cipher.encrypt(plaintext_bytes)
        tag = cipher.digest()
        
        # combine nonce, tag and ciphertext and encode with base64
        encrypted_data = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        return encrypted_data
    
    def decrypt(self, ciphertext):
        """Decrypt base64 encoded ciphertext and return plaintext"""
        # decode the base64 ciphertext
        encrypted_data = base64.b64decode(ciphertext)
        
        # extract nonce (first 12 bytes) and tag (next 16 bytes)
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        actual_ciphertext = encrypted_data[28:]
        
        # create a ChaCha20-Poly1305 cipher object
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        
        # set the received tag
        cipher.update(b'')  # AAD (Additional Authenticated Data) if needed
        
        try:
            # decrypt the ciphertext and verify the tag
            plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
            return plaintext.decode('utf-8')
        except ValueError:
            # this will be raised if the tag verification fails
            raise ValueError("Authentication failed: Data may be corrupted or key is incorrect")
    
    def encrypt_file(self, file_content):
        """Encrypt binary file content"""
        # generate a random nonce
        nonce = get_random_bytes(12)  # 96-bit nonce for ChaCha20-Poly1305
        
        # create a ChaCha20-Poly1305 cipher object
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        
        # encrypt the data and get the tag
        ciphertext = cipher.encrypt(file_content)
        tag = cipher.digest()
        
        # return nonce + tag + ciphertext
        return nonce + tag + ciphertext
    
    def decrypt_file(self, encrypted_content):
        """Decrypt binary file content"""
        # extract nonce (first 12 bytes) and tag (next 16 bytes)
        nonce = encrypted_content[:12]
        tag = encrypted_content[12:28]
        actual_ciphertext = encrypted_content[28:]
        
        # create a ChaCha20-Poly1305 cipher object
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        
        # set the received tag
        cipher.update(b'')  # AAD (Additional Authenticated Data) if needed
        
        try:
            # decrypt the ciphertext and verify the tag
            content = cipher.decrypt_and_verify(actual_ciphertext, tag)
            return content
        except ValueError:
            # this will be raised if the tag verification fails
            raise ValueError("Authentication failed: File may be corrupted or key is incorrect")