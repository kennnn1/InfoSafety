import os
import logging
import secrets
import datetime
from typing import Dict, Any, Optional

from werkzeug.utils import secure_filename

from crypto import AESCipher, BlowfishCipher, ChaCha20Cipher
from qr_handler import read_qr_code

class DecryptionManager:
    def __init__(self, app_config):
        """
        Initialize DecryptionManager with application configuration
        
        Args:
            app_config (dict): Application configuration settings
        """
        self.app_config = app_config
        self.upload_folder = app_config['UPLOAD_FOLDER']
        self.download_folder = app_config['DOWNLOAD_FOLDER']
        
        # configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='decryption.log'
        )
        self.logger = logging.getLogger(__name__)
    
    def _get_cipher(self, algorithm: str, key: str):
        """
        Select appropriate cipher based on algorithm
        
        Args:
            algorithm (str): Encryption algorithm
            key (str): Decryption key
        
        Returns:
            Cipher object for decryption
        """
        cipher_map = {
            'aes': AESCipher,
            'blowfish': BlowfishCipher,
            'chacha20': ChaCha20Cipher
        }
        
        cipher_class = cipher_map.get(algorithm.lower())
        if not cipher_class:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return cipher_class(key)
    
    def decrypt_text(self, ciphertext: str, algorithm: str, key: str) -> str:
        """
        Decrypt text using specified algorithm
        
        Args:
            ciphertext (str): Encrypted text
            algorithm (str): Encryption algorithm
            key (str): Decryption key
        
        Returns:
            str: Decrypted plaintext
        """
        try:
            cipher = self._get_cipher(algorithm, key)
            decrypted_text = cipher.decrypt(ciphertext)
            
            self.logger.info(f"Text decryption successful - Algorithm: {algorithm}")
            return decrypted_text
        except Exception as e:
            self.logger.error(f"Text decryption failed - {str(e)}")
            raise
    
    def decrypt_file(self, file, algorithm: str, key: str) -> Dict[str, Any]:
        """
        Decrypt an uploaded file
        
        Args:
            file: Uploaded file object
            algorithm (str): Encryption algorithm
            key (str): Decryption key
        
        Returns:
            dict: Decryption result with file details
        """
        try:
            # secure filename to prevent directory traversal
            filename = secure_filename(file.filename)
            
            # read file content
            file_content = file.read()
            
            # choose cipher and decrypt
            cipher = self._get_cipher(algorithm, key)
            decrypted_content = cipher.decrypt_file(file_content)
            
            # generate unique filename for decrypted file
            output_filename = f"decrypted_{secrets.token_hex(8)}_{filename}"
            output_path = os.path.join(self.download_folder, output_filename)
            
            # save decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_content)
            
            self.logger.info(f"File decryption successful - Filename: {filename}, Algorithm: {algorithm}")
            
            return {
                'path': output_filename,
                'original_name': filename,
                'size': len(decrypted_content),
                'decrypted_at': datetime.datetime.now().isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"File decryption failed - {str(e)}")
            raise
    
    def decrypt_qr_code(self, qr_image, algorithm: str, key: str) -> str:
        """
        Decrypt text from a QR code image
        
        Args:
            qr_image: Uploaded QR code image
            algorithm (str): Encryption algorithm
            key (str): Decryption key
        
        Returns:
            str: Decrypted text from QR code
        """
        try:
            # secure filename
            filename = secure_filename(qr_image.filename)
            filepath = os.path.join(self.upload_folder, filename)
            qr_image.save(filepath)
            
            # sead QR code content
            encrypted_data = read_qr_code(filepath)
            
            if not encrypted_data:
                raise ValueError("No valid QR code data found")
            
            # decrypt qr code content
            cipher = self._get_cipher(algorithm, key)
            decrypted_text = cipher.decrypt(encrypted_data)
            
            self.logger.info(f"QR code decryption successful - Algorithm: {algorithm}")
            return decrypted_text
        
        except Exception as e:
            self.logger.error(f"QR code decryption failed - {str(e)}")
            raise

    def cleanup_temp_files(self, max_age_hours: int = 24):
        """
        Clean up temporary uploaded and decrypted files
        
        Args:
            max_age_hours (int): Max age of files to keep
        """
        current_time = datetime.datetime.now()
        
        for folder in [self.upload_folder, self.download_folder]:
            for filename in os.listdir(folder):
                filepath = os.path.join(folder, filename)
                
                # skip if not a file
                if not os.path.isfile(filepath):
                    continue
                
                # get file creation time
                file_creation_time = datetime.datetime.fromtimestamp(os.path.getctime(filepath))
                
                # check if file is older than max_age_hours
                if (current_time - file_creation_time).total_seconds() > max_age_hours * 3600:
                    try:
                        os.remove(filepath)
                        self.logger.info(f"Deleted old file: {filename}")
                    except Exception as e:
                        self.logger.error(f"Error deleting file {filename}: {str(e)}")