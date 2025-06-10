from Crypto.Cipher import AES

from constants import *


class Server:
    def __init__(self, client):
        self.client_iv = client.IV
        self.key = client.key

    def process_request(self, ciphertext):
        """Simulates processing an encrypted request"""
        if self.padding_oracle(ciphertext, self.client_iv, self.key):
            return {"Code": 200, "Message": "Request processed successfully"}
        else:
            return {"Code": 400, "Message": "Bad request - invalid data"}

    def padding_oracle(self, ciphertext, iv, key):
        """
        Complete padding oracle function that:
        1. Decrypts the ciphertext
        2. Validates the padding
        3. Returns only whether padding is valid
        This simulates the server's behavior in the POODLE attack scenario.
        """
        key = self.key if key is None else key
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)
            if self.ssl3_validate_padding(decrypted_data, BLOCK_SIZE):
                return True, decrypted_data[-1]
        except ValueError as e:
            print(f'ERROR: Server padding_oracle output: {str(e)}')
        return False, -1

    def ssl3_validate_padding(self, padded_data, block_size) -> bool:
        """
        SSL v3 vulnerable padding validation - only checks the last byte
        Returns True if padding is valid, False otherwise
        """
        if len(padded_data) == 0 or len(padded_data) % block_size != 0:
            return False
        pad_length = padded_data[-1]
        if pad_length >= block_size:
            return False
        if pad_length + 1 > len(padded_data):
            return False
        # SSL v3 vulnerability: only checks the padding length byte
        # NOT checking the content of the other padding bytes
        # In a proper implementation (like TLS), server would also verify all padding bytes
        # have the same value, but SSL v3 doesn't do this check
        return True
