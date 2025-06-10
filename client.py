from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from server import Server

from constants import *


class Client:
    def __init__(self, secret, prefix):
        self.IV = get_random_bytes(BLOCK_SIZE)
        self.key = get_random_bytes(BLOCK_SIZE)
        self.secret = secret
        self.controllable_prefix = prefix

    def create_request_and_send(self, server: Server):
        cipher_text = self._cipher_plaintext()
        # In real scenario, this would be HTTP request/response
        server_response = server.process_request(cipher_text)
        return cipher_text, server_response

    def _cipher_plaintext(self):
        if self.controllable_prefix:
            plaintext = self.controllable_prefix + self.secret
        else:
            plaintext = self.secret
        padded_plaintext = self._ssl3_pad(plaintext, BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, self.IV)
        ciphered_text = cipher.encrypt(padded_plaintext)
        return ciphered_text

    def _ssl3_pad(self, data, block_size):
        # Calculate padding length needed
        pad_len = block_size - (len(data) % block_size)
        if pad_len == 0:
            pad_len = block_size
        # In SSL v3, only the last byte needs to be the padding length
        # Other padding bytes can be any value
        padding = bytes([0] * (pad_len - 1) + [pad_len - 1])
        return data + padding
