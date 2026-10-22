import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from constants import *


class Client:
    """Emulates an SSL 3.0 client's record layer.

    Every request is a self-contained CBC record built as

        plaintext = data || MAC(data) || padding

    with a FRESH random IV each time, exactly as a real SSL/TLS record layer
    behaves. The MAC authenticates the data; the SSL3 padding fills the record
    out to a block boundary, and only its final byte is meaningful (it stores
    number_of_padding_bytes - 1). SSL3 leaves the *contents* of the remaining
    padding bytes undefined — that is the flaw POODLE exploits on the server.
    """

    def __init__(self, secret):
        self.key = get_random_bytes(BLOCK_SIZE)
        self.mac_key = get_random_bytes(BLOCK_SIZE)
        self.secret = secret

    def _mac(self, data):
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()[:MAC_LEN]

    def _ssl3_pad(self, data):
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        # Only the last byte must carry (pad_len - 1); the rest are arbitrary.
        return data + bytes([0] * (pad_len - 1) + [pad_len - 1])

    def _encrypt_record(self, data):
        plaintext = self._ssl3_pad(data + self._mac(data))
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv, cipher.encrypt(plaintext)

    def create_request_and_send(self, server):
        """A normal, legitimate request carrying the secret."""
        iv, ciphertext = self._encrypt_record(self.secret)
        return iv, ciphertext, server.process_request(iv, ciphertext)

    def attack_request(self, prefix_len, suffix_len):
        """Send a request whose framing the attacker controls.

        The attacker (e.g. injected JavaScript) cannot read the secret, but it
        can pad the request around the secret with bytes of its choosing. By
        picking ``prefix_len`` and ``suffix_len`` it slides the secret to a
        chosen block offset and keeps the record block-aligned. A fresh IV
        randomises the whole CBC chain on every call, which is what lets the
        attacker keep retrying until a guess lands.
        """
        data = b'\x00' * prefix_len + self.secret + b'\x00' * suffix_len
        return self._encrypt_record(data)
