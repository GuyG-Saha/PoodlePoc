import hashlib
import hmac

from Crypto.Cipher import AES

from constants import *


class Server:
    """Emulates an SSL 3.0 server's record layer.

    It decrypts a CBC record, strips padding *the SSL3 way* — trusting only the
    final length byte and NOT inspecting the other padding bytes — then verifies
    the MAC. It returns only a single bit: accept or reject. No decrypted
    plaintext ever leaves the server, so there is nothing to leak.
    """

    def __init__(self, client):
        # Symmetric secrets shared with the client (as after a handshake).
        self.key = client.key
        self.mac_key = client.mac_key

    def process_request(self, iv, ciphertext):
        if self._decrypt_and_verify(iv, ciphertext):
            return {"Code": 200, "Message": "Request processed successfully"}
        return {"Code": 400, "Message": "Bad request - invalid data"}

    def padding_oracle(self, iv, ciphertext):
        """The only thing the attacker can observe: one accept/reject bit."""
        return self._decrypt_and_verify(iv, ciphertext)

    def _decrypt_and_verify(self, iv, ciphertext):
        if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
            return False

        plaintext = AES.new(self.key, AES.MODE_CBC, iv).decrypt(ciphertext)

        # --- SSL3 padding removal (the vulnerable part) ---
        pad_len = plaintext[-1]          # trust the length byte...
        if pad_len >= BLOCK_SIZE:
            return False
        strip = pad_len + 1
        if strip > len(plaintext):
            return False
        # ...and DO NOT check the content of the other padding bytes. A proper
        # TLS implementation verifies every padding byte here; SSL3 does not,
        # which is exactly what POODLE relies on.
        body = plaintext[:-strip]

        # --- MAC verification (what makes this a 1-in-256 oracle) ---
        if len(body) < MAC_LEN:
            return False
        data, mac = body[:-MAC_LEN], body[-MAC_LEN:]
        expected = hmac.new(self.mac_key, data, hashlib.sha256).digest()[:MAC_LEN]

        # When an attacker swaps in a chosen block as the final block, the
        # record only leaves data||MAC intact (and so verifies) if the decrypted
        # last byte happens to be BLOCK_SIZE-1 — i.e. the whole final block is
        # taken as padding. That is a 1-in-256 event, and it reveals nothing
        # beyond "it happened".
        return hmac.compare_digest(mac, expected)
