from constants import *


class Attacker:
    """A POODLE man-in-the-middle.

    Capabilities (all realistic for the attack):
      * It can make the client send requests with attacker-chosen prefix/suffix
        lengths (modelling injected JavaScript), but it never sees the secret.
      * It sees the ciphertext of each request on the wire.
      * It can tamper with a record and submit it to the server.
      * It observes ONLY the server's accept/reject bit — never any plaintext.

    From that single bit it recovers the secret one byte at a time, using the
    classic POODLE block-substitution trick. There is no leaked byte and no
    nibble ambiguity: every recovered byte is exact.
    """

    MAX_ATTEMPTS_PER_BYTE = 100_000

    def __init__(self, client):
        self.client = client

    @staticmethod
    def _blocks(iv, ciphertext):
        # blocks[0] = IV, blocks[1] = C0, blocks[2] = C1, ...
        return [iv] + [ciphertext[k:k + BLOCK_SIZE]
                       for k in range(0, len(ciphertext), BLOCK_SIZE)]

    def extract_byte(self, i, oracle_func):
        """Recover secret[i] exactly, using only the accept/reject oracle.

        Framing: choose prefix_len so secret[i] sits at offset 15 of some
        ciphertext block b, and suffix_len so the record is block-aligned. The
        record then looks like:  [ data blocks ... ][ MAC block ][ full padding
        block ]. The target byte may live in any data block, so secrets longer
        than one block work exactly the same way.

        Each attempt (with a fresh IV, so every block is randomised):
          1. Capture the ciphertext. C_target = block b holds secret[i] at
             offset 15; its CBC predecessor is C_{b-1} (the IV when b == 0).
          2. Forge a record by replacing the final padding block with C_target.
             The block now in front of C_target is the MAC block, C_mac.
          3. Ask the oracle. The server decrypts the last block as
                 P = AES_decrypt(C_target) XOR C_mac
             and accepts iff P[15] == BLOCK_SIZE-1 (the whole block reads as
             padding, so data||MAC is left intact and the MAC verifies).

        On acceptance:
             AES_decrypt(C_target)[15] XOR C_mac[15] == 15
          => AES_decrypt(C_target)[15] == 15 XOR C_mac[15]
        and from the original (un-forged) chaining of block b:
             secret[i] == AES_decrypt(C_target)[15] XOR C_{b-1}[15]
          => secret[i] == 15 XOR C_mac[15] XOR C_{b-1}[15]
        Every term on the right is known from the captured ciphertext, so the
        byte is recovered exactly. Acceptance is a 1-in-256 event, so each byte
        costs ~256 oracle requests on average.
        """
        secret_len = len(self.client.secret)
        prefix_len = (BLOCK_SIZE - 1 - i) % BLOCK_SIZE
        suffix_len = (-(prefix_len + secret_len)) % BLOCK_SIZE  # keep record block-aligned
        b = (prefix_len + i) // BLOCK_SIZE  # ciphertext block holding secret[i] at offset 15

        for attempt in range(1, self.MAX_ATTEMPTS_PER_BYTE + 1):
            iv, ct = self.client.attack_request(prefix_len, suffix_len)
            blocks = self._blocks(iv, ct)   # blocks[0] = IV, blocks[n+1] = C_n

            c_target = blocks[b + 1]    # C_b: secret[i] at offset 15
            predecessor = blocks[b]     # CBC predecessor of C_b (the IV when b == 0)
            c_mac = blocks[-2]          # block in front of the padding block

            forged = ct[:-BLOCK_SIZE] + c_target
            if oracle_func(iv, forged):
                d15 = (BLOCK_SIZE - 1) ^ c_mac[15]
                return d15 ^ predecessor[15], attempt

        return None, self.MAX_ATTEMPTS_PER_BYTE

    def poodle_attack(self, oracle_func, secret_length):
        """Recover the whole secret, byte by byte, from the boolean oracle."""
        extracted = bytearray(secret_length)
        total = 0
        print(f"\n[POODLE] Starting attack — recovering {secret_length} byte(s) "
              f"from an accept/reject oracle only...")

        for i in range(secret_length - 1, -1, -1):
            byte_val, attempts = self.extract_byte(i, oracle_func)
            total += attempts
            if byte_val is not None:
                extracted[i] = byte_val
                printable = chr(byte_val) if 0x20 <= byte_val <= 0x7e else '?'
                print(f"[POODLE] secret[{i}] = {printable!r}  (0x{byte_val:02x})  "
                      f"after {attempts} oracle request(s)")
            else:
                print(f"[POODLE] secret[{i}]: FAILED to recover")

        print(f"[POODLE] Total oracle requests: {total}")
        result = bytes(extracted)
        print(f"[POODLE] Recovered secret: {result}")
        return result
