from constants import *


class Attacker:
    def __init__(self, client):
        self.client = client

    def extract_byte(self, target_block, prev_block, oracle_func):
        """
        Recover the plaintext byte at position 15 of target_block.

        POODLE trick: SSL3 validates padding by checking ONLY the last byte
        (must be 0-15). We try all 256 values for prev_block[15] and ask the
        oracle whether the resulting decryption has valid padding.

        CBC math:
            decrypted[-1] = AES_decrypt(target_block)[-1] XOR modified_prev[15]
                          = (plaintext[15] XOR original_prev[15]) XOR guess

        Rearranging:
            plaintext[15] = decrypted_last_byte XOR original_prev[15] XOR guess

        The oracle returns the actual decrypted last byte on success, so the
        formula gives an exact answer on the very first hit.
        """
        for guess in range(256):
            modified_prev = bytearray(prev_block)
            modified_prev[15] = guess

            # Send the single target block with the modified previous block as IV
            pad_flag, decrypted_last_byte = oracle_func(
                bytes(target_block), bytes(modified_prev), None
            )
            if pad_flag:
                plaintext_byte = decrypted_last_byte ^ prev_block[15] ^ guess
                return plaintext_byte

        return None  # should not happen for a correct oracle

    def poodle_attack(self, oracle_func, secret_length):
        """
        Full POODLE attack: recover every byte of the secret one at a time.

        For each byte index i (0 .. secret_length-1):
          1. Choose prefix_len = (15 - i) % 16 so that secret[i] lands at
             position 15 of block 0 in the fresh encryption.
          2. Request a fresh ciphertext from the client with that prefix.
          3. Feed block 0 (and the IV as its "previous block") to extract_byte.
          4. The oracle query modifies only IV[15] — the one byte that XORs
             into plaintext position 15, which is the byte SSL3 validates.
        """
        extracted = bytearray(secret_length)
        print(f"\n[POODLE] Starting attack — recovering {secret_length} byte(s)...")

        for i in range(secret_length - 1, -1, -1):
            # Position secret[i] at byte offset 15 inside block 0
            prefix_len = (15 - i) % 16

            ciphertext = self.client.encrypt_with_prefix_len(prefix_len)

            # Block 0 of this ciphertext has the target byte at position 15
            target_block = ciphertext[:BLOCK_SIZE]
            prev_block   = self.client.IV   # block 0's "previous" is the IV

            byte_val = self.extract_byte(target_block, prev_block, oracle_func)

            if byte_val is not None:
                extracted[i] = byte_val
                print(f"[POODLE] secret[{i}] = {chr(byte_val)!r}  (0x{byte_val:02x})")
            else:
                print(f"[POODLE] secret[{i}]: FAILED to recover")

        result = bytes(extracted)
        print(f"[POODLE] Recovered secret: {result}")
        return result

    def _analyze_ciphertext(self, ciphertext):
        """Helper to display the block structure of an intercepted ciphertext."""
        total_length = len(ciphertext)
        num_blocks = total_length // BLOCK_SIZE
        print(f"INFO: MITM_attacker - total ciphertext length: {total_length} bytes")
        print(f"INFO: MITM_attacker - Number of blocks: {num_blocks}")
        for i in range(num_blocks):
            start = i * BLOCK_SIZE
            block = ciphertext[start:start + BLOCK_SIZE]
            print(f"INFO: MITM_attacker - Block {i}: {len(block)} bytes - {block.hex()}")
