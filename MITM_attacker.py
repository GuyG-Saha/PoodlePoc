from constants import *


class Attacker:
    def __init__(self, client_iv, ciphertext):
        self.client_iv = client_iv
        self.original_ciphertext = ciphertext

    def extract_byte(self, target_block_index, target_byte_position, oracle_func):
        """
        Extract a single byte using padding oracle attack
        target_block_index: Which block contains the byte we want
        target_byte_position: Position within that block (0-15)
        oracle_func: The server's padding oracle
        """
        block_start = target_block_index * BLOCK_SIZE
        target_block = self.original_ciphertext[block_start:block_start + BLOCK_SIZE]
        if target_block_index == 0:
            # For first block, use IV as "previous block"
            previous_block = bytearray(self.client_iv)
        else:
            # Use the actual previous ciphertext block
            prev_start = (target_block_index - 1) * BLOCK_SIZE
            previous_block = bytearray(self.original_ciphertext[prev_start:prev_start + BLOCK_SIZE])

        # Try different values for the byte in previous_block that affects our target byte
        for guess in range(256):
            # Modify the previous block to test our guess
            modified_previous = previous_block.copy()
            modified_previous[target_byte_position] = guess

            # Create the ciphertext with our modification
            if target_block_index == 0:
                # Use modified IV
                test_ciphertext = target_block
                test_iv = bytes(modified_previous)
            else:
                # Replace the previous block in the ciphertext
                test_ciphertext = (self.original_ciphertext[:prev_start] +
                                   bytes(modified_previous) +
                                   self.original_ciphertext[prev_start + BLOCK_SIZE:])
                test_iv = self.client_iv

            # Query the oracle
            if oracle_func(test_ciphertext, test_iv, None):
                # Valid padding found! Now calculate the plaintext byte
                # This is where the CBC math comes in...
                # (The exact calculation depends on what padding value we're targeting)
                print(f"INFO: MITM_attacker - Found valid padding with guess: {guess}")
                return guess  # Simplified - you'll need the full math here

        return None  # Byte not found

    def poodle_attack(self, original_ciphertext, iv, oracle_func):
        """Full POODLE attack to extract secret"""
        # Divide ciphertext into blocks
        # For each byte in the secret:
        #   Position it at the end of a block
        #   Extract using padding oracle
        # Assemble and return plaintext
        self.original_ciphertext = original_ciphertext
        self.client_iv = iv

        self.analyze_ciphertext()
        # Start with the last block, last byte (this is where padding info is)
        num_blocks = len(original_ciphertext) // BLOCK_SIZE
        last_block_index = num_blocks - 1
        padding_byte = self.extract_byte(last_block_index, 15, oracle_func)
        print(f"Extracted padding byte: {padding_byte}")
        return padding_byte

    def analyze_ciphertext(self):
        """Helper to understand the structure of intercepted ciphertext"""
        total_length = len(self.original_ciphertext)
        num_blocks = total_length // BLOCK_SIZE
        print(f"INFO: MITM_attacker - total ciphertext length: {total_length} bytes")
        print(f"INFO: MITM_attacker - Number of blocks: {num_blocks}")
        for i in range(num_blocks):
            start = i * BLOCK_SIZE
            end = start + BLOCK_SIZE
            block = self.original_ciphertext[start:end]
            print(f"INFO: MITM_attacker - Block {i}: {len(block)} bytes - {block.hex()}")
