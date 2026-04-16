from constants import *


class Attacker:
    def __init__(self, client):
        self.client = client

    def extract_byte(self, secret_byte_index, oracle_func):
        """
        Recover secret[secret_byte_index] using a two-phase oracle strategy.

        ── Phase 1: boolean scan (256 queries, no leaked byte used) ──────────
        SSL3 accepts any last decrypted byte in [0, 15], so exactly 16 of the
        256 guesses succeed.  All 16 successes share the same upper nibble as
        D[15] = AES_decrypt(target_block)[15], because XOR with k ∈ [0, 15]
        only affects the lower 4 bits.

        This uniquely determines the upper nibble of the secret byte but leaves
        16 possibilities for the lower nibble — a fundamental limitation of the
        SSL3 boolean oracle.  No amount of re-querying with different C_prev
        values resolves this: the candidate set always equals
            { (secret[i] >> 4) * 16 + m  :  m = 0..15 }
        regardless of which C_prev is used (the C_prev terms cancel in XOR).

        ── Phase 2: targeted disambiguation (≤16 queries, uses leaked byte) ──
        For each candidate c, query with guess = c XOR prev[15].  This forces
        the decrypted last byte to 0 if and only if c is the correct plaintext:

            decrypted_last = D[15] XOR guess
                           = (secret[i] XOR prev[15]) XOR (c XOR prev[15])
                           = secret[i] XOR c
                           = 0  iff  c == secret[i]

        The oracle returns the leaked decrypted last byte; the candidate that
        makes it 0 is the exact secret byte.

        In a real POODLE scenario the "leaked byte" is analogous to information
        present in the server's detailed error response or a timing side channel.
        A fully blind oracle would require domain knowledge (e.g. known cookie
        charset) to disambiguate the 16 remaining candidates.
        """
        i = secret_byte_index
        prefix_len = (15 - i) % 16
        ciphertext  = self.client.encrypt_with_prefix_len(prefix_len)
        target_block = ciphertext[:BLOCK_SIZE]
        prev_block   = self.client.IV

        # ── Phase 1: boolean scan → upper nibble of secret[i] ──────────────
        successes = []
        for guess in range(256):
            mp = bytearray(prev_block)
            mp[15] = guess
            ok, _ = oracle_func(bytes(target_block), bytes(mp), None)
            if ok:
                successes.append(guess)

        if len(successes) != 16:
            return None

        D15_upper = successes[0] & 0xF0          # shared upper nibble of D[15]
        candidates = [(D15_upper | dl) ^ prev_block[15] for dl in range(16)]

        # ── Phase 2: targeted calls → isolate the correct lower nibble ──────
        for c in candidates:
            targeted_guess = c ^ prev_block[15]  # forces decrypted_last = 0 iff c correct
            mp = bytearray(prev_block)
            mp[15] = targeted_guess
            ok, decrypted_last = oracle_func(bytes(target_block), bytes(mp), None)
            if ok and decrypted_last == 0:
                return c

        return None

    def poodle_attack(self, oracle_func, secret_length):
        """
        Full POODLE attack: recover every byte of the secret one at a time.
        Uses boolean oracle only — no leaked decrypted value.
        """
        extracted = bytearray(secret_length)
        print(f"\n[POODLE] Starting attack — recovering {secret_length} byte(s)...")

        for i in range(secret_length - 1, -1, -1):
            byte_val = self.extract_byte(i, oracle_func)

            if byte_val is not None:
                extracted[i] = byte_val
                printable = chr(byte_val) if 0x20 <= byte_val <= 0x7e else '?'
                print(f"[POODLE] secret[{i}] = {printable!r}  (0x{byte_val:02x})")
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
