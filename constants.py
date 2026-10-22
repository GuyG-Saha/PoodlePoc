BLOCK_SIZE = 16

# Length of the record MAC (bytes). Modelling the MAC is what makes the server
# a genuine accept/reject oracle: a tampered record only verifies when the
# decrypted final block is a whole block of padding, so acceptance is a
# 1-in-256 event rather than a leaked plaintext byte.
MAC_LEN = 16
