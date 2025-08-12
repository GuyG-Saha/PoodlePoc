from datetime import datetime
from server import Server

from client import Client

from MITM_attacker import Attacker

if __name__ == '__main__':
    secret = b"abcabcabc"
    prefix = b""
    ssl_v3_client = Client(secret, prefix, 'pcks7')
    mock_ssl_v3_server = Server(ssl_v3_client)

    # Initial client-server communication
    ciphertext, response = ssl_v3_client.create_request_and_send(mock_ssl_v3_server)
    print(f"INFO: {datetime.now()} - Initial Server response: {response}")
    poodle_attacker = Attacker(client_iv=ssl_v3_client.IV, ciphertext=ciphertext)

    extracted_secret = poodle_attacker.poodle_attack(
        ciphertext,
        ssl_v3_client.IV,
        mock_ssl_v3_server.padding_oracle  # Attacker uses server as oracle
    )
    print(f"Attacker extracted: {extracted_secret}")

