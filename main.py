from datetime import datetime
from server import Server
from client import Client
from MITM_attacker import Attacker

if __name__ == '__main__':
    secret = b"&pwd=admin12345"
    prefix = b""
    ssl_v3_client = Client(secret, prefix, 'x923')
    mock_ssl_v3_server = Server(ssl_v3_client)

    # Initial legitimate client-server communication (intercepted by attacker)
    ciphertext, response = ssl_v3_client.create_request_and_send(mock_ssl_v3_server)
    print(f"INFO: {datetime.now()} - Initial Server response: {response}")

    # POODLE attacker holds a reference to the client so it can request
    # fresh encryptions with varying prefix lengths (simulating an attacker
    # that can force repeated requests, e.g. via injected JavaScript).
    poodle_attacker = Attacker(client=ssl_v3_client)

    extracted_secret = poodle_attacker.poodle_attack(
        oracle_func=mock_ssl_v3_server.padding_oracle,
        secret_length=len(secret)
    )
    print(f"\nAttacker extracted : {extracted_secret}")
    print(f"Actual secret      : {secret}")
    print(f"Attack succeeded   : {extracted_secret == secret}")
