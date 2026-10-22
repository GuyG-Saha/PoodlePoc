from datetime import datetime

from server import Server
from client import Client
from MITM_attacker import Attacker

if __name__ == '__main__':
    secret = b"&pwd=admin12345"

    client = Client(secret)
    server = Server(client)

    # Initial legitimate client-server exchange (the attacker observes it).
    iv, ciphertext, response = client.create_request_and_send(server)
    print(f"INFO: {datetime.now()} - Initial server response: {response}")

    # The attacker only ever receives the server's accept/reject bit from
    # server.padding_oracle — no decrypted byte is returned anywhere.
    attacker = Attacker(client)
    extracted_secret = attacker.poodle_attack(
        oracle_func=server.padding_oracle,
        secret_length=len(secret),
    )

    print(f"\nAttacker extracted : {extracted_secret}")
    print(f"Actual secret      : {secret}")
    print(f"Attack succeeded   : {extracted_secret == secret}")
