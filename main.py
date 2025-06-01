from datetime import datetime
from server import Server

from client import Client

from MITM_attacker import Attacker

if __name__ == '__main__':
    secret = b"sessionid=secretvalue12345"
    prefix = b"param1=value1&param2=value2&"
    ssl_v3_client = Client(secret, prefix)
    mock_ssl_v3_server = Server(ssl_v3_client)

    # Normal communication
    ciphertext, response = ssl_v3_client.create_request_and_send(mock_ssl_v3_server)
    print(f"INFO: {datetime.now()} - Server response: {response}")
    poodle_attacker = Attacker(client_iv=ssl_v3_client.IV, ciphertext=ciphertext)

    extracted_secret = poodle_attacker.poodle_attack(
        ciphertext,
        ssl_v3_client.IV,
        mock_ssl_v3_server.padding_oracle  # Attacker uses server as oracle
    )
    print(f"Attacker extracted: {extracted_secret}")

