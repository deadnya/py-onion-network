import socket
import encryption_module as enc
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Client:
    def __init__(self, server_addresses, destination_address):
        self.server_addresses = server_addresses
        self.destination_address = destination_address
        self.client_private_key, self.client_public_key = enc.generate_key_pair()
        self.server_public_keys = {}
        self.session_keys = {}
        self.listening_port = 8000

    def get_server_public_keys(self):
        logging.info("Requesting public keys from servers...")

        for addr in self.server_addresses:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(addr)
                s.sendall(b'GET_PUBLIC_KEY')
                public_key_bytes = s.recv(4096)
                if not public_key_bytes:
                    raise ConnectionError(f"Failed to retrieve public key from {addr}")

                public_key_x = int.from_bytes(public_key_bytes[:32], 'big')
                public_key_y = int.from_bytes(public_key_bytes[32:], 'big')
                public_key = enc.Point(public_key_x, public_key_y)

                self.server_public_keys[addr] = public_key
                logging.info(f"Received public key from {addr}: {public_key}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(self.destination_address)
            s.sendall(b'GET_PUBLIC_KEY')
            public_key_bytes = s.recv(4096)
            if not public_key_bytes:
                raise ConnectionError(f"Failed to retrieve public key from {self.destination_address}")

            public_key_x = int.from_bytes(public_key_bytes[:32], 'big')
            public_key_y = int.from_bytes(public_key_bytes[32:], 'big')
            public_key = enc.Point(public_key_x, public_key_y)

            self.server_public_keys[self.destination_address] = public_key
            logging.info(f"Received public key from {self.destination_address}: {public_key}")

    def build_onion(self, message):
        onion = message.encode('utf-8')
        routing_info = {}

        session_key = enc.derive_session_key(self.client_private_key, self.server_public_keys[self.destination_address])
        logging.info(f"Destination session key: {session_key}")

        if session_key is None:
            raise ValueError("Could not derive session key for destination")
        self.session_keys[self.destination_address] = session_key

        logging.info(f"Original onion payload: {onion}")
        onion = enc.encrypt(onion, session_key)
        logging.info(f"Encrypted payload: {onion}")

        routing_info[self.destination_address] = "FINAL_DESTINATION"

        for addr in reversed(self.server_addresses):
            session_key = enc.derive_session_key(self.client_private_key, self.server_public_keys[addr])
            logging.info(f"Server {addr} session key: {session_key}")

            if session_key is None:
                raise ValueError("Could not derive session key")

            if addr == self.server_addresses[-1]:
                routing_info[addr] = self.destination_address
            else:
                routing_info[addr] = self.server_addresses[self.server_addresses.index(addr)+1]

            payload = {
                "routing_info": routing_info[addr],
                "encrypted_message": onion.decode('utf-8')
            }
            
            logging.info(f"Original onion payload: {payload}")
            payload_json = json.dumps(payload).encode('utf-8')
            onion = enc.encrypt(payload_json, session_key)
            logging.info(f"Encrypted payload: {onion}")


        return onion, routing_info

    def send_message(self, message):
        try:
            self.get_server_public_keys()
            onion, routing_info = self.build_onion(message)
            signature = enc.sign(message, self.client_private_key)

            message_package = {
                "onion": onion.decode('utf-8'),
                "signature": signature
            }
            message_package_json = json.dumps(message_package).encode('utf-8')

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(self.server_addresses[0])
                public_key_bytes = self.client_public_key.x.to_bytes(32, 'big') + self.client_public_key.y.to_bytes(32, 'big')
                
                sock.sendall(public_key_bytes + message_package_json)
                logging.info("Full payload sent successfully")

        except Exception as e:
            logging.error(f"Error sending message: {str(e)}", exc_info=True)



    def receive_response(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', self.listening_port))
        sock.listen(1)
        logging.info("Listening for response...")

        conn, addr = sock.accept()
        with conn:
            logging.info(f"Connected by: {addr}")
            encrypted_response = conn.recv(4096)
            if not encrypted_response:
                logging.info("No response received.")
                return

            response = enc.decrypt(encrypted_response, self.session_keys[self.destination_address])
            logging.info(f"Received response: {response}")
        sock.close()
