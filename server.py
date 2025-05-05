import socket
import threading
import encryption_module as enc
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Server:
    def __init__(self, address, next_hop=None):
        self.address = address
        self.next_hop = next_hop
        self.private_key, self.public_key = enc.generate_key_pair()

    def handle_client(self, conn, addr):
        try:
            logging.info(f"New connection from {addr}")
            
            request = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                request += chunk
                if request == b'GET_PUBLIC_KEY':
                    break

            logging.info(f"Incoming request: {request}")

            if request == b'GET_PUBLIC_KEY':
                public_key_bytes = self.public_key.x.to_bytes(32, 'big') + self.public_key.y.to_bytes(32, 'big')
                conn.sendall(public_key_bytes)
                logging.info("Sent public key to client")
                return
            
            if len(request) < 64:
                logging.error(f"Invalid client public key length: {len(request)} bytes")
                return
            client_public_key_bytes = request[:64]
            message_package_json = request[64:]
            
            try:
                client_public_key_x = int.from_bytes(client_public_key_bytes[:32], 'big')
                client_public_key_y = int.from_bytes(client_public_key_bytes[32:], 'big')
                client_public_key = enc.Point(client_public_key_x, client_public_key_y)

                session_key = enc.derive_session_key(self.private_key, client_public_key)
                if session_key is None:
                    logging.error("Could not derive session key, discarding")
                    return

                message_package = json.loads(message_package_json.decode('utf-8'))
                onion = message_package['onion'].encode('utf-8')
                signature = tuple(message_package['signature'])

                decrypted_data = enc.decrypt(onion, session_key)

                if self.next_hop is not None:
                    try:
                        payload = json.loads(decrypted_data)
                        routing_info = payload['routing_info']
                        encrypted_message = payload['encrypted_message'].encode('utf-8')

                        try:
                            next_hop_host = routing_info[0]
                            next_hop_port = int(routing_info[1])
                            next_hop = (next_hop_host, next_hop_port)
                        except (IndexError, ValueError, TypeError) as e:
                            logging.error(f"Invalid routing info: {routing_info}. Error: {str(e)}")
                            return

                        try:
                            new_message_package = {
                                "onion": encrypted_message.decode('utf-8'),
                                "signature": list(signature)
                            }
                            new_message_package_json = json.dumps(new_message_package).encode('utf-8')

                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
                                forward_socket.connect(next_hop)
                                forward_socket.sendall(client_public_key_bytes + new_message_package_json)
                                logging.info(f"Forwarded message to {next_hop}")

                        except Exception as e:
                            logging.error(f"Failed to forward to {next_hop}: {str(e)}", exc_info=True)
                    except Exception as e:
                        logging.error(f"Error parsing payload: {str(e)}", exc_info=True)
                else:
                    final_message = decrypted_data
                    logging.info(f"Received final message: {final_message}")

                    try:
                        response = "Message received by destination!"
                        response_encrypted = enc.encrypt(response.encode('utf-8'), session_key)
                        logging.info(f"Encrypted response: {response_encrypted}")
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as response_socket:
                            response_socket.connect(("client", 8000))
                            response_socket.sendall(response_encrypted)
                            logging.info("Sent response to client")
                    except Exception as e:
                        logging.error(f"Failed to send response: {str(e)}", exc_info=True)

            except Exception as e:
                logging.error(f"Error handling client: {str(e)}", exc_info=True)

        except Exception as e:
            logging.error(f"Error: {str(e)}", exc_info=True)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(self.address)
            s.listen()
            logging.info(f"Server listening on {self.address}")
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()
