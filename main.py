import time
from client import Client
from server import Server
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_server(host, port, next_hop=None):
    server = Server((host, port), next_hop)
    server.run()

if __name__ == "__main__":
    service_type = os.getenv("SERVICE_TYPE", "client")
    
    if service_type == "server1":
        logging.info("Starting Server 1")
        run_server("0.0.0.0", 9001, next_hop=("server2", 9002))
    
    elif service_type == "server2":
        logging.info("Starting Server 2")
        run_server("0.0.0.0", 9002, next_hop=("destination", 9003))
    
    elif service_type == "destination":
        logging.info("Starting Destination Server")
        run_server("0.0.0.0", 9003)
    
    elif service_type == "client":
        time.sleep(5)
        logging.info("Starting Client")
        client = Client(
            [("server1", 9001), ("server2", 9002)],
            ("destination", 9003)
        )
        message = "This is a secret message sent through the onion network."
        client.send_message(message)
        client.receive_response()
    
    else:
        logging.error("Unknown service type")