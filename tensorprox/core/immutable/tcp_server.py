import socket
import threading
import logging
import signal
import time

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
stop_event = threading.Event()  # Global event to signal thread shutdown

KING_OVERLAY_IP = "10.0.0.1"

def handle_client(client_socket, client_address):
    """Handle an individual client connection."""
    logging.info(f"Connection established with {client_address}")
    client_socket.settimeout(60)  # Set client socket timeout to 60 seconds
    try:
        while True:
            data = client_socket.recv(1500)
            if not data:
                logging.info(f"No data received. Closing connection with {client_address}")
                break

            logging.debug(f"Data received from {client_address}: {data}")
            
            # Process all traffic the same way without checking for BENIGN-TCP-
            logging.info(f"Processing traffic from {client_address}")
            client_socket.sendall(b"ACK: Traffic processed.\n")
            
    except socket.timeout:
        logging.warning(f"Client connection with {client_address} timed out.")
    except ConnectionResetError:
        logging.warning(f"Connection reset by {client_address}")
    except Exception as e:
        logging.error(f"Error handling client {client_address}: {e}")
    finally:
        logging.info(f"Closing connection with {client_address}")
        client_socket.close()


def start_server(port):
    """Start a server on a specific port."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((KING_OVERLAY_IP, port))
        server.listen(100)  # Increased backlog
        logging.info(f"Listening on {KING_OVERLAY_IP}:{port}")
        server.settimeout(1.0)  # Set timeout outside the loop
        while not stop_event.is_set():
            try:
                client_socket, client_address = server.accept()
                threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
            except socket.timeout:
                continue
            except OSError as e:
                logging.error(f"Error accepting connections: {e}")
    except OSError as e:
        logging.warning(f"Port {port} unavailable: {e}")
    except Exception as e:
        logging.error(f"Error in server on port {port}: {e}")
    finally:
        logging.info(f"Server on port {port} shut down.")
        server.close()


def tcp_server(target_ports=[80, 443, 21, 3306, 53, 8080, 8443, 2121, 2022, 5432, 5353]):
    """Main TCP server dynamically checking specified target ports."""
    available_ports = []

    # Check availability of target ports
    logging.info(f"Checking availability of target ports: {target_ports}")
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((KING_OVERLAY_IP, port))  # If successful, the port is free
                available_ports.append(port)
        except OSError:
            logging.warning(f"Port {port} is in use or unavailable on {KING_OVERLAY_IP}.")

    if not available_ports:
        logging.error("No available target ports. Exiting.")
        return

    # Start servers on available ports
    logging.info(f"Available ports: {available_ports}")
    for port in available_ports:
        threading.Thread(target=start_server, args=(port,), daemon=True).start()

    # Keep the main thread alive and handle graceful shutdown
    def shutdown_handler(signum, frame):
        logging.info("Shutting down the server...")
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        logging.info("TCP server is running. Press Ctrl+C to stop.")
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown_handler(None, None)
    finally:
        logging.info("All servers have been shut down.")

if __name__ == "__main__":
    tcp_server()