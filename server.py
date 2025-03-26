import socket
import pickle
import threading
import os
import time

def get_local_ip():
    """Get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Connect to a known server to get the local IP
        return s.getsockname()[0]  # Return the local IP address
    except Exception as e:
        return "127.0.0.1"  # Fallback to localhost
    finally:
        s.close()

SERVER_HOST = get_local_ip()  # Dynamically get local IP
SERVER_PORT = 65432  # Server port for client connections
BROADCAST_PORT = 12345  # UDP port for server discovery

clients = {}  # Dictionary to store client information (client_id: (client_ip, client_port))

# Handle incoming client connection
def handle_client(client_socket, addr):
    try:
        # First receive client ID
        client_id = client_socket.recv(1024).decode().strip()
        
        # Send ACK as proper pickled message
        ack_message = pickle.dumps({"type": "ack", "status": "ok"})
        client_socket.sendall(ack_message)
        
        # Handle further communication
        while True:
            try:
                # First get message length (4 bytes)
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break
                length = int.from_bytes(length_bytes, 'big')
                
                # Then receive the actual data
                data = b''
                while len(data) < length:
                    packet = client_socket.recv(length - len(data))
                    if not packet:
                        raise ConnectionError("Incomplete data")
                    data += packet
                
                # Process the message
                message = pickle.loads(data)
                # ... handle message ...

            except (pickle.PickleError, ConnectionError) as e:
                print(f"Error with {client_id}: {str(e)}")
                break

    except Exception as e:
        print(f"Client handler error: {str(e)}")
    finally:
        client_socket.close()

def broadcast_peer_left(client_id):
    """Notify all clients about a peer departure"""
    message = pickle.dumps({
        'type': 'peer_left',
        'data': client_id
    })
    for peer_id, peer_info in list(clients.items()):
        try:
            with socket.socket() as s:
                s.connect((peer_info['ip'], peer_info['port']))
                s.sendall(message)
        except:
            # Remove unreachable peers
            if peer_id in clients:
                del clients[peer_id]

# Server setup to listen for incoming client connections and UDP broadcast
def start_server():
    try:
        # Create a UDP socket to listen for broadcast messages
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp_socket.bind(('', BROADCAST_PORT))  # Bind to the broadcast port

            print(f"[INFO] Listening for UDP broadcast messages on port {BROADCAST_PORT}...")

            # Start the server to handle TCP client connections
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((SERVER_HOST, SERVER_PORT))
                server_socket.listen(5)
                print(f"[INFO] Server listening on {SERVER_HOST}:{SERVER_PORT}...")

                # Respond to broadcast requests with the server's IP
                while True:
                    message, addr = udp_socket.recvfrom(1024)
                    if message == b'PING':
                        udp_socket.sendto(SERVER_HOST.encode(), addr)
                        print(f"[INFO] Responded to {addr} with IP: {SERVER_HOST}")

                    client_socket, client_address = server_socket.accept()
                    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                    client_thread.start()

    except Exception as e:
        print(f"[ERROR] Server failed to start: {e}")

if __name__ == "__main__":
    start_server()
