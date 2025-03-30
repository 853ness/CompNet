import socket
import pickle
import threading
import time


# Discover the server dynamically via UDP broadcast
def discover_server():
    broadcast_ip = "<broadcast>"
    broadcast_port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.settimeout(5)  # Timeout for receiving response
        udp_socket.sendto(b'PING', (broadcast_ip, broadcast_port))  # Send PING message
        try:
            server_ip, _ = udp_socket.recvfrom(1024)  # Receive server IP
            return server_ip.decode()
        except socket.timeout:
            print("[ERROR] No response from server. Ensure the server is running.")
            return None

# Dynamically obtain server IP address using broadcast discovery
SERVER_HOST = discover_server()
if SERVER_HOST is None:
    print("Could not discover server. Exiting.")
    exit()

SERVER_PORT = 65432  # Server port for registration

client_id = None
clients = {}

# Dynamically generate client_id based on user input
client_id = input("Enter your custom client ID (string): ")

# Receive messages from other peers
def receive_messages():
    while True:
        try:
            with socket.socket() as listener:
                listener.bind(('0.0.0.0', 0))
                listener.listen(5)
                
                while True:
                    conn, addr = listener.accept()
                    with conn:
                        try:
                            # First get message length
                            length_bytes = conn.recv(4)
                            if not length_bytes:
                                continue
                            length = int.from_bytes(length_bytes, 'big')
                            
                            # Then receive data
                            data = b''
                            while len(data) < length:
                                packet = conn.recv(length - len(data))
                                if not packet:
                                    raise ConnectionError("Incomplete data")
                                data += packet
                            
                            # Deserialize
                            message = pickle.loads(data)
                            if message.get("type") == "ack":
                                print("Connection acknowledged")
                            # ... handle other message types ...
                            
                        except pickle.PickleError:
                            print("Received invalid data - protocol mismatch")
                        except ConnectionResetError:
                            print("Peer disconnected abruptly")

        except Exception as e:
            print(f"Receiver error: {str(e)}")
            time.sleep(5)


def send_messages(self):
        """Allow the user to send messages to the server or other clients."""
        while self.running:
            try:
                cmd = input("\nEnter command:\n1. List clients\n2. Send private message\n3. Exit\n> ").strip()

                if cmd == '1':
                    self.client_socket.sendall(pickle.dumps({'type': 'get_clients'}))
                elif cmd == '2':
                    target = input("Enter recipient name: ").strip()
                    message = input("Enter message: ").strip()
                    self.client_socket.sendall(pickle.dumps({
                        'type': 'private_msg',
                        'target': target,
                        'message': message
                    }))
                elif cmd == '3':
                    self.running = False
                    self.client_socket.sendall(pickle.dumps({'type': 'exit'}))  # Optional server exit message
                    break
                else:
                    print("[ERROR] Invalid command. Please try again.")
            except Exception as e:
                print(f"[ERROR] Failed to send message: {e}")
                break

        self.client_socket.close()

def start_client():
    global client_id

    # Start receiving messages in a separate thread
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.daemon = True  # Daemonize the thread so it exits with the main program
    receive_thread.start()

    # Start sending messages
    while True:
        print("\nAvailable clients:")
        for c_id in clients:
            print(f"- {c_id}")

        target_client_id = input("Enter the client ID to send a message to (or 'exit' to quit): ")
        if target_client_id == 'exit':
            print("[INFO] Exiting client...")
            break
        
        message = input("Enter your message: ")
        send_message(target_client_id, message)

    # Ensure the client shuts down gracefully
    # Close all resources and connections
    print("[INFO] Closing client...")
    time.sleep(1)  # Allow any pending messages to be processed before exiting


if __name__ == "__main__":
    start_client()
