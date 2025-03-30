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

    def receive_messages(self):
        """Handle incoming messages from the server."""
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                message = pickle.loads(data)
                if message['type'] == 'private_msg':
                    print(f"\n[Private from {message['from']}] {message['message']}")
                elif message['type'] == 'client_list':
                    print("\n[Server] Client list updated:")
                    self.print_client_list(message['data'])
                elif message['type'] == 'error':
                    print(f"\n[Error] {message['message']}")
            except Exception as e:
                print(f"[ERROR] Failed to receive message: {e}")
                break
        print("\n[!] Disconnected from server")
        self.running = False 

# Send a message to a specific peer
def send_message(target_client_id, message):
    if target_client_id not in clients:
        print(f"[ERROR] Target client {target_client_id} not found.")
        return

    target_ip, target_port = clients[target_client_id]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
        target_socket.connect((target_ip, target_port))
        target_socket.send(message.encode("utf-8"))
        print(f"[INFO] Message sent to {target_client_id}")


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
