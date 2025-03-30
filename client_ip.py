import socket
import pickle
import threading

class ChatClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.name = None

    def connect(self):
        """Connect to the server and register the client."""
        try:
            self.client_socket.connect((self.server_host, self.server_port))
            self.name = input("Enter your name: ").strip()
            self.client_socket.sendall(self.name.encode('utf-8'))

            # Receive welcome message and client list
            data = self.client_socket.recv(4096)
            welcome = pickle.loads(data)
            print(f"\n[Server] {welcome['message']}")
            self.print_client_list(welcome['client_list'])

            self.running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()  # Start the receiver thread
            self.send_messages()  # Handle sending messages

        except Exception as e:
            print(f"[ERROR] Failed to connect: {e}")
            self.client_socket.close()
