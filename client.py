import socket
import pickle
import threading
import os

class ChatClient:
    def __init__(self, server_host, server_port, download_dir):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.name = None
        self.download_dir = download_dir  # Directory for storing received files
        self.client_list = {}  # Store connected clients list

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
            self.client_list = welcome['client_list']  # Store client list
            self.print_client_list(self.client_list)

            self.running = True
            threading.Thread(target=self.receive_messages, daemon=True).start()  # Start the receiver thread
            self.send_messages()  # Handle sending messages

        except Exception as e:
            print(f"[ERROR] Failed to connect: {e}")
            self.client_socket.close()

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
                    self.client_list = message['data']
                    self.print_client_list(self.client_list)
                elif message['type'] == 'error':
                    print(f"\n[Error] {message['message']}")
            except Exception as e:
                print(f"[ERROR] Failed to receive message: {e}")
                break
        print("\n[!] Disconnected from server")
        self.running = False

    def send_messages(self):
        """Allow the user to send messages to the server or other clients."""
        while self.running:
            try:
                cmd = input("\nEnter command:\n1. List clients\n2. Send private message\n3. Send file\n4. Exit\n5. Change download directory\n> ").strip()

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
                    target = input("Enter recipient name for file: ").strip()
                    if target in self.client_list:
                        target_ip = self.client_list[target]
                        file_path = input("Enter file path to send: ").strip()
                        self.send_file(target_ip, file_path)
                    else:
                        print(f"[ERROR] Client {target} not found.")
                elif cmd == '4':
                    self.running = False
                    self.client_socket.sendall(pickle.dumps({'type': 'exit'}))  # Optional server exit message
                    break
                elif cmd == '5':
                    self.change_download_dir()
                else:
                    print("[ERROR] Invalid command. Please try again.")
            except Exception as e:
                print(f"[ERROR] Failed to send message: {e}")
                break

        self.client_socket.close()

    def send_file(self, target_ip, file_path):
        """Send a file to the specified recipient."""
        try:
            if not os.path.isfile(file_path):
                print("[ERROR] The specified file does not exist.")
                return

            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            print(f"Sending file: {file_name} ({file_size} bytes) to {target_ip}")

            if isinstance(target_ip, tuple):
                target_ip = target_ip[0]

            file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_socket.connect((target_ip, self.server_port))

            metadata = {'type': 'file', 'file_name': file_name, 'file_size': file_size}
            file_socket.sendall(pickle.dumps(metadata))

            with open(file_path, 'rb') as file:
                while (chunk := file.read(4096)):
                    file_socket.sendall(chunk)

            print(f"File {file_name} sent successfully.")
            file_socket.close()
        except Exception as e:
            print(f"[ERROR] Failed to send file: {e}")

    def print_client_list(self, client_list):
        """Print the list of connected clients."""
        print("\n=== Active Clients ===")
        for name, address in client_list.items():
            ip_address = address[0] if isinstance(address, tuple) else address
            print(f"- {name} ({ip_address})")
        print("======================")

    def change_download_dir(self):
        """Change the download directory."""
        new_dir = input("Enter the new directory to save received files: ").strip()
        
        if os.path.isdir(new_dir):
            self.download_dir = new_dir
            print(f"[INFO] Download directory changed to: {self.download_dir}")
        else:
            print("[ERROR] Invalid directory. Please enter a valid path.")


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



def discover_server():
    """Discover the server IP using UDP broadcast."""
    broadcast_ip = "<broadcast>"
    broadcast_port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.settimeout(5)
        udp_socket.sendto(b'PING', (broadcast_ip, broadcast_port))
        try:
            server_ip, _ = udp_socket.recvfrom(1024)
            return server_ip.decode()
        except socket.timeout:
            print("[ERROR] No response from server. Ensure the server is running.")
            return None

if __name__ == "__main__":
    download_dir = input("Enter the directory to save received files: ").strip()

    if not os.path.isdir(download_dir):
        print("[ERROR] Invalid directory. Exiting.")
        exit(1)

    server_ip = discover_server()
    if server_ip:
        server_port = 65432
        client = ChatClient(server_ip, server_port, download_dir)
        client.connect()

    def connect_to_server(self):
        """Connect to the chat server"""
        if not self.server_ip and not self.discover_server():
            self.server_ip = simpledialog.askstring("Server IP", "Enter server IP manually:")
            if not self.server_ip:
                return False

        self.name = simpledialog.askstring("Your Name", "Enter your name:")
        if not self.name:
            return False

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            self.client_socket.sendall(pickle.dumps({
                'type': 'connect',
                'name': self.name,
                'port': self.file_transfer_port
            }))

            # Start listening for messages from server
            threading.Thread(target=self.receive_messages, daemon=True).start()

            # Start file receiver in background
            self.start_file_receiver()

            # Start file monitoring thread
            threading.Thread(target=self.monitor_shared_files, daemon=True).start()

            self.update_status(f"Connected as {self.name}")
            return True
        except Exception as e:
            self.update_status(f"Failed to connect: {e}")
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            return False
