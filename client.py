import socket
import threading
import pickle
import os
import hashlib
import time
from tkinter import *
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
import tkinter.ttk as ttk

class ChatClient:
    def __init__(self, server_host, server_port, download_dir):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.name = None
        self.download_dir = download_dir  # Directory for storing received files
        self.client_list = {}  # Store connected clients list
    
    def setup_gui(self):
        """Set up the Tkinter GUI"""
        # Main frames
        self.main_frame = Frame(self.root)
        self.main_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        
        # Left panel with notebook for clients and files
        self.left_panel = Frame(self.main_frame)
        self.left_panel.pack(side=LEFT, fill=Y, padx=5, pady=5)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.left_panel)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Clients tab
        self.client_tab = Frame(self.notebook)
        self.notebook.add(self.client_tab, text="Clients")
        
        self.client_tree = ttk.Treeview(self.client_tab, columns=('ip',), show='tree headings')
        self.client_tree.heading('#0', text='Name')
        self.client_tree.heading('ip', text='IP Address')
        self.client_tree.column('ip', width=100, anchor='w')
        self.client_tree.pack(fill=BOTH, expand=True)
        
        # Files tab
        self.files_tab = Frame(self.notebook)
        self.notebook.add(self.files_tab, text="Shared Files")
        
        self.files_tree = ttk.Treeview(self.files_tab, columns=('size', 'version'), show='tree headings')
        self.files_tree.heading('#0', text='File')
        self.files_tree.heading('size', text='Size')
        self.files_tree.heading('version', text='Version')
        self.files_tree.column('size', width=80, anchor='e')
        self.files_tree.column('version', width=60, anchor='center')
        self.files_tree.pack(fill=BOTH, expand=True)
        
        # Chat display
        self.chat_frame = LabelFrame(self.main_frame, text="Chat")
        self.chat_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled')
        self.chat_display.pack(fill=BOTH, expand=True)
        
        # Message entry
        self.msg_frame = Frame(self.chat_frame)
        self.msg_frame.pack(fill=X, pady=5)
        
        self.msg_entry = Entry(self.msg_frame)
        self.msg_entry.pack(side=LEFT, fill=X, expand=True)
        self.msg_entry.bind('<Return>', self.send_message)
        
        self.send_btn = ttk.Button(self.msg_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=LEFT, padx=5)
        
        # File sharing controls
        self.file_share_frame = LabelFrame(self.root, text="File Sharing")
        self.file_share_frame.pack(fill=X, padx=10, pady=5)
        
        self.share_file_path = StringVar()
        self.share_file_entry = Entry(self.file_share_frame, textvariable=self.share_file_path, state='readonly')
        self.share_file_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        
        self.browse_share_btn = ttk.Button(self.file_share_frame, text="Browse", command=self.browse_share_file)
        self.browse_share_btn.pack(side=LEFT, padx=5)
        
        self.share_btn = ttk.Button(self.file_share_frame, text="Share File", command=self.share_file_with_server)
        self.share_btn.pack(side=LEFT, padx=5)
        
        self.unshare_btn = ttk.Button(self.file_share_frame, text="Unshare Selected", command=self.unshare_file)
        self.unshare_btn.pack(side=LEFT, padx=5)
        
        # File transfer controls
        self.file_transfer_frame = LabelFrame(self.root, text="File Transfer")
        self.file_transfer_frame.pack(fill=X, padx=10, pady=5)
        
        self.download_btn = ttk.Button(self.file_transfer_frame, text="Download Selected", command=self.download_file)
        self.download_btn.pack(side=LEFT, padx=5)
        
        # Download directory controls
        self.dir_frame = LabelFrame(self.root, text="Download Directory")
        self.dir_frame.pack(fill=X, padx=10, pady=5)
        
        self.dir_path = StringVar(value=self.download_dir)
        self.dir_entry = Entry(self.dir_frame, textvariable=self.dir_path, state='readonly')
        self.dir_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        
        self.change_dir_btn = ttk.Button(self.dir_frame, text="Change", command=self.change_download_dir)
        self.change_dir_btn.pack(side=LEFT, padx=5)
        
        # Status bar
        self.status_var = StringVar(value="Disconnected")
        self.status_bar = Label(self.root, textvariable=self.status_var, bd=1, relief=SUNKEN, anchor=W)
        self.status_bar.pack(fill=X, padx=10, pady=5)
        
        # Menu
        self.menu_bar = Menu(self.root)
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.cleanup)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.root.config(menu=self.menu_bar)


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
