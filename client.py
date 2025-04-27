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
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File-Transfer Client")
        
        # Server connection info
        self.server_ip = None
        self.server_port = 65432
        self.client_socket = None
        
        # Client info
        self.name = None
        self.clients = {}
        self.shared_files = {}  # Dictionary to store shared files {client_name: [file_list]}
        self.running = True
        self.file_transfer_port = 65433
        self.file_receiver = None
        self.download_dir = os.path.join(os.getcwd(), "received_files")
        self.shared_files_list = []  # Tracks files shared by this client
        
        # Create default download directory if it doesn't exist
        os.makedirs(self.download_dir, exist_ok=True)
        
        # Setup GUI
        self.setup_gui()
        
        # Start connection process
        self.connect_to_server()

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

    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def discover_server(self):
        """Discover server using UDP broadcast"""
        self.update_status("Discovering server...")
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.settimeout(3)
        
        try:
            udp_socket.sendto(b'PING', ('<broadcast>', 12345))
            data, addr = udp_socket.recvfrom(1024)
            self.server_ip = data.decode()
            self.update_status(f"Discovered server at {self.server_ip}")
            return True
        except socket.timeout:
            self.update_status("Server discovery timed out")
            return False
        finally:
            udp_socket.close()

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

    def receive_messages(self):
        """Listen for messages from the server"""
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                    
                message = pickle.loads(data)
                
                if message['type'] == 'welcome':
                    self.display_message(f"Server: {message['message']}")
                    self.clients = message['client_list']
                    self.shared_files = message['shared_files']
                    self.update_client_list()
                    self.update_shared_files_list()
                
                elif message['type'] == 'client_list':
                    self.clients = message['data']
                    self.update_client_list()
                
                elif message['type'] == 'shared_files_update':
                    self.shared_files = message['data']
                    self.update_shared_files_list()
                
                elif message['type'] == 'private_msg':
                    self.display_message(f"[Private from {message['from']}]: {message['message']}")
                
                elif message['type'] == 'broadcast_msg':
                    self.display_message(f"[Broadcast from {message['from']}]: {message['message']}")
                
                elif message['type'] == 'file_changed':
                    self.display_message(
                        f"\nFile update: {message['client']}'s {message['file']} "
                        f"(v{message['new_version']}, {self.format_file_size(message['new_size'])})"
                    )
                
                elif message['type'] == 'error':
                    self.display_message(f"[Error]: {message['message']}")
                
            except (ConnectionResetError, pickle.PickleError):
                break
            except Exception as e:
                self.display_message(f"\nError receiving message: {e}")
                break
        
        self.display_message("\nDisconnected from server")
        self.update_status("Disconnected")
        self.running = False

    def monitor_shared_files(self):
        """Monitor shared files for changes and update server"""
        while self.running:
            for i, (file_path, file_name, last_size, last_mtime) in enumerate(self.shared_files_list.copy()):
                try:
                    if not os.path.exists(file_path):
                        self.unshare_file(file_name)
                        continue
                        
                    current_size = os.path.getsize(file_path)
                    current_mtime = os.path.getmtime(file_path)
                    
                    if current_mtime != last_mtime:
                        file_hash = self.calculate_file_hash(file_path)
                        self.client_socket.sendall(pickle.dumps({
                            'type': 'share_file',
                            'file_name': file_name,
                            'file_size': current_size,
                            'file_mtime': current_mtime,
                            'file_hash': file_hash
                        }))
                        self.shared_files_list[i] = (file_path, file_name, current_size, current_mtime)
                        self.display_message(f"\nUpdated shared file '{file_name}' (modified)")
                except Exception as e:
                    self.display_message(f"\nError monitoring file {file_name}: {e}")
            time.sleep(10)

    def update_client_list(self):
        """Update the client list treeview"""
        self.client_tree.delete(*self.client_tree.get_children())
        for name, data in self.clients.items():
            self.client_tree.insert('', 'end', text=name, values=(data[0],))

    def update_shared_files_list(self):
        """Update the shared files treeview"""
        self.files_tree.delete(*self.files_tree.get_children())
        for client_name, files in self.shared_files.items():
            if files:
                parent = self.files_tree.insert('', 'end', text=client_name, open=True)
                for file_info in files:
                    if len(file_info) >= 5:  # Check if version info exists
                        file_name, file_size, _, _, version = file_info
                        self.files_tree.insert(parent, 'end', text=file_name, 
                                             values=(self.format_file_size(file_size), version))
                    else:
                        # Fallback for old format
                        file_name, file_size = file_info
                        self.files_tree.insert(parent, 'end', text=file_name, 
                                             values=(self.format_file_size(file_size), "1"))

    def format_file_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def display_message(self, message):
        """Display a message in the chat display"""
        self.chat_display.config(state='normal')
        self.chat_display.insert('end', message + '\n')
        self.chat_display.config(state='disabled')
        self.chat_display.see('end')

    def send_message(self, event=None):
        """Send a message to the selected client or broadcast"""
        message = self.msg_entry.get()
        if not message:
            return
            
        selected = self.client_tree.focus()
        if selected:
            target_name = self.client_tree.item(selected)['text']
            try:
                self.client_socket.sendall(pickle.dumps({
                    'type': 'private_msg',
                    'target': target_name,
                    'message': message
                }))
                self.display_message(f"[You to {target_name}]: {message}")
            except Exception as e:
                self.display_message(f"Error sending message: {e}")
        else:
            try:
                self.client_socket.sendall(pickle.dumps({
                    'type': 'broadcast_msg',
                    'message': message
                }))
                self.display_message(f"[You to everyone]: {message}")
            except Exception as e:
                self.display_message(f"Error sending broadcast: {e}")
        
        self.msg_entry.delete(0, 'end')

    def start_file_receiver(self):
        """Start a thread to listen for incoming file transfers"""
        if self.file_receiver is None:
            self.file_receiver = threading.Thread(target=self.listen_for_files, daemon=True)
            self.file_receiver.start()

    def listen_for_files(self):
        """Listen for incoming file transfer connections"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.file_transfer_port))
            s.listen()
            
            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_incoming_file, args=(conn,), daemon=True).start()
                except:
                    break

    def handle_incoming_file(self, conn):
        try:
            # 1) Read the requested filename
            requested = conn.recv(1024).decode()
            if not requested:
                return

            # 2) Find the full path in our shared_files_list
            match = next(
                (fullpath for (fullpath, name, _, _) in self.shared_files_list
                 if name == requested),
                None
            )
            if match is None or not os.path.exists(match):
                conn.sendall("ERROR|File not found".encode())
                return

            # 3) Send back metadata and then the bytes
            file_size = os.path.getsize(match)
            conn.sendall(f"{requested}|{file_size}".encode())

            with open(match, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    conn.sendall(chunk)

        except Exception as e:
            self.display_message(f"\nError sending file: {e}")
        finally:
            conn.close()



    def browse_share_file(self):
        """Open file dialog to select file to share"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.share_file_path.set(file_path)

    def share_file_with_server(self):
        """Share a file with the server to make it available to other clients"""
        file_path = self.share_file_path.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file first")
            return
        
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_mtime = os.path.getmtime(file_path)
            file_hash = self.calculate_file_hash(file_path)
            
            self.shared_files_list.append((file_path, file_name, file_size, file_mtime))
            
            self.client_socket.sendall(pickle.dumps({
                'type': 'share_file',
                'file_name': file_name,
                'file_size': file_size,
                'file_mtime': file_mtime,
                'file_hash': file_hash
            }))
            
            self.display_message(f"\nShared file '{file_name}' with the server")
            self.share_file_path.set("")
            
        except Exception as e:
            self.display_message(f"\nError sharing file: {e}")

    def unshare_file(self, file_name=None):
        """Unshare a previously shared file"""
        if file_name is None:
            selected = self.files_tree.focus()
            if not selected:
                messagebox.showerror("Error", "Please select a file to unshare")
                return
            
            item = self.files_tree.item(selected)
            parent = self.files_tree.parent(selected)
            if parent:  # This is a file item
                client_name = self.files_tree.item(parent)['text']
                file_name = item['text']
                
                if client_name != self.name:
                    messagebox.showerror("Error", "You can only unshare your own files")
                    return
        
        # Remove from local tracking
        self.shared_files_list = [
            f for f in self.shared_files_list 
            if f[1] != file_name
        ]
        
        try:
            self.client_socket.sendall(pickle.dumps({
                'type': 'unshare_file',
                'file_name': file_name
            }))
            self.display_message(f"\nUnshared file '{file_name}'")
        except Exception as e:
            self.display_message(f"\nError unsharing file: {e}")

    def download_file(self):
        """Download a selected shared file from another client"""
        selected = self.files_tree.focus()
        if not selected:
            messagebox.showerror("Error", "Please select a file to download")
            return

        item = self.files_tree.item(selected)
        parent = self.files_tree.parent(selected)
        if not parent:  # This is a client item, not a file
            messagebox.showerror("Error", "Please select a file to download")
            return

        client_name = self.files_tree.item(parent)['text']
        file_name = item['text']

        if client_name == self.name:
            messagebox.showerror("Error", "You can't download your own shared file")
            return

        if client_name not in self.clients:
            messagebox.showerror("Error", "Client not available for download")
            return

        client_ip, client_port = self.clients[client_name]

        try:
            # Connect to the client for P2P file transfer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((client_ip, client_port))
                s.sendall(f"{file_name}".encode())

                # Receive file metadata
                file_info = s.recv(1024).decode()
                if file_info.startswith("ERROR"):
                    self.display_message(f"\n{file_info}")
                    return

                # Validate and split metadata
                if '|' not in file_info:
                    self.display_message(f"\nInvalid file metadata: {file_info}")
                    return

                file_name, file_size_str = file_info.split('|', 1)
                file_size = int(file_size_str)
                file_name = os.path.basename(file_name)

                # Prepare to save the file
                save_path = os.path.join(self.download_dir, file_name)
                counter = 1
                base, ext = os.path.splitext(file_name)
                while os.path.exists(save_path):
                    save_path = os.path.join(self.download_dir, f"{base}_{counter}{ext}")
                    counter += 1

                self.display_message(f"\nDownloading file '{file_name}' ({file_size} bytes)...")

                # Receive file data
                received = 0
                with open(save_path, 'wb') as f:
                    while received < file_size:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)

                self.display_message(f"File saved to: {save_path}")

        except Exception as e:
            self.display_message(f"\nError downloading file: {e}")


    def change_download_dir(self):
        """Change the download directory"""
        new_dir = filedialog.askdirectory()
        if new_dir:
            self.download_dir = new_dir
            self.dir_path.set(new_dir)
            messagebox.showinfo("Success", f"Download directory changed to:\n{new_dir}")

    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update()

    def cleanup(self):
        """Clean up before exiting"""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.sendall(pickle.dumps({'type': 'disconnect'}))
                self.client_socket.close()
            except:
                pass
        self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    app = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", app.cleanup)
    root.mainloop()