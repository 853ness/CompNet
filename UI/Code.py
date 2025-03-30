# Code.py
import streamlit as st

def code_page():
    st.set_page_config(
        page_title="Code",
        page_icon=":guardsman:",
    )

    st.sidebar.success("Select a page")

    code = '''# Default directory to save files
    save_directory = os.getcwd()

    # cretes a GUI to select the directory to save files
    def select_directory():
        global save_directory
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        save_directory = filedialog.askdirectory()
        if not save_directory:
            save_directory = os.getcwd()  # Default to current directory
        print(f"[DIRECTORY] Files will be saved to: {save_directory}")

    def handle_client(conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        # Receive requested filename
        requested_filename = conn.recv(SIZE).decode(FORMAT)
        print(f"[REQUEST] Peer requested: {requested_filename}")

        if os.path.exists(requested_filename):
            conn.send("FOUND".encode(FORMAT))
            conn.recv(SIZE)  # Acknowledge response

            # Send file size
            file_size = os.path.getsize(requested_filename)
            conn.send(str(file_size).encode(FORMAT))
            conn.recv(SIZE)  # Acknowledge response

            # Send file in chunks
            with open(requested_filename, "rb") as file:
                # Read and send file in chunks
                while chunk := file.read(SIZE):
                    conn.send(chunk)

            print(f"[SENT] {requested_filename} sent successfully.")
        else:
            conn.send("NOT FOUND".encode(FORMAT))

        conn.close()

    # Start the server to listen for incoming connections
    def start_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(ADDR)
        server.listen()
        print(f"[LISTENING] Server running on {IP}:{PORT}")

        while True:
            # Accept incoming connections
            conn, addr = server.accept()
            # Handle each client in a new thread
            threading.Thread(target=handle_client, args=(conn, addr)).start()

    def request_file(target_ip, filename):
        """ Request a file from another peer """
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_ip, PORT))

        # Send filename request
        client.send(filename.encode(FORMAT))
        
        # Receive response
        response = client.recv(SIZE).decode(FORMAT)
        # Check if file is found
        if response == "FOUND":
            client.send("READY".encode(FORMAT))  # Acknowledge

            # Receive file size
            file_size = int(client.recv(SIZE).decode(FORMAT))
            client.send("SIZE RECEIVED".encode(FORMAT))  # Acknowledge

            # Receive file in chunks
            file_path = os.path.join(save_directory, filename)
            # Open file for writing
            with open(file_path, "wb") as file:
                received_size = 0
                # Read and write file in chunks
                while received_size < file_size:
                    chunk = client.recv(SIZE)
                    if not chunk:
                        break
                    file.write(chunk)
                    received_size += len(chunk)

            print(f"[RECEIVED] {filename} received successfully in {save_directory}.")
        else:
            print(f"[ERROR] {filename} not found on {target_ip}.")

        client.close()

    if __name__ == "__main__":
        # Start the server in a separate thread
        threading.Thread(target=start_server, daemon=True).start()
        
        # Select directory for received files
        select_directory()

        while True:
            action = input("\nEnter 'send' to request a file or 'exit' to quit: ").strip().lower()
            
            if action == "send":
                target_peer = input("Enter the target peer's IP: ").strip()
                filename = input("Enter the filename to request: ").strip()
                request_file(target_peer, filename)
            elif action == "exit":
                print("Exiting...")
                break
    '''

    st.title("Code Display in Streamlit")
    st.write("Below is the Python code displayed using Streamlit:")

    st.code(code, language="python")
