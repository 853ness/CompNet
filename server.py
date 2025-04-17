import socket
import threading
import time
import pickle
from queue import Queue

clients = {}  # {client_name: {'socket': socket, 'address': tuple, 'queue': Queue}}

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

def broadcast_client_list():
    """Broadcast the updated client list to all clients."""
    client_list = {name: info['address'] for name, info in clients.items()}
    for name, info in clients.copy().items():
        try:
            info['socket'].sendall(pickle.dumps({
                'type': 'client_list',
                'data': client_list
            }))
        except:
            if name in clients:
                del clients[name]

def handle_client(client_socket, address):
    client_name = None
    try:
        client_name = client_socket.recv(1024).decode('utf-8').strip()
        clients[client_name] = {
            'socket': client_socket,
            'address': address,
            'queue': Queue()
        }
        
        client_socket.sendall(pickle.dumps({
            'type': 'welcome',
            'message': f"Welcome {client_name}!",
            'client_list': {name: info['address'] for name, info in clients.items()}
        }))
        broadcast_client_list()
        
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                message = pickle.loads(data)
                if message['type'] == 'private_msg':
                    target = message['target']
                    if target in clients:
                        clients[target]['socket'].sendall(pickle.dumps({
                            'type': 'private_msg',
                            'from': client_name,
                            'message': message['message']
                        }))
                    else:
                        client_socket.sendall(pickle.dumps({
                            'type': 'error',
                            'message': f"Client {target} not found"
                        }))
                elif message['type'] == 'broadcast_msg':
                    # Broadcast the message to all clients
                    for other_name, other_info in clients.items():
                        if other_name != client_name:
                            other_info['socket'].sendall(pickle.dumps({
                                'type': 'broadcast_msg',
                                'from': client_name,
                                'message': message['message']
                            }))
            except:
                break
                
    except Exception as e:
        print(f"Error with {address}: {str(e)}")
    finally:
        if client_name and client_name in clients:
            del clients[client_name]
            broadcast_client_list()
        client_socket.close()

def listen_for_discovery():
    """Listen for UDP discovery requests and respond with the server's IP."""
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', 12345))  # Listen on UDP port 12345
    print("[*] Server is listening for discovery requests on UDP port 12345...")
    
    while True:
        try:
            message, address = udp_socket.recvfrom(1024)
            if message == b'PING':
                print(f"Discovery request from {address}")
                server_ip = get_local_ip()  # Get the server's local IP address
                udp_socket.sendto(server_ip.encode(), address)  # Respond with server IP
        except Exception as e:
            print(f"[ERROR] UDP Error: {e}")

def start_server(host='0.0.0.0', port=65432):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Server started on {host}:{port}")

    threading.Thread(target=listen_for_discovery, daemon=True).start()
    threading.Thread(target=check_file_modifications, daemon=True).start()

    try:
        while True:
            client_socket, address = server.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, address),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
    finally:
        server.close()
if __name__ == "__main__":
    start_server()
