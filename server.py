import socket
import threading
import pickle
import time
import hashlib
import os
from queue import Queue
from datetime import datetime

# Global variables
clients = {}  # {client_name: {'socket': socket, 'address': tuple, 'queue': Queue}}
shared_files = {}  # {client_name: [(file_name, file_size, last_modified, file_hash, version)]}
file_history = {}  # {client_name: {file_name: [(version, size, mtime, hash)]}}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def broadcast_client_list():
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

def broadcast_shared_files():
    for name, info in clients.copy().items():
        try:
            info['socket'].sendall(pickle.dumps({
                'type': 'shared_files_update',
                'data': shared_files
            }))
        except:
            if name in clients:
                del clients[name]

def check_file_modifications():
    while True:
        time.sleep(60)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}] Checking file modifications...")
        
        for client_name, files in shared_files.copy().items():
            if client_name not in clients:
                continue
                
            for file_info in files:
                file_name = file_info[0]
                try:
                    clients[client_name]['socket'].sendall(pickle.dumps({
                        'type': 'verify_file',
                        'file_name': file_name
                    }))
                except:
                    if client_name in shared_files:
                        del shared_files[client_name]
                    break

def handle_client(client_socket, address):
    client_name = None
    try:
        data = client_socket.recv(1024)
        if not data:
            return
            
        connection_data = pickle.loads(data)
        client_name = connection_data['name']
        client_port = connection_data.get('port', address[1])
        
        clients[client_name] = {
            'socket': client_socket,
            'address': (address[0], client_port),
            'queue': Queue()
        }
        
        client_socket.sendall(pickle.dumps({
            'type': 'welcome',
            'message': f"Welcome {client_name}!",
            'client_list': {name: info['address'] for name, info in clients.items()},
            'shared_files': shared_files
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
                    for other_name, other_info in clients.items():
                        if other_name != client_name:
                            other_info['socket'].sendall(pickle.dumps({
                                'type': 'broadcast_msg',
                                'from': client_name,
                                'message': message['message']
                            }))
                
                elif message['type'] == 'share_file':
                    try:
                        required_fields = ['file_name', 'file_size', 'file_mtime', 'file_hash']
                        if not all(field in message for field in required_fields):
                            raise ValueError("Missing required file information")
                            
                        file_name = message['file_name']
                        file_size = message['file_size']
                        file_mtime = message['file_mtime']
                        file_hash = message['file_hash']
                        
                        if client_name not in shared_files:
                            shared_files[client_name] = []
                            
                        file_index = next((i for i, (fname, *_) in enumerate(shared_files[client_name]) 
                                        if fname == file_name), None)
                        
                        if file_index is not None:
                            _, _, _, _, version = shared_files[client_name][file_index]
                            shared_files[client_name][file_index] = (
                                file_name, file_size, file_mtime, file_hash, version + 1
                            )
                        else:
                            shared_files[client_name].append(
                                (file_name, file_size, file_mtime, file_hash, 1))
                        
                        if client_name not in file_history:
                            file_history[client_name] = {}
                        if file_name not in file_history[client_name]:
                            file_history[client_name][file_name] = []
                            
                        file_history[client_name][file_name].append(
                            (shared_files[client_name][-1][4], file_size, file_mtime, file_hash))
                        
                        broadcast_shared_files()
                        
                    except Exception as e:
                        print(f"Error processing file share from {client_name}: {e}")
                        try:
                            clients[client_name]['socket'].sendall(pickle.dumps({
                                'type': 'error',
                                'message': f"File share failed: {str(e)}"
                            }))
                        except:
                            pass
                
                elif message['type'] == 'file_verification':
                    file_name = message['file_name']
                    current_size = message['current_size']
                    current_mtime = message['current_mtime']
                    current_hash = message['current_hash']
                    
                    for i, (fname, fsize, fmtime, fhash, version) in enumerate(shared_files.get(client_name, [])):
                        if fname == file_name:
                            if fhash != current_hash:
                                new_version = version + 1
                                shared_files[client_name][i] = (
                                    file_name, current_size, current_mtime, current_hash, new_version
                                )
                                
                                file_history[client_name][file_name].append(
                                    (new_version, current_size, current_mtime, current_hash))
                                
                                broadcast_shared_files()
                                
                                for name, info in clients.items():
                                    try:
                                        info['socket'].sendall(pickle.dumps({
                                            'type': 'file_changed',
                                            'client': client_name,
                                            'file': file_name,
                                            'new_size': current_size,
                                            'new_version': new_version,
                                            'change_time': datetime.now().isoformat()
                                        }))
                                    except:
                                        if name in clients:
                                            del clients[name]
                            break
                
                elif message['type'] == 'unshare_file':
                    if client_name in shared_files:
                        shared_files[client_name] = [
                            f for f in shared_files[client_name] 
                            if f[0] != message['file_name']
                        ]
                        broadcast_shared_files()
                    
            except Exception as e:
                print(f"Error handling message from {client_name}: {e}")
                break
                
    except Exception as e:
        print(f"Connection error with {address}: {str(e)}")
    finally:
        if client_name:
            if client_name in clients:
                del clients[client_name]
                broadcast_client_list()
            if client_name in shared_files:
                del shared_files[client_name]
                broadcast_shared_files()
        client_socket.close()

def listen_for_discovery():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', 12345))
    
    while True:
        try:
            message, address = udp_socket.recvfrom(1024)
            if message == b'PING':
                server_ip = get_local_ip()
                udp_socket.sendto(server_ip.encode(), address)
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