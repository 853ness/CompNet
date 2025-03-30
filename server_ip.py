import socket

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