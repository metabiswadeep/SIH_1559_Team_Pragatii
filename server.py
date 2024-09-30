import socket

def start_server(host='localhost', port=65432):
    """Starts the server to listen for incoming connections and messages."""
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        
        server_socket.bind((host, port))
        print(f"Server started and listening on {host}:{port}")
        
        
        server_socket.listen(1)
        
        while True:
            print("Waiting for a connection...")
            
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    
                    data = conn.recv(1024)
                    if not data:
                        
                        print("Connection closed by the client.")
                        break
                   
                    message = data.decode('utf-8')
                    print(f"Received message: {message}")
                    

if __name__ == "__main__":
    start_server()
