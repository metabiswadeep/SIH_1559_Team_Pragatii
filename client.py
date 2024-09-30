import socket

def start_client(host='localhost', port=65432):
    """Starts the client to connect to the server and send messages."""
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            
            client_socket.connect((host, port))
            print(f"Connected to server at {host}:{port}")
            
            while True:
                
                message = input("Enter message to send (type 'exit' to quit): ")
                
                if message.lower() == 'exit':
                    print("Closing connection.")
                    break
                
                
                print()
                print(f"Haha from the hacker 😈, and I just read your message as - \"{message}\"")
                print()
                client_socket.sendall(message.encode('utf-8'))
                
                
        except ConnectionRefusedError:
            print(f"Cannot connect to server at {host}:{port}. Is the server running?")
        except KeyboardInterrupt:
            print("\nClient terminated by user.")

if __name__ == "__main__":
    start_client()
