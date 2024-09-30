import socket
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def generate_dh_parameters():
    
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16
    )
    g = 2
    return p, g

def derive_aes_key(shared_secret):
    
    shared_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    from Crypto.Hash import SHA256
    hash_obj = SHA256.new(shared_bytes)
    return hash_obj.digest()

def start_client(host='localhost', port=65433):
    """Starts the secure client to connect to the server and send encrypted messages."""
    p, g = generate_dh_parameters()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
            print(f"[+] Connected to server at {host}:{port}")
            
            
            client_private = int.from_bytes(get_random_bytes(256), 'big') % p
            client_public = pow(g, client_private, p)
            
            
            client_socket.sendall(str(client_public).encode())
            print(f"[+] Sent client's public key: {client_public}")
            
            
            server_pub_key_data = client_socket.recv(4096)
            server_pub_key = int(server_pub_key_data.decode())
            print(f"[+] Received server's public key: {server_pub_key}")
            
            
            shared_secret = pow(server_pub_key, client_private, p)
            print(f"[+] Shared secret established.")
            print()
            
            
            aes_key = derive_aes_key(shared_secret)
            
            while True:
                
                message = input("Enter message to send (type 'exit' to quit): ")
                if message.lower() == 'exit':
                    print("[*] Exiting.")
                    break
                
                
                iv = get_random_bytes(16)  
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
                
                encrypted_data = iv + ciphertext
                
                encoded_data = base64.b64encode(encrypted_data)
                
                client_socket.sendall(encoded_data)
                print(f"[+] Encrypted message sent: {encoded_data}")
                print()
                
        except ConnectionRefusedError:
            print(f"[-] Cannot connect to server at {host}:{port}. Is the server running?")
        except KeyboardInterrupt:
            print("\n[*] Client terminated by user.")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    start_client()
