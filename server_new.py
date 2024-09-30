import socket
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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

def start_server(host='localhost', port=65433):
    """Starts the secure server to listen for incoming connections and encrypted messages."""
    p, g = generate_dh_parameters()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        print(f"[+] Server started and listening on {host}:{port}")
        server_socket.listen(1)
        
        while True:
            print("[*] Waiting for a connection...")
            conn, addr = server_socket.accept()
            with conn:
                print(f"[+] Connected by {addr}")
                try:
                    
                    client_pub_key = int(conn.recv(4096).decode())
                    print(f"[+] Received client's public key: {client_pub_key}")
                    
                    
                    server_private = int.from_bytes(get_random_bytes(256), 'big') % p
                    server_public = pow(g, server_private, p)
                    
                    
                    conn.sendall(str(server_public).encode())
                    print(f"[+] Sent server's public key: {server_public}")
                    
                    
                    shared_secret = pow(client_pub_key, server_private, p)
                    print(f"[+] Shared secret established.")
                    
                    
                    aes_key = derive_aes_key(shared_secret)
                    
                    while True:
                        
                        data = conn.recv(4096)
                        if not data:
                            print("[-] Connection closed by the client.")
                            break
                        
                        encrypted_data = base64.b64decode(data)
                        
                        iv = encrypted_data[:16]
                        ciphertext = encrypted_data[16:]
                        
                        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                        message = plaintext.decode('utf-8')
                        print()
                        print(f"[Encrypted] {data}")
                        print(f"[Decrypted] {message}")
                        print()
                except Exception as e:
                    print(f"[-] An error occurred: {e}")
                finally:
                    print("[*] Closing connection.")
    
if __name__ == "__main__":
    start_server()
