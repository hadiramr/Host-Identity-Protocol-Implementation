# HIP SERVER

import socket
import time
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
# Generate global Diffie-Hellman parameters to be shared between all clients and the server
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
# Access Control List to define permissions based on role

ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}
# Log server events with timestamp
def write_server_log(msg):
    with open("server_log.txt", "a", encoding="utf-8") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log.write(f"[{timestamp}] {msg}\n")
# Verify the RSA digital signature using the client's public key
def verify(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False
# Perform Diffie-Hellman key exchange and derive a shared session key
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'hip key exchange').derive(shared_key)
# Encrypt and decrypt a message using the session key
def aes_communicate(key, message):
    fernet_key = urlsafe_b64encode(key[:32])
    cipher = Fernet(fernet_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted, decrypted
# Check if the user's role is allowed to perform a specific action
def authorize(role, action):
    return action in ACL.get(role.lower(), [])
# Start the HIP server
def start_server():
        # Generate RSA key pair for the server
    server_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_public = server_private.public_key()
    # Create a socket and listen for connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 9999))
        s.listen()
        print("[Server] Running on port 9999...")
            # Accept a new client connection
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"\n[Server] Connected by {addr}")
                write_server_log(f"Connection from {addr}")
                last_timestamp = 0 # For replay protection
                # Step 1: Receive the client's RSA public key 
                client_hi = conn.recv(4096)
                client_public = serialization.load_der_public_key(client_hi)
                # Step 2: Send server's RSA public key to client 
                server_hi_bytes = server_public.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
                conn.sendall(server_hi_bytes)

                # Step 3: Perform DH key exchange and generate session key 
                dh_priv = dh_parameters.generate_private_key()
                peer_dh_pub = dh_parameters.generate_private_key().public_key()# Simulated peer public key
                session_key = derive_shared_key(dh_priv, peer_dh_pub)
                print(f"[Server] Session Key for {addr}: {session_key.hex()}")
                write_server_log(f"Session Key created for {addr}")
                # Step 4: Begin receiving client messages 

                while True:
                    try:
                        data = conn.recv(8192)
                        if not data:
                            print("[Server] Client disconnected.")
                            break
                        # Parse the incoming message
                        data = data.decode().split("||")
                        signature = bytes.fromhex(data[0])
                        timestamp = float(data[1])
                        role = data[2]
                        action = data[3]
                        message = data[4].encode()
                        # Check for replay attacks or outdated timestamps
                        if timestamp <= last_timestamp:
                            conn.sendall(b"Replay detected!")
                            write_server_log("Replay attack detected")
                            continue
                        elif abs(time.time() - timestamp) > 30:
                            conn.sendall(b"Timestamp expired!")
                            write_server_log("Timestamp expired")
                            continue
                        last_timestamp = timestamp
                        # Verify the digital signature
                        if verify(client_public, signature, f"{timestamp}".encode()):
                            if authorize(role, action):
                                enc, dec = aes_communicate(session_key, message)
                                result = f"[Auth] Encrypted: {enc.decode()} | Decrypted: {dec.decode()}"
                                write_server_log(f"Authorized '{role}' for '{action}'. Msg: {dec.decode()}")
                            else:
                                result = "[ Auth] Authorization failed"
                                write_server_log(f"Unauthorized action '{action}' by role '{role}'")
                        else:
                            result = "[Auth] Signature verification failed"
                            write_server_log("Signature verification failed")
                        # Send the result back to the client
                        conn.sendall(result.encode())

                    except Exception as e:
                        print(f"[Server Error] {e}")
                        write_server_log(f"Server Error: {e}")
                        break

if __name__ == "__main__":
    start_server()   