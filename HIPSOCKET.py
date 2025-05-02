# imports due to code execution state reset
import socket
import threading
import time
import hashlib
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# Global DH parameters
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def generate_hit(public_key):
    public_bytes = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).digest()[:16]

def generate_dh_key_pair():
    private_key = dh_parameters.generate_private_key()
    return private_key, private_key.public_key()

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hip key exchange'
    ).derive(shared_key)

def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

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

def aes_communicate(key, message):
    fernet_key = urlsafe_b64encode(key[:32])
    cipher = Fernet(fernet_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted, decrypted

def authorize(role, action):
    return action in ACL.get(role.lower(), [])

# Server logic with replay protection
def start_server():
    try:
        server_private, server_public = generate_key_pair()
        dh_priv, dh_pub = generate_dh_key_pair()
        last_timestamp = 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 9999))
            s.listen()
            print("[Server] Listening on port 9999...")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"[Server] Connected by {addr}")
                    client_hi = conn.recv(4096)
                    client_public = serialization.load_der_public_key(client_hi)

                    server_hi_bytes = server_public.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    conn.sendall(server_hi_bytes)

                    data = conn.recv(8192).decode().split("||")
                    signature = bytes.fromhex(data[0])
                    timestamp = float(data[1])
                    role = data[2]
                    action = data[3]
                    message = data[4].encode()

                    if timestamp <= last_timestamp:
                        conn.sendall(b"Replay detected!")
                        continue
                    elif abs(time.time() - timestamp) > 30:
                        conn.sendall(b"Timestamp expired!")
                        continue

                    last_timestamp = timestamp

                    if verify(client_public, signature, f"{timestamp}".encode()):
                        session_key = derive_shared_key(dh_priv, dh_pub)
                        allowed = authorize(role, action)
                        if allowed:
                            enc, dec = aes_communicate(session_key, message)
                            result = f"Auth Success | Encrypted: {enc.decode()} | Decrypted: {dec.decode()}"
                        else:
                            result = "Authorization failed"
                    else:
                        result = "Authentication failed"

                    conn.sendall(result.encode())
    except Exception as e:
        print(f"[Server Error] {e}")

# Client logic with optional replay
def start_client(role, action, message, reuse_timestamp=None, reuse_signature=None):
    try:
        client_private, client_public = generate_key_pair()
        dh_priv, dh_pub = generate_dh_key_pair()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 9999))

            public_bytes = client_public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            s.sendall(public_bytes)

            server_hi = s.recv(4096)
            server_public = serialization.load_der_public_key(server_hi)

            if reuse_timestamp and reuse_signature:
                timestamp = reuse_timestamp
                signature = reuse_signature
            else:
                timestamp = time.time()
                signature = sign(client_private, f"{timestamp}".encode())

            payload = f"{signature.hex()}||{timestamp}||{role}||{action}||{message}"
            s.sendall(payload.encode())

            response = s.recv(8192).decode()
            print(f"[Client Response] {response}")

            return timestamp, signature

    except Exception as e:
        print(f"[Client Error] {e}")

# Scenario runner
def run_combined_scenario_with_replay():
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(1)

    ts, sig = start_client("analyst", "read", "First message")
    time.sleep(1)
    start_client("analyst", "read", "Replayed message", reuse_timestamp=ts, reuse_signature=sig)
    start_client("admin", "write", "Admin update")

run_combined_scenario_with_replay()
