#HIP CLIENT 
import socket
import time
import json
import os
from getpass import getpass
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# File where users' credentials and roles are stored
USERS_FILE = "users.json"

# Shared Diffie-Hellman parameters between client and server
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

# Load all registered users from JSON file
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

# Save users data to JSON file
def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# Write activity logs for client operations
def write_client_log(msg):
    with open("client_log.txt", "a", encoding="utf-8") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log.write(f"[{timestamp}] {msg}\n")

# Digitally sign a message using RSA private key
def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# Derive a symmetric session key using Diffie-Hellman key exchange
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hip key exchange'
    ).derive(shared_key)

# Register new user (always assigned role = "guest")
def sign_up():
    users = load_users()
    print("\n Sign Up:")
    username = input(" New Username: ").strip()

    if username in users:
        print("[SignUp ] Username already exists.")
        return None

    password = getpass(" Password: ")

    # All new users are assigned the 'guest' role
    role = "guest"
    users[username] = {"password": password, "role": role}
    save_users(users)

    print(f"[SignUp ] Account created as GUEST: {username}")
    write_client_log(f"New guest user signed up: {username}")
    return username

# Authenticate user, perform handshake, and handle actions
def login_and_connect():
    users = load_users()
    username = input(" Username: ").strip()
    password = getpass(" Password: ")

    # Verify username and password
    if username not in users or users[username]["password"] != password:
        print("[Client ] Invalid username or password")
        write_client_log(f"Login FAILED for username: '{username}'")
        return

    # Extract user's role
    role = users[username]["role"]

    # Generate RSA key pair for signing
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 9999))

            # Step 1: Send client's RSA public key to server
            public_bytes = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            s.sendall(public_bytes)

            # Step 2: Receive server's RSA public key
            server_hi = s.recv(4096)
            server_public = serialization.load_der_public_key(server_hi)

            # Step 3: Generate client's DH key pair
            dh_priv = dh_parameters.generate_private_key()
            client_dh_pub = dh_priv.public_key()

            # Step 4: Receive server's DH public key
            server_dh_bytes = s.recv(4096)
            server_dh_pub = serialization.load_pem_public_key(server_dh_bytes)

            # Step 5: Send client's DH public key
            s.sendall(client_dh_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Step 6: Compute shared session key using DH
            session_key = derive_shared_key(dh_priv, server_dh_pub)
            write_client_log(f"Session Key generated for user '{username}'")

            session_start = time.time()
            print("Session started. You have 5 minutes.")

            # Main session loop
            while True:
                if time.time() - session_start > 300:
                    print(" Session expired after 5 minutes. Please login again.")
                    write_client_log(f"Session expired for user '{username}'")
                    break

                # Prompt for action from the user
                action = input("\n Action (read/write/delete): ").strip()
                message = input("Message or index: ").strip()

                # Timestamp and signature
                timestamp = time.time()
                signature = sign(private_key, f"{timestamp}".encode())

                # Construct message to send
                payload = f"{signature.hex()}||{timestamp}||{role}||{action}||{message}"
                s.sendall(payload.encode())

                # Receive and print response from server
                response = s.recv(8192).decode()
                print(f"[ Server Response] {response}")
                write_client_log(f"User '{username}' performed '{action}' as '{role}'. Response: {response}")

                # Option to continue or exit
                again = input(" Do another action? (y/n): ").strip().lower()
                if again != 'y':
                    print(" Session ended.")
                    write_client_log(f"User '{username}' ended session.")
                    break

    except Exception as e:
        print(f"[Client ] Error: {e}")
        write_client_log(f"Client Error: {e}")

# === MAIN MENU ===
if __name__ == "__main__":
    while True:
        print("\n===== HIP Client Main Menu =====")
        print("1.  Login")
        print("2.  Sign Up")
        print("3.  Exit")
        choice = input("Select option (1/2/3): ")

        if choice == "1":
            login_and_connect()
        elif choice == "2":
            sign_up()
        elif choice == "3":
            print(" Goodbye!")
            break
        else:
            print(" Invalid choice. Please select 1, 2, or 3.")
