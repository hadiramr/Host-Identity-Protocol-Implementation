from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import time

# Generate RSA key pairs
def generate_key_pair():
    PrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PublicKey = PrivateKey.public_key()
    return PrivateKey, PublicKey

# Generate keys for A and B
APrivate, APublic = generate_key_pair()
BPrivate, BPublic = generate_key_pair()

# Role-based Access Control
ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}

# Digital signature (Authentication)
def authenticate(signerPrivate, verifierPublic, Message):
    try:
        signature = signerPrivate.sign(
            Message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        verifierPublic.verify(
            signature,
            Message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True, signature
    except Exception:
        return False, None

# Authorization based on role
def authorize(role, action):
    allowed_actions = ACL.get(role.lower(), [])
    return action in allowed_actions

# AES Encryption/Decryption
def aes_communication(shared_key, message):
    cipher = Fernet(shared_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted.decode(), decrypted.decode()

# Global timestamp for replay attack prevention
last_timestamp = 0

# Scenario Runner
def run_scenario(title, sender_priv, receiver_priv, role, action, message, spoofed=False, replay=False):
    global last_timestamp

    if replay:
        timestamp = last_timestamp  
    else:
        timestamp = time.time()

    timestamped = message + b'||' + str(timestamp).encode()

    # Authentication logic
    if spoofed:
        # Use mismatched public keys to simulate spoofing and force failure
        authAtoB, _ = authenticate(sender_priv, BPublic, timestamped)
        authBtoA, _ = authenticate(receiver_priv, APublic, timestamped)
    else:
        authAtoB, _ = authenticate(sender_priv, sender_priv.public_key(), timestamped)
        authBtoA, _ = authenticate(receiver_priv, receiver_priv.public_key(), timestamped)

    # Authorization
    if authAtoB and authBtoA:
        authz = authorize(role, action)
    else:
        authz = "Skipped (authentication failed)"

    # AES communication
    aesKey = Fernet.generate_key()
    encrypted, decrypted = aes_communication(aesKey, message)
    if not (authAtoB and authBtoA and authz == True):
        decrypted = "Not allowed"

    # Replay protection
    if authAtoB and authBtoA:
        try:
            msg_parts = timestamped.split(b'||')
            msg = msg_parts[0]
            ts = float(msg_parts[1].decode())
            current_time = time.time()

            if ts <= last_timestamp:
                replay_valid = False
                replay_result = "Detected replay attack! Hacker reused an old message."
            elif abs(current_time - ts) > 30:
                replay_valid = False
                replay_result = "Replay attack detected (expired)."
            else:
                replay_valid = True
                replay_result = msg.decode()
                last_timestamp = ts
        except:
            replay_valid = False
            replay_result = "Invalid timestamp format!"
    else:
        replay_valid = False
        replay_result = "Authentication failed — Replay check not performed"

    # Output
    print(f"{title}:")
    print(f"Authentication A -> B: {authAtoB}\n")
    print(f"Authentication B -> A: {authBtoA}\n")
    print(f"Role: {role}\n")
    print(f"Requested Action: {action}\n")
    print(f"Authorization Result: {authz}\n")
    print(f"Encrypted AES Message: {encrypted}\n")
    print(f"Decrypted AES Message: {decrypted}\n")
    print(f"Replay Check Valid: {replay_valid}\n")
    print(f"Replay Check Result: {replay_result}\n")


run_scenario("Scenario 1", APrivate, BPrivate, "analyst", "write", b"Hello")
run_scenario("Scenario 2 (Spoofed Communication)", APrivate, BPrivate, "analyst", "delete", b"Hello 2", spoofed=True)
run_scenario("Scenario 3", BPrivate, APrivate, "guest", "read", b"Hello 3")
run_scenario("Scenario 4 (Replay Attack)", APrivate, BPrivate, "analyst", "write", b"Hello", replay=True)
