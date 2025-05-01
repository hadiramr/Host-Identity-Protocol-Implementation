from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import time

def generate_key_pair():
    PrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PublicKey = PrivateKey.public_key()
    return PrivateKey, PublicKey

APrivate, APublic = generate_key_pair()
BPrivate, BPublic = generate_key_pair()

ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}

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

def authorize(role, action):
    allowed_actions = ACL.get(role.lower(), [])
    return action in allowed_actions

def aes_communication(shared_key, message):
    cipher = Fernet(shared_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted.decode(), decrypted.decode()

# Global timestamp for replay protection
last_timestamp = 0

def run_scenario(title, sender_priv, receiver_priv, role, action, message, spoofed=False, replay=False):
    global last_timestamp

    if replay:
        timestamp = last_timestamp  # Intentionally reuse old timestamp
    else:
        timestamp = time.time()

    timestamped = message + b'||' + str(timestamp).encode()

    # Authentication
    if spoofed:
        authAtoB, _ = authenticate(sender_priv, receiver_priv.public_key(), timestamped)
        authBtoA, _ = authenticate(receiver_priv, sender_priv.public_key(), timestamped)
    else:
        authAtoB, _ = authenticate(sender_priv, sender_priv.public_key(), timestamped)
        authBtoA, _ = authenticate(receiver_priv, receiver_priv.public_key(), timestamped)

    # Authorization
    if authAtoB and authBtoA:
        authz = authorize(role, action)
    else:
        authz = "Skipped (authentication failed)"

    # AES encryption/decryption
    aesKey = Fernet.generate_key()
    encrypted, decrypted = aes_communication(aesKey, message)
    if not (authAtoB and authBtoA and authz == True):
        decrypted = "Not allowed"

    # Replay Check
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
                last_timestamp = ts  # Update timestamp only if message is fresh
        except:
            replay_valid = False
            replay_result = "Invalid timestamp format!"
    else:
        replay_valid = False
        replay_result = "Authentication failed — Replay check not performed"

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

# Test Scenarios
run_scenario("Scenario 1", APrivate, BPrivate, "analyst", "write", b"Hello")
print()
run_scenario("Scenario 2", APrivate, BPrivate, "analyst", "delete", b"Hello 2")
print()
run_scenario("Scenario 3", BPrivate, APrivate, "guest", "read", b"Hello 3", spoofed=True)
print()
run_scenario("Scenario 4 (Replay Attack)", APrivate, BPrivate, "analyst", "write", b"Hello", replay=True)
