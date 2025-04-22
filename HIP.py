from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import time

# ==== Step 1: Generate RSA Keys ====
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

A_private, A_public = generate_key_pair()
B_private, B_public = generate_key_pair()

# ==== Step 2: ACL Roles ====
ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}

# ==== Step 3: Authentication Function ====
def authenticate(signer_private, verifier_public, message):
    signature = signer_private.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    try:
        verifier_public.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True, signature
    except Exception:
        return False, None

# ==== Step 4: Authorization Function ====
def authorize(role, action):
    allowed_actions = ACL.get(role.lower(), [])
    return action in allowed_actions

# ==== Step 5: AES Encryption After Auth ====
def aes_communication(shared_key, message):
    cipher = Fernet(shared_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted, decrypted

# ==== Step 6: Simulate Replay Attack Detection ====
def verify_timestamped_message(message_with_time, window=30):
    try:
        msg_parts = message_with_time.split(b'||')
        msg = msg_parts[0]
        timestamp = float(msg_parts[1].decode())
        current_time = time.time()
        if abs(current_time - timestamp) > window:
            return False, "Replay attack detected!"
        return True, msg.decode()
    except:
        return False, "Invalid message format!"

# ==== Simulate Full Flow ====
original_message = b"Prove your identity"
timestamped_message = original_message + b'||' + str(time.time()).encode()

# 1. Authentication
auth_A_to_B, signature_A = authenticate(A_private, A_public, timestamped_message)
auth_B_to_A, signature_B = authenticate(B_private, B_public, timestamped_message)

# 2. Authorization
A_role = "analyst"
requested_action = "delete"
authorization_result = authorize(A_role, requested_action)

# 3. AES Secure Communication
aes_key = Fernet.generate_key()
encrypted_msg, decrypted_msg = aes_communication(aes_key, b"Confidential message from A to B")

# 4. Replay Attack Check (simulate 5 seconds delay)
valid_replay_check, replay_result = verify_timestamped_message(timestamped_message)

# ==== Output Results ====
{
    "Authentication A -> B": auth_A_to_B,
    "Authentication B -> A": auth_B_to_A,
    "Role": A_role,
    "Requested Action": requested_action,
    "Authorization Result": authorization_result,
    "Encrypted AES Message": encrypted_msg.decode(),
    "Decrypted AES Message": decrypted_msg.decode(),
    "Replay Check Valid": valid_replay_check,
    "Replay Check Result": replay_result
}

