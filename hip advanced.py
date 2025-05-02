from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode
import hashlib
import time

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Generate HIT (Host Identity Tag)
def generate_hit(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hit = hashlib.sha256(public_bytes).digest()[:16]
    return hit

# Generate Diffie-Hellman key pair
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
def generate_dh_key_pair():
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

#Derive shared session key using DH exchange
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hip key exchange'
    ).derive(shared_key)
    return derived_key

# Authenticate with RSA
def authenticate(signer_private, verifier_public, message):
    try:
        signature = signer_private.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        verifier_public.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True, signature
    except Exception:
        return False, None

# Encrypt/Decrypt with Fernet using session key
def aes_communication_with_session_key(session_key, message):
    fernet_key = urlsafe_b64encode(session_key[:32])
    cipher = Fernet(fernet_key)
    encrypted = cipher.encrypt(message)
    decrypted = cipher.decrypt(encrypted)
    return encrypted.decode(), decrypted.decode()

# Authorization
ACL = {
    "admin": ["read", "write", "delete"],
    "analyst": ["read", "write"],
    "guest": ["read"]
}
def authorize(role, action):
    return action in ACL.get(role.lower(), [])

# HIP Base Exchange Simulation
def hip_base_exchange():
    # Generate DH key pairs
    A_dh_priv, A_dh_pub = generate_dh_key_pair()
    B_dh_priv, B_dh_pub = generate_dh_key_pair()

    # Exchange DH keys to derive shared key
    A_shared_key = derive_shared_key(A_dh_priv, B_dh_pub)
    B_shared_key = derive_shared_key(B_dh_priv, A_dh_pub)

    if A_shared_key == B_shared_key:
        return A_shared_key
    else:
        return None

# Global RSA keys
APrivate, APublic = generate_key_pair()
BPrivate, BPublic = generate_key_pair()

# Replay protection
last_timestamp = 0

# Scenario Simulation
def run_scenario(title, sender_priv, receiver_priv, role, action, message, spoofed=False, replay=False):
    global last_timestamp

    # Generate timestamp
    if replay:
        timestamp = last_timestamp
    else:
        timestamp = time.time()
    timestamped = message + b'||' + str(timestamp).encode()

    # Mutual Authentication
    if spoofed:
        authAtoB, _ = authenticate(sender_priv, receiver_priv.public_key(), timestamped)
        authBtoA, _ = authenticate(receiver_priv, sender_priv.public_key(), timestamped)
    else:
        authAtoB, _ = authenticate(sender_priv, sender_priv.public_key(), timestamped)
        authBtoA, _ = authenticate(receiver_priv, receiver_priv.public_key(), timestamped)

    # HIP Key Exchange
    if authAtoB and authBtoA:
        session_key = hip_base_exchange()
    else:
        session_key = None

    # Authorization Check
    authz = authorize(role, action) if (authAtoB and authBtoA) else "Skipped"

    # AES Communication
    if session_key:
        encrypted, decrypted = aes_communication_with_session_key(session_key, message)
    else:
        encrypted, decrypted = "Not encrypted", "Not allowed"

    # Replay Check
    if authAtoB and authBtoA:
        try:
            msg_parts = timestamped.split(b'||')
            ts = float(msg_parts[1].decode())
            current_time = time.time()

            if ts <= last_timestamp:
                replay_result = "Detected replay attack!"
                replay_valid = False
            elif abs(current_time - ts) > 30:
                replay_result = "Replay window expired!"
                replay_valid = False
            else:
                last_timestamp = ts
                replay_result = "Fresh message"
                replay_valid = True
        except:
            replay_valid = False
            replay_result = "Timestamp error!"
    else:
        replay_valid = False
        replay_result = "Replay check skipped (auth failed)"

    # Output
    print(f"\n{title}")
    print(f"HIT_A: {generate_hit(sender_priv.public_key()).hex()}")
    print(f"HIT_B: {generate_hit(receiver_priv.public_key()).hex()}")
    print(f"Authentication AB: {authAtoB}")
    print(f"Authentication BA: {authBtoA}")
    print(f"Role: {role}, Action: {action}")
    print(f"Authorization: {authz}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Replay Valid: {replay_valid}, Replay Result: {replay_result}")
    

# Run Scenarios
run_scenario("Scenario 1: Analyst writes", APrivate, BPrivate, "analyst", "write", b"Hello HIP")
run_scenario("Scenario 2: Analyst deletes (unauthorized)", APrivate, BPrivate, "analyst", "delete", b"Should fail")
run_scenario("Scenario 3: Spoofed guest read", BPrivate, APrivate, "guest", "read", b"Spoofed message", spoofed=True)
run_scenario("Scenario 4: Replay attack", APrivate, BPrivate, "analyst", "write", b"Hello HIP", replay=True)
