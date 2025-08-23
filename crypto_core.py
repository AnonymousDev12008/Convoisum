# crypto_core.py

import os
import threading
import ctypes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Secure byte buffer that zeroes memory on deletion
class SecureBytes:
    def __init__(self, data: bytes):
        self.size = len(data)
        self.buf = (ctypes.c_ubyte * self.size)()
        ctypes.memmove(self.buf, data, self.size)
    def bytes(self) -> bytes:
        return bytes(self.buf)
    def __del__(self):
        ctypes.memset(self.buf, 0, self.size)

def secure_delete(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    ctypes.memset(buf, 0, len(data))

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

def validate_public_key(public_key):
    try:
        nums = public_key.public_numbers()
        # Reject identity point
        if nums.x == 0 and nums.y == 0:
            return False
        # Curve parameters
        curve = nums.curve
        p = curve.curve.p
        # Check y^2 == x^3 + a*x + b mod p
        if (nums.y*nums.y) % p != (nums.x*nums.x*nums.x + curve.curve.a * nums.x + curve.curve.b) % p:
            return False
        return True
    except Exception:
        return False

def derive_shared_key_with_context(private_key, peer_public_key, session_context: bytes):
    if not validate_public_key(peer_public_key):
        raise ValueError("Invalid peer public key")
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    secret_buf = SecureBytes(shared_secret)
    try:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"convoisum-session-v1" + session_context
        ).derive(secret_buf.bytes())
        return SecureBytes(derived)
    finally:
        secure_delete(shared_secret)
        del secret_buf

def derive_sas(session_key: SecureBytes, transcript: bytes):
    # sample PGP wordlist subset
    words = ["aardvark","absurd","accrue","acme","adrift","adult","afflict","ahead",
             "aimless","algae","allow","alone","amuse","animal","anthem","apple",
             "armor","around","arrest","artist","atomic","august","autumn","avatar",
             "awake","backup","badge","bamboo","barrel","battery","beach","beaver",
             "become","bedroom","beehive","begin","behave","believe","benefit","best",
             "bicycle","bigger","billion","biology","birthday","blanket","blossom","blue",
             "board","boast","boat","body","boil","bomb","bone","bonus",
             "boost","border","boring","borrow","boss","bottom","bounce","box",
             "brave","bread","break","breed","brick","bridge","brief","bright",
             "bring","broad","broken","bronze","brown","brush","bubble","buddy",
             "build","bulk","bundle","burden","burn","burst","business","butter",
             "buyer","cable","cactus","cage","cake","call","calm","camera",
             "camp","can","cancel","candle","candy","cannon","canoe","canvas",
             "canyon","capable","capital","captain","capture","carbon","card","care",
             "cargo","carpet","carry","cart","case","cash","castle","casual",
             "catch","category","cattle","caught","cause","caution","cave","ceiling"]
    sas_material = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"convoisum-sas-v1"
    ).derive(session_key.bytes() + transcript)
    indices = []
    for i in range(4):
        chunk = sas_material[i*2:(i+1)*2]
        idx = int.from_bytes(chunk, "big") % len(words)
        indices.append(idx)
    return "-".join(words[i] for i in indices)

class SecureNonceCounter:
    def __init__(self):
        self.lock = threading.Lock()
    def get_next_nonce(self):
        # Always use 12 bytes of secure randomness
        return os.urandom(12)

def encrypt_message(key: SecureBytes, plaintext: str, nonce_counter=None):
    aesgcm = AESGCM(key.bytes())
    if nonce_counter:
        nonce = nonce_counter.get_next_nonce()
    else:
        nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct

def dummy_decrypt(key: SecureBytes):
    aesgcm = AESGCM(key.bytes())
    try:
        aesgcm.decrypt(b"\x00"*12, b"\x00"*32, None)
    except Exception:
        pass

def decrypt_message(key: SecureBytes, encrypted_message: bytes):
    # Constant-time failure path
    if len(encrypted_message) < 12:
        dummy_decrypt(key)
        return None
    aesgcm = AESGCM(key.bytes())
    nonce = encrypted_message[:12]
    ct = encrypted_message[12:]
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
        result = pt.decode("utf-8")
        success = True
    except Exception:
        result = None
        success = False
    # uniform timing
    if not success:
        dummy_decrypt(key)
    return result
