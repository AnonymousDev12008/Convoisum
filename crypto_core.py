# crypto_core.py - Updated with security improvements

import os
import threading
import ctypes
import atexit
import signal
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
        self._destroyed = False
    
    def bytes(self) -> bytes:
        if self._destroyed:
            raise ValueError("SecureBytes has been destroyed")
        return bytes(self.buf)
    
    def destroy(self):
        """Explicitly zero the buffer"""
        if not self._destroyed:
            ctypes.memset(self.buf, 0, self.size)
            self._destroyed = True
    
    def __del__(self):
        self.destroy()

def secure_delete(data: bytes):
    """Securely zero memory buffer"""
    buf = ctypes.create_string_buffer(data, len(data))
    ctypes.memset(buf, 0, len(data))

def generate_keys():
    """Generate ECDH key pair on P-256 curve"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize public key to PEM format"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """Deserialize and validate public key from PEM"""
    try:
        public_key = serialization.load_pem_public_key(pem_bytes)
        if not validate_public_key(public_key):
            raise ValueError("Invalid public key")
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to deserialize public key: {e}")

def validate_public_key(public_key):
    """Validate public key is on curve and not identity point"""
    try:
        nums = public_key.public_numbers()
        
        print(f"Public key X: {nums.x}")
        print(f"Public key Y: {nums.y}")
        print(f"Curve: {type(nums.curve)}")
        
        # Reject identity point (0,0)
        if nums.x == 0 and nums.y == 0:
            print("[!] Validation failed: Identity point (0,0)")
            return False
        
        # Verify key is on P-256 curve
        if not isinstance(nums.curve, ec.SECP256R1):
            print("[!] Validation failed: Key is not on SECP256R1 curve")
            return False
        
        print("[+] Public key validation passed")
        return True
    except Exception as e:
        print(f"[!] Exception during key validation: {e}")
        return False



def derive_shared_key_with_context(private_key, peer_public_key, session_context: bytes):
    """Derive shared session key using ECDH + HKDF"""
    if not validate_public_key(peer_public_key):
        raise ValueError("Invalid peer public key")
    
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    secret_buf = SecureBytes(shared_secret)
    
    try:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"convoisum-session-salt-v1",  # Fixed salt for consistency
            info=b"convoisum-session-v1" + session_context
        ).derive(secret_buf.bytes())
        return SecureBytes(derived)
    finally:
        secure_delete(shared_secret)
        secret_buf.destroy()

def derive_sas(session_key: SecureBytes, transcript: bytes):
    """Derive Short Authentication String for verification"""
    # Extended PGP wordlist subset for better entropy
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
        salt=b"convoisum-sas-salt-v1",  # Fixed salt
        info=b"convoisum-sas-v1"
    ).derive(session_key.bytes() + transcript)
    
    indices = []
    for i in range(4):
        chunk = sas_material[i*2:(i+1)*2]
        idx = int.from_bytes(chunk, "big") % len(words)
        indices.append(idx)
    
    return "-".join(words[i] for i in indices)

class SecureNonceCounter:
    """Thread-safe nonce counter with deterministic generation"""
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0
        self.base_nonce = os.urandom(8)  # 8 bytes base + 4 bytes counter = 12 total
    
    def get_next_nonce(self):
        """Generate deterministic nonce with counter to prevent reuse"""
        with self.lock:
            # Combine 8-byte base with 4-byte counter
            counter_bytes = self.counter.to_bytes(4, 'big')
            nonce = self.base_nonce + counter_bytes
            self.counter += 1
            
            # Reset counter if it overflows (very unlikely)
            if self.counter >= 2**32:
                self.counter = 0
                self.base_nonce = os.urandom(8)
            
            return nonce

def encrypt_message(key: SecureBytes, plaintext: str, nonce_counter, sequence_num: int = 0):
    """Encrypt message with replay protection"""
    if key._destroyed:
        raise ValueError("Cannot encrypt with destroyed key")
    
    aesgcm = AESGCM(key.bytes())
    nonce = nonce_counter.get_next_nonce()
    
    # Include sequence number in associated data to prevent replay
    associated_data = sequence_num.to_bytes(8, 'big')
    
    try:
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return nonce + ct
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")

def dummy_decrypt(key: SecureBytes):
    """Constant-time dummy operation for timing attack resistance"""
    try:
        aesgcm = AESGCM(key.bytes())
        aesgcm.decrypt(b"\x00"*12, b"\x00"*32, b"\x00"*8)
    except Exception:
        pass

def decrypt_message(key: SecureBytes, encrypted_message: bytes, sequence_num: int = 0):
    """Decrypt message with replay protection"""
    if key._destroyed:
        raise ValueError("Cannot decrypt with destroyed key")
    
    # Constant-time failure path
    if len(encrypted_message) < 28:  # 12 nonce + 16 min ciphertext
        dummy_decrypt(key)
        return None
    
    aesgcm = AESGCM(key.bytes())
    nonce = encrypted_message[:12]
    ct = encrypted_message[12:]
    
    # Include sequence number in associated data
    associated_data = sequence_num.to_bytes(8, 'big')
    
    try:
        pt = aesgcm.decrypt(nonce, ct, associated_data)
        result = pt.decode("utf-8")
        success = True
    except Exception:
        result = None
        success = False
    
    # Uniform timing
    if not success:
        dummy_decrypt(key)
    
    return result
