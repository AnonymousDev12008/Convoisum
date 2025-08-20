# crypto_core.py

import os
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Layer 1: Identity & Key Generation ---

def generate_keys():
    """
    Generates a new ECC private and public key pair for a user.
    """
    # Generate a private key using the SECP256R1 curve (a common, strong standard)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Converts a public key object into bytes so it can be sent over the network.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """
    Converts received bytes back into a public key object.
    """
    return serialization.load_pem_public_key(pem_bytes)

# --- Layer 2: The Secure Handshake (ECDH) --- 

def derive_shared_key(private_key, peer_public_key):
    """
    DEPRECATED: Use derive_shared_key_with_context instead for better security.
    Derives a shared secret key using our private key and the peer's public key.
    """
    # Perform the ECDH key exchange
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use HKDF to derive a strong, fixed-size symmetric key from the shared secret.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes = 256 bits for AES-256
        salt=None,
        info=b'p2p-texting-app-key' # Context-specific info
    ).derive(shared_secret)
    
    return derived_key

def derive_shared_key_with_context(private_key, peer_public_key, session_context):
    """
    SECURE VERSION: Derives a shared secret key with session context binding.
    This prevents key confusion attacks and session splicing.
    
    Args:
        private_key: Our ECDH private key
        peer_public_key: Peer's ECDH public key  
        session_context: Bytes that uniquely identify this session
                        (should include both pubkeys, onion address, port)
    """
    # Perform the ECDH key exchange
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use HKDF with session context to derive a strong, session-bound key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=None,
        info=b'convoisum-session-v1' + session_context
    ).derive(shared_secret)
    
    return derived_key

def derive_sas(session_key, transcript):
    """
    Derive Short Authentication String for human verification.
    
    Args:
        session_key: The derived session key
        transcript: Session transcript (pubkeys + connection info)
    
    Returns:
        Human-readable verification string (4 words)
    """
    # PGP word list for clear, unambiguous verification
    # Using a subset for brevity - in production use full PGP word list
    words = [
        "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
        "aimless", "algae", "allow", "alone", "amuse", "animal", "anthem", "apple",
        "armor", "around", "arrest", "artist", "atomic", "august", "autumn", "avatar",
        "awake", "backup", "badge", "bamboo", "barrel", "battery", "beach", "beaver",
        "become", "bedroom", "beehive", "begin", "behave", "believe", "benefit", "best",
        "bicycle", "bigger", "billion", "biology", "birthday", "blanket", "blossom", "blue",
        "board", "boast", "boat", "body", "boil", "bomb", "bone", "bonus",
        "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box",
        "brave", "bread", "break", "breed", "brick", "bridge", "brief", "bright",
        "bring", "broad", "broken", "bronze", "brown", "brush", "bubble", "buddy",
        "build", "bulk", "bundle", "burden", "burn", "burst", "business", "butter",
        "buyer", "cable", "cactus", "cage", "cake", "call", "calm", "camera",
        "camp", "can", "cancel", "candle", "candy", "cannon", "canoe", "canvas",
        "canyon", "capable", "capital", "captain", "capture", "carbon", "card", "care",
        "cargo", "carpet", "carry", "cart", "case", "cash", "castle", "casual",
        "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling"
    ]
    
    # Derive SAS from session key and transcript
    sas_material = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'convoisum-sas-v1'
    ).derive(session_key + transcript)
    
    # Convert to 4 word verification string
    indices = []
    for i in range(4):
        # Use 2 bytes per word for better distribution
        word_bytes = sas_material[i*2:(i+1)*2]
        word_index = int.from_bytes(word_bytes, 'big') % len(words)
        indices.append(word_index)
    
    verification_words = [words[i] for i in indices]
    return "-".join(verification_words)

# --- Layer 3: Nonce Management ---

class NonceCounter:
    """
    Thread-safe nonce counter to prevent nonce reuse in AES-GCM.
    Uses counter + random to avoid birthday paradox collisions.
    """
    def __init__(self):
        self.counter = 0
        self.lock = threading.Lock()
        self.session_random = os.urandom(4)  # Random per session
    
    def get_next_nonce(self):
        """Generate next unique nonce"""
        with self.lock:
            # 8 bytes counter + 4 bytes session random = 12 bytes total
            nonce = self.counter.to_bytes(8, 'big') + self.session_random
            self.counter += 1
            if self.counter >= 2**60:  # Prevent counter overflow
                raise RuntimeError("Nonce counter overflow - start new session")
            return nonce

# --- Layer 4: The Core Encryption/Decryption Engine ---

def encrypt_message(key, plaintext, nonce_counter=None):
    """
    Encrypts a message using AES-256-GCM with secure nonce management.
    
    Args:
        key: 32-byte AES key
        plaintext: Message to encrypt
        nonce_counter: NonceCounter instance (recommended) or None for random nonce
    """
    aesgcm = AESGCM(key)
    
    if nonce_counter:
        nonce = nonce_counter.get_next_nonce()
    else:
        # Fallback to random - not recommended for production
        nonce = os.urandom(12)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext  # Return both nonce and ciphertext together

def decrypt_message(key, encrypted_message):
    """
    Decrypts a message using AES-256-GCM.
    Returns the decrypted plaintext or None if authentication fails.
    """
    if len(encrypted_message) < 12:
        print("Message too short to contain valid nonce")
        return None
        
    aesgcm = AESGCM(key)
    
    # The first 12 bytes are the nonce
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    
    try:
        # Decryption will automatically verify the authentication tag.
        # If the ciphertext was tampered with, this will raise InvalidTag exception.
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Important: If decryption fails, it means the message was corrupted or tampered with.
        # Return None instead of the plaintext.
        print(f"Decryption failed: {e}")
        return None
