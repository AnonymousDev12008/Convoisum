# crypto_core.py

import os
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
    Derives a shared secret key using our private key and the peer's public key.
    Then, it uses a Key Derivation Function (HKDF) to create a robust 32-byte key for AES.
    """
    # Perform the ECDH key exchange
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use HKDF to derive a strong, fixed-size symmetric key from the shared secret.
    # This is a crucial step to ensure the key is cryptographically suitable for AES.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes = 256 bits for AES-256
        salt=None,
        info=b'p2p-texting-app-key' # Context-specific info
    ).derive(shared_secret)
    
    return derived_key

# --- Layer 3: The Core Encryption/Decryption Engine ---

def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Proper, secure random nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext  # Return both nonce and ciphertext together

def decrypt_message(key, encrypted_message):
    """
    Decrypts a message using AES-256-GCM.
    Returns the decrypted plaintext or raises an exception if authentication fails.
    """
    aesgcm = AESGCM(key)
    
    # The first 12 bytes are the nonce
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    
    try:
        # Decryption will automatically verify the authentication tag.
        # If the ciphertext was tampered with, this line will raise InvalidTag exception.
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Important: If decryption fails, it means the message was corrupted or tampered with.
        # Do not use the output.
        print(f"Decryption failed: {e}")
        return None

