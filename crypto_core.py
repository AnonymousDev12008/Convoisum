import os
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

def derive_shared_key_with_context(private_key, peer_public_key, session_context):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'convoisum-session-v1' + session_context
    ).derive(shared_secret)
    return derived_key

def derive_sas(session_key, transcript):
    # Minimal word list subset for demo; consider using a full PGP word list in production
    words = [
        "aardvark","absurd","accrue","acme","adrift","adult","afflict","ahead",
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
        "catch","category","cattle","caught","cause","caution","cave","ceiling"
    ]

    sas_material = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'convoisum-sas-v1'
    ).derive(session_key + transcript)

    indices = []
    for i in range(4):
        chunk = sas_material[i*2:(i+1)*2]
        idx = int.from_bytes(chunk, 'big') % len(words)
        indices.append(idx)

    verification_words = [words[i] for i in indices]
    return "-".join(verification_words)

class NonceCounter:
    def __init__(self):
        self.counter = 0
        self.lock = threading.Lock()
        self.session_random = os.urandom(4)  # 4 bytes random per session

    def get_next_nonce(self):
        with self.lock:
            nonce = self.counter.to_bytes(8, 'big') + self.session_random  # 8+4=12 bytes
            self.counter += 1
            if self.counter >= 2**60:
                raise RuntimeError("Nonce counter overflow - start new session")
            return nonce

def encrypt_message(key, plaintext, nonce_counter=None):
    aesgcm = AESGCM(key)
    if nonce_counter:
        nonce = nonce_counter.get_next_nonce()
    else:
        nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt_message(key, encrypted_message):
    if len(encrypted_message) < 12:
        print("Message too short to contain valid nonce")
        return None
    aesgcm = AESGCM(key)
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    try:
        pt = aesgcm.decrypt(nonce, ciphertext, None)
        return pt.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None
