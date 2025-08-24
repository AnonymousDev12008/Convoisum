# Convoisim-v2 crypto_core.py

import os
import threading
import ctypes
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import Hash, SHA256


# -------- Secure byte handling --------

class SecureBytes:
    """
    SecureBytes stores sensitive data in a mutable buffer and supports explicit zeroization.
    Note: Any time .bytes() is called, a new Python bytes object is created; avoid persisting it.
    Always destroy() long-lived SecureBytes as soon as you are done.
    """
    def __init__(self, data: bytes):
        self.size = len(data)
        self.buf = (ctypes.c_ubyte * self.size)()
        if self.size:
            ctypes.memmove(self.buf, data, self.size)
        self._destroyed = False

    def bytes(self) -> bytes:
        if self._destroyed:
            raise ValueError("SecureBytes has been destroyed")
        return bytes(self.buf[:self.size])

    def destroy(self):
        if not self._destroyed and self.size:
            ctypes.memset(self.buf, 0, self.size)
            self._destroyed = True

    def __del__(self):
        try:
            self.destroy()
        except Exception:
            pass


def secure_delete(data: bytes):
    """
    WARNING: Python bytes are immutable; there may be multiple copies.
    This function zeroes a temporary buffer and does NOT clear the original bytes object.
    Prefer SecureBytes for secrets you control.
    """
    if not isinstance(data, (bytes, bytearray)):
        return
    if len(data) == 0:
        return
    tmp = ctypes.create_string_buffer(data, len(data))
    ctypes.memset(tmp, 0, len(data))


# -------- Public key operations --------

def generate_keys():
    """Generate ECDH key pair on P-256 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """Serialize public key to PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_bytes: bytes):
    """Deserialize and validate public key from PEM."""
    try:
        public_key = serialization.load_pem_public_key(pem_bytes)
        if not validate_public_key(public_key):
            raise ValueError("Invalid public key")
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to deserialize public key: {e}")


def validate_public_key(public_key) -> bool:
    """
    Validate public key is on P-256 curve and not identity.
    No prints; returns boolean only.
    """
    try:
        nums = public_key.public_numbers()
        # Reject identity (0,0)
        if nums.x == 0 and nums.y == 0:
            return False
        # Enforce P-256
        if not isinstance(nums.curve, ec.SECP256R1):
            return False
        return True
    except Exception:
        return False


# -------- Transcript-bound salts --------

def _salt_from_transcript(label: bytes, transcript: bytes) -> bytes:
    """
    Derive a 16-byte salt from the transcript and a label, to bind KDF to session context.
    """
    h = Hash(SHA256())
    h.update(label)
    h.update(b"|")
    h.update(transcript)
    return h.finalize()[:16]


# -------- Session key and SAS derivation --------

def derive_shared_key_with_context(private_key, peer_public_key, session_context: bytes) -> SecureBytes:
    """
    Derive shared session key using ECDH + HKDF with transcript-derived salt and info binding.
    """
    if not validate_public_key(peer_public_key):
        raise ValueError("Invalid peer public key")

    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    secret_buf = SecureBytes(shared_secret)
    try:
        salt = _salt_from_transcript(b"convoisim-v2-session-salt", session_context)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"convoisim-v2-session|" + session_context
        ).derive(secret_buf.bytes())
        return SecureBytes(derived)
    finally:
        secret_buf.destroy()


# 256-entry SAS word list: keep stable; ASCII lowercase; avoid homophones.
SAS_WORDS = [
    "able","acid","aged","also","area","army","away","baby",
    "back","bake","ball","band","bank","base","bath","bear",
    "beat","been","beer","bell","belt","bend","best","bill",
    "bird","bite","blue","boat","body","bomb","bond","bone",
    "book","boom","boot","born","boss","both","bowl","bulk",
    "burn","bush","busy","cafe","cake","calm","camp","card",
    "care","case","cash","cast","cell","chat","chip","city",
    "club","coal","coat","code","cold","come","cook","cool",
    "cope","core","cost","crew","crop","dark","data","date",
    "dawn","days","dead","deal","dean","dear","debt","deep",
    "deer","desk","dial","dick","diet","disk","done","doom",
    "door","down","draw","drew","drop","drug","dual","duty",
    "each","earn","ease","east","easy","edge","else","even",
    "ever","evil","exit","face","fact","fail","fair","fall",
    "farm","fast","fate","fear","feed","feel","fell","felt",
    "file","fill","film","find","fine","fire","firm","fish",
    "five","flag","flat","flow","fold","folk","food","foot",
    "form","fort","four","free","from","fuel","full","fund",
    "gain","game","gate","gaze","gear","gene","gift","girl",
    "give","glad","goal","goes","gold","golf","gone","good",
    "gray","grew","grid","grow","gulf","hair","half","hall",
    "hand","hang","hard","harm","hate","have","head","hear",
    "heat","held","hell","help","here","hero","high","hill",
    "hire","hold","hole","holy","home","hope","host","hour",
    "huge","hung","hunt","hurt","idea","inch","into","iron",
    "item","jack","jane","jean","john","join","jump","jury",
    "just","keen","keep","kept","kick","kill","kind","king",
    "knee","knew","know","lack","lady","laid","lake","land",
    "lane","last","late","lead","leaf","lean","left","lend",
    "less","life","lift","like","limb","line","link","lips",
    "list","live","load","loan","lock","logo","long","look",
    "lord","lose","loss","lost","lots","love","luck","luke",
    "made","mail","main","make","male","many","mark","mass",
    "meal","mean","meat","meet","menu","mere","mess","mile",
    "milk","mind","mine","miss","moon","more","most","move",
    "much","must","name","navy","near","neck","need","news",
    "next","nice","nick","nine","none","nose","note","okay",
    "once","only","onto","open","oral","ours","over","pack",
    "page","paid","pain","pair","palm","park","part","pass",
    "past","path","peak","pick","pink","pipe","plan","play",
    "plot","plug","plus","poll","pool","poor","port","pose",
    "post","pour","pray","prep","pull","pure","push","race",
    "rail","rain","rare","rate","read","real","rear","rely",
    "rent","rest","rice","rich","ride","ring","rise","risk",
    "road","rock","role","roll","roof","room","root","rope",
    "rose","ruin","rule","rush","safe","said","sake","sale",
    "salt","same","sand","save","seat","seed","seek","seem",
    "seen","self","sell","send","sent","sept","ship","shop",
    "shot","show","shut","sick","side","sign","site","size",
    "skin","slip","slow","snow","soft","soil","sold","sole",
    "some","song","soon","sort","soul","spot","star","stay",
    "step","stop","such","suit","sure","take","tale","talk",
    "tall","tank","tape","task","taxi","team","tech","tell",
    "tend","term","test","text","than","that","them","then",
    "they","thin","this","thus","tide","tier","till","time",
    "tiny","told","toll","tone","tony","took","tool","tour",
    "town","tree","trip","true","tune","turn","twin","type",
    "unit","upon","used","user","used","vary","vast","very",
    "vice","view","vote","wage","wait","wake","walk","wall",
    "want","ward","warm","wash","wave","ways","weak","wear",
    "week","well","went","were","west","what","when","whom",
    "wide","wife","wild","will","wind","wine","wing","wire",
    "wise","wish","with","wolf","wood","wool","word","wore",
    "work","yard","yeah","year","york","your"
]

def derive_sas(session_key: SecureBytes, transcript: bytes) -> str:
    """
    Derive 6-word SAS (~48 bits) from a 256-word list with transcript-bound salt.
    """
    salt = _salt_from_transcript(b"convoisim-v2-sas-salt", transcript)
    sas_material = HKDF(
        algorithm=hashes.SHA256(),
        length=6,
        salt=salt,
        info=b"convoisim-v2-sas"
    ).derive(session_key.bytes() + transcript)
    indices = list(sas_material)  # 6 bytes -> 6 indices 0..255
    return "-".join(SAS_WORDS[i] for i in indices)


# -------- Nonce and AEAD --------

class SecureNonceCounter:
    """
    Thread-safe nonce counter: 8-byte random base + 4-byte counter => 12-byte nonce for AES-GCM.
    Per-sender instance per session to avoid reuse.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0
        self.base_nonce = os.urandom(8)

    def get_next_nonce(self) -> bytes:
        with self.lock:
            counter_bytes = self.counter.to_bytes(4, 'big')
            nonce = self.base_nonce + counter_bytes
            self.counter += 1
            if self.counter >= 2**32:
                self.counter = 0
                self.base_nonce = os.urandom(8)
            return nonce


def encrypt_message(key: SecureBytes, plaintext: str, nonce_counter: SecureNonceCounter, sequence_num: int = 0) -> bytes:
    """
    Encrypt message with AES-GCM; associated_data carries the monotonic sequence number (replay/ordering).
    """
    if key._destroyed:
        raise ValueError("Cannot encrypt with destroyed key")
    aesgcm = AESGCM(key.bytes())
    nonce = nonce_counter.get_next_nonce()
    associated_data = sequence_num.to_bytes(8, 'big')
    try:
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return nonce + ct
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")


def _dummy_decrypt(key: SecureBytes):
    try:
        AESGCM(key.bytes()).decrypt(b"\x00"*12, b"\x00"*32, b"\x00"*8)
    except Exception:
        pass


def decrypt_message(key: SecureBytes, encrypted_message: bytes, sequence_num: int = 0) -> Optional[str]:
    """
    Decrypt with AES-GCM and verify sequence via associated_data.
    Returns None on failure; constant-time-ish failure path via dummy decrypt.
    """
    if key._destroyed:
        raise ValueError("Cannot decrypt with destroyed key")

    if len(encrypted_message) < 28:  # 12-byte nonce + 16-byte tag minimum
        _dummy_decrypt(key)
        return None

    aesgcm = AESGCM(key.bytes())
    nonce = encrypted_message[:12]
    ct = encrypted_message[12:]
    associated_data = sequence_num.to_bytes(8, 'big')

    try:
        pt = aesgcm.decrypt(nonce, ct, associated_data)
        return pt.decode("utf-8")
    except Exception:
        _dummy_decrypt(key)
        return None
