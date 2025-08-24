# Convoisim-v2 ephemeral.py

import os
import sys
import socket
import threading
import tempfile
import subprocess
import time
import random
import shutil
import platform
import atexit
import signal
import re
import select
from typing import Optional, Tuple, List

import socks  # PySocks
try:
    import pyperclip
except Exception:
    pyperclip = None

from cryptography.hazmat.primitives import serialization

from crypto_core import (
    generate_keys,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key_with_context,
    derive_sas,
    encrypt_message,
    decrypt_message,
    SecureNonceCounter,
    SecureBytes,
)

DEBUG = False
USE_CLIPBOARD = False  # Default off for safety
MAX_MESSAGE_LENGTH = 512

_last_tmp_dir = None
_last_tor_proc = None


# -------- Cleanup and signals --------

def cleanup():
    global _last_tor_proc, _last_tmp_dir
    if _last_tor_proc:
        try:
            _last_tor_proc.terminate()
        except Exception:
            pass
    if _last_tmp_dir and os.path.isdir(_last_tmp_dir):
        shutil.rmtree(_last_tmp_dir, ignore_errors=True)

atexit.register(cleanup)
for sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(sig, lambda *_: sys.exit(0))
    except Exception:
        pass


# -------- Validation helpers --------

def strict_onion_v3_check(addr: str) -> bool:
    return bool(re.fullmatch(r"[a-z2-7]{56}\.onion", addr.strip().lower()))

def validate_port(s: str) -> Optional[int]:
    try:
        p = int(s)
        return p if 1024 <= p <= 65535 else None
    except Exception:
        return None

def read_pem_from_stdin(prompt: str) -> Optional[bytes]:
    while True:
        print(f"\n{prompt} (enter full PEM block including headers or type 'cancel' to abort)")
        lines = []
        while True:
            line = sys.stdin.readline()
            if not line:
                print("[!] Incomplete PEM; returning to menu.")
                return None
            line = line.rstrip("\r\n")
            if line.lower() == "cancel":
                print("[Info] Input cancelled. Returning to main menu.\n")
                return None
            lines.append(line)
            if line == "-----END PUBLIC KEY-----":
                break
        pem = "\n".join(lines) + "\n"
        if not pem.startswith("-----BEGIN PUBLIC KEY-----"):
            print("[Error] Invalid PEM format. Please try again or type 'cancel' to abort.\n")
            continue
        return pem.encode()

def is_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# -------- Framing (length-prefixed messages) --------

def send_frame(sock: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(4, 'big')
    sock.sendall(header + data)

def recv_frames(sock: socket.socket, buffer: bytearray) -> Optional[List[bytes]]:
    frames = []
    chunk = sock.recv(4096)
    if not chunk:
        return None  # peer closed
    buffer.extend(chunk)
    while True:
        if len(buffer) < 4:
            break
        length = int.from_bytes(buffer[:4], 'big')
        if length < 0 or length > 10_000_000:
            raise ValueError("Invalid frame length")
        if len(buffer) < 4 + length:
            break
        frame = bytes(buffer[4:4+length])
        del buffer[:4+length]
        frames.append(frame)
    return frames


# -------- Tor helpers (hardened) --------

def start_tor_hidden_service(local_port: int):
    """
    Hardened torrc:
    - No SocksPort (avoids conflicts with existing Tor)
    - ClientOnly 1
    """
    global _last_tmp_dir, _last_tor_proc
    tmp = tempfile.mkdtemp(prefix="convoisim_v2_")
    os.chmod(tmp, 0o700)
    _last_tmp_dir = tmp
    hs = os.path.join(tmp, "hs")
    os.makedirs(hs, 0o700)
    torrc = os.path.join(tmp, "torrc")
    with open(torrc, "w") as f:
        f.write(f"""
HiddenServiceDir {hs}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
ClientOnly 1
""")
    try:
        proc = subprocess.Popen(
            ["tor", "-f", torrc],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=not platform.system().lower().startswith("win")
        )
    except FileNotFoundError:
        print("[!] Tor not found.")
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None, None

    hostname = os.path.join(hs, "hostname")
    for i in range(120):
        if os.path.exists(hostname):
            try:
                onion = open(hostname).read().strip()
            except Exception:
                onion = None
            time.sleep(2)
            _last_tor_proc = proc
            return proc, onion, tmp
        if i % 10 == 0:
            print(f"[Info] Waiting for Tor HS... {i+1}s elapsed")
        time.sleep(1)

    try:
        proc.terminate()
    except Exception:
        pass
    shutil.rmtree(tmp, ignore_errors=True)
    print("[!] HS creation timeout")
    return None, None, None


# -------- Transcript binding --------

def build_transcript(host_der: bytes, client_der: bytes, onion: str, port: int) -> bytes:
    """
    Directional transcript: host DER || client DER || onion || port(2B big-endian)
    """
    return host_der + client_der + onion.encode() + port.to_bytes(2, "big")


# -------- Chat logic (strict sequencing + framing) --------

def handle_chat(sock: socket.socket, session_key: SecureBytes, nonce_ctr: SecureNonceCounter):
    """
    Strict in-order, framed chat:
    - Frames are length-prefixed.
    - Sequence numbers are per-direction, strictly monotonic (0,1,2,...).
    - Associated data in AEAD binds the sequence.
    """
    stop = threading.Event()
    seq_send = 0
    seq_recv = 0
    recv_buffer = bytearray()

    def recv_loop():
        nonlocal seq_recv
        sock.setblocking(True)
        while not stop.is_set():
            try:
                frames = recv_frames(sock, recv_buffer)
                if frames is None:
                    print("\n[!] Peer disconnected")
                    stop.set()
                    return
            except ConnectionResetError:
                print("\n[!] Connection reset by peer")
                stop.set()
                return
            except Exception as e:
                print(f"\n[!] recv error: {e}")
                stop.set()
                return

            for data in frames:
                # Decrypt with expected sequence number
                msg = decrypt_message(session_key, data, seq_recv)
                if msg is None:
                    print("\n[!] Decryption failed or out-of-order/replay detected")
                    stop.set()
                    return
                print(f"\nPeer: {msg}\n")
                print("You: ", end="", flush=True)
                if msg.strip().lower() == "exit":
                    stop.set()
                    return
                seq_recv += 1

    threading.Thread(target=recv_loop, daemon=True).start()

    while not stop.is_set():
        try:
            msg = input("You: ")
        except (EOFError, KeyboardInterrupt):
            print("\n[Info] Exiting chat.")
            stop.set()
            break

        if msg.strip().lower() == "cancel":
            print("[Info] Chat cancelled.")
            stop.set()
            break

        if len(msg) > MAX_MESSAGE_LENGTH:
            print(f"[Error] Message too long (max {MAX_MESSAGE_LENGTH} chars). Please shorten.")
            continue

        ct = encrypt_message(session_key, msg, nonce_ctr, seq_send)
        send_frame(sock, ct)

        if msg.strip().lower() == "exit":
            print("\n[Info] You exited the chat.")
            stop.set()

        seq_send += 1

    try:
        sock.close()
    except Exception:
        pass
    print("\n[Info] Chat session ended.\n")


# -------- Host/client flows --------

def _prebind_local_listener() -> Tuple[Optional[socket.socket], Optional[int]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = None
    for _ in range(30):
        p = random.randint(15000, 20000)
        try:
            listener.bind(("127.0.0.1", p))
            port = p
            break
        except OSError:
            continue
    if port is None:
        try:
            listener.close()
        except Exception:
            pass
        return None, None
    listener.listen(1)
    return listener, port


def run_host():
    print("\n=== Host Mode (Convoisim-v2) ===")

    # Pre-bind port before creating HS to avoid conflicts
    listener, port = _prebind_local_listener()
    if listener is None:
        print("[Error] Could not find an available local port")
        return

    print("[Info] Starting Tor HS... please wait")
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc or not onion:
        try:
            listener.close()
        except Exception:
            pass
        return
    print("[Success] HS ready\n")

    print("[Warning] THIS IS YOUR PUBLIC KEY PEM. SHARE IT SECURELY ONLY (e.g., video call).")
    print(f"Onion address: {onion}")
    print(f"Port: {port}")

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()

    if USE_CLIPBOARD and pyperclip:
        try:
            pyperclip.copy(pem)
            print("\n[Info] PEM copied to clipboard\n")
        except Exception:
            print("\n[Warning] Failed to copy PEM to clipboard, please copy manually\n")
    else:
        print("\n[Info] Clipboard copy disabled or unavailable\n")

    print(pem)

    peer_pem = read_pem_from_stdin("Paste peer PUBLIC KEY PEM:")
    if not peer_pem:
        try:
            listener.close()
        except Exception:
            pass
        return

    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified\n")
    except ValueError as e:
        print(f"[Error] {e}\n")
        try:
            listener.close()
        except Exception:
            pass
        return

    transcript = build_transcript(
        pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        peer_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        onion, port
    )

    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print(f"SAS: {sas}")
    if input("[Prompt] Proceed? (yes/no): ").strip().lower() != "yes":
        print("[Info] Aborted\n")
        try:
            listener.close()
        except Exception:
            pass
        return

    print("[Info] Waiting for peer (type 'cancel' to abort):")
    stop_flag = threading.Event()

    def cancel_monitor():
        while not stop_flag.is_set():
            try:
                cmd = sys.stdin.readline()
            except EOFError:
                break
            if cmd.strip().lower() == "cancel":
                stop_flag.set()
                try:
                    listener.close()
                except Exception:
                    pass
                print("[Info] Host cancelled\n")
                break

    threading.Thread(target=cancel_monitor, daemon=True).start()
    try:
        conn, _ = listener.accept()
        print("[Info] Peer connected. Starting chat session.\n")
    except Exception:
        if stop_flag.is_set():
            return
        print("[Error] Listener error\n")
        return
    finally:
        stop_flag.set()
        try:
            listener.close()
        except Exception:
            pass

    handle_chat(conn, session_key, nonce_ctr)


def run_client():
    print("\n=== Client Mode (Convoisim-v2) ===")
    onion = input("[Prompt] Host Onion (.onion): ").strip()
    if onion.lower() == "cancel":
        print("[Info] Cancelled\n")
        return
    if not strict_onion_v3_check(onion):
        print("[Error] Invalid onion\n")
        return

    port_s = input("[Prompt] Host port: ").strip()
    if port_s.lower() == "cancel":
        print("[Info] Cancelled\n")
        return
    port = validate_port(port_s)
    if not port:
        print("[Error] Invalid port\n")
        return

    if not is_listening("127.0.0.1", 9050):
        print("[Info] Starting Tor... please wait")
        try:
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                if is_listening("127.0.0.1", 9050):
                    break
                time.sleep(1)
            else:
                print("[Warning] Timeout waiting for Tor proxy\n")
        except FileNotFoundError:
            print("[!] Tor not found; start manually\n")
            return

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()

    if USE_CLIPBOARD and pyperclip:
        try:
            pyperclip.copy(pem)
            print("\n[Info] PEM copied to clipboard\n")
        except Exception:
            print("\n[Warning] Copy failed, copy manually\n")
    else:
        print("\n[Info] Clipboard copy disabled or unavailable\n")

    print(pem)

    peer_pem = read_pem_from_stdin("Paste host PUBLIC KEY PEM:")
    if not peer_pem:
        return

    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified\n")
    except ValueError as e:
        print(f"[Error] {e}\n")
        return

    transcript = build_transcript(
        peer_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        onion, port
    )

    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print(f"SAS: {sas}")
    if input("[Prompt] Proceed? (yes/no): ").strip().lower() != "yes":
        print("[Info] Aborted\n")
        return

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    s.settimeout(10.0)
    s.setblocking(True)
    print("[Info] Connecting to peer... (type 'cancel' to abort)")
    connect_err = None
    stop = False

    while True:
        try:
            s.connect((onion, port))
            print("[Info] Connected! Start typing messages. Type 'exit' to quit.\n")
            break
        except BlockingIOError:
            pass
        except socket.timeout:
            connect_err = socket.timeout("Connection timed out")
            break
        except Exception as e:
            connect_err = e
            break

        # Check for cancel typed
        try:
            rlist, _, _ = select.select([sys.stdin], [], [], 0)
        except Exception:
            rlist = []
        if sys.stdin in rlist:
            cmd = sys.stdin.readline().strip().lower()
            if cmd == "cancel":
                stop = True
                print("[Info] Connection cancelled\n")
                break
        if stop:
            break
        time.sleep(0.2)

    if connect_err:
        print(f"[Error] Connection failed: {connect_err}\n")
        try:
            s.close()
        except Exception:
            pass
        return

    if not stop:
        handle_chat(s, session_key, nonce_ctr)


# -------- Main menu --------

def main_menu():
    while True:
        print("""
===== Convoisim-v2 =====
Hide | Chat | Erase | Repeat

[h] Host  [j] Join  [q] Quit
""")
        choice = input("Choice: ").strip().lower()
        if choice == "h":
            run_host()
        elif choice == "j":
            run_client()
        elif choice == "q":
            print("[Info] Goodbye!\n")
            break
        else:
            print("[Error] Enter 'h', 'j', or 'q'\n")


if __name__ == "__main__":
    main_menu()
