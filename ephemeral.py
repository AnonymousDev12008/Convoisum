
"""
Convoisum – Privacy-focused ephemeral peer-to-peer chat over Tor v3
"""

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
import socks
import re
import select

import pyperclip

from crypto_core import (
    generate_keys,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key_with_context,
    derive_sas,
    encrypt_message,
    decrypt_message,
    SecureNonceCounter,
)
from cryptography.hazmat.primitives import serialization

DEBUG = False  # Toggle detailed debug output

MAX_MESSAGE_LENGTH = 512  # Limit max message length to prevent DoS

# --- Helpers & Cleanup -------------------------------------------------------

_last_tmp_dir = None
_last_tor_proc = None

def cleanup():
    if _last_tor_proc:
        _last_tor_proc.terminate()
    if _last_tmp_dir and os.path.isdir(_last_tmp_dir):
        shutil.rmtree(_last_tmp_dir, ignore_errors=True)

atexit.register(cleanup)
for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, lambda *_: sys.exit(0))

def strict_onion_v3_check(addr):
    return bool(re.fullmatch(r"[a-z2-7]{56}\.onion", addr.strip().lower()))

def validate_port(s):
    try:
        p = int(s)
        return p if 1024 <= p <= 65535 else None
    except:
        return None

def read_pem_from_stdin(prompt):
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

def is_listening(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

# --- Tor Helpers -------------------------------------------------------------

def start_tor_hidden_service(local_port):
    global _last_tmp_dir, _last_tor_proc
    tmp = tempfile.mkdtemp(prefix="convoisum_")
    os.chmod(tmp, 0o700)
    _last_tmp_dir = tmp
    hs = os.path.join(tmp, "hs")
    os.makedirs(hs, 0o700)
    torrc = os.path.join(tmp, "torrc")
    with open(torrc, "w") as f:
        f.write(f"""
SocksPort 9050
HiddenServiceDir {hs}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
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
            onion = open(hostname).read().strip()
            time.sleep(2)
            return proc, onion, tmp
        if i % 10 == 0:
            print(f"[Info] Waiting for Tor HS... {i+1}s elapsed")
        time.sleep(1)
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
    print("[!] HS creation timeout")
    return None, None, None

# --- Chat Logic --------------------------------------------------------------

def build_transcript(host_der, client_der, onion, port):
    return host_der + client_der + onion.encode() + port.to_bytes(2, "big")

def handle_chat(sock, session_key, nonce_ctr):
    stop = threading.Event()
    seq_send = 0
    seq_recv = 0
    seen = set()

    def recv_loop():
        nonlocal seq_recv
        sock.setblocking(True)
        while not stop.is_set():
            try:
                if DEBUG: print("[Debug] waiting for data...")
                data = sock.recv(4096)
                if DEBUG: print(f"[Debug] got {len(data)} bytes")
            except ConnectionResetError:
                print("\n[!] Connection reset by peer")
                stop.set()
                return
            except Exception as e:
                print(f"\n[!] recv error: {e}")
                stop.set()
                return
            if not data:
                print("\n[!] Peer disconnected")
                stop.set()
                return
            if seq_recv in seen:
                continue
            msg = decrypt_message(session_key, data, seq_recv)
            if msg is None:
                print("\n[!] Decryption failed")
                stop.set()
                return
            print(f"\nPeer: {msg}\n")
            print("You: ", end="", flush=True)
            if msg.strip().lower() == "exit":
                stop.set()
                return
            seen.add(seq_recv)
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
        sock.sendall(encrypt_message(session_key, msg, nonce_ctr, seq_send))
        if msg.strip().lower() == "exit":
            print("\n[Info] You exited the chat.")
            stop.set()
        seq_send += 1
    sock.close()
    print("\n[Info] Chat session ended.\n")

def run_host():
    print("\n=== Host Mode ===")
    port = random.randint(15000, 20000)
    print("[Info] Starting Tor HS... please wait")
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc: return
    print("[Success] HS ready\n")
    print("[Warning] THIS IS YOUR PUBLIC KEY PEM. SHARE IT WITH YOUR PEER ONLY VIA A SECURE CHANNEL (e.g., video call) TO PREVENT MAN-IN-THE-MIDDLE ATTACKS.\n")
    print(f"Onion address: {onion}")
    print(f"Port: {port}")
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()
    try:
        pyperclip.copy(pem)
        print("\n[Info] PEM copied to clipboard\n")
    except:
        print("\n[Warning] Failed to copy PEM to clipboard, please copy manually\n")
    print(pem)
    peer_pem = read_pem_from_stdin("Paste peer PUBLIC KEY PEM:")
    if not peer_pem: return
    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified\n")
    except ValueError as e:
        print(f"[Error] {e}\n")
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
        return
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
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
                try: listener.close()
                except: pass
                print("[Info] Host cancelled\n")
    threading.Thread(target=cancel_monitor, daemon=True).start()
    try:
        conn, _ = listener.accept()
        print("[Info] Peer connected. Starting chat session.\n")
    except Exception:
        if stop_flag.is_set(): return
        print("[Error] Listener error\n")
        return
    stop_flag.set()
    handle_chat(conn, session_key, nonce_ctr)

def run_client():
    print("\n=== Client Mode ===")
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
                if is_listening("127.0.0.1", 9050): break
                time.sleep(1)
            else:
                print("[Warning] Timeout waiting for Tor proxy\n")
        except FileNotFoundError:
            print("[!] Tor not found; start manually\n")
            return
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()
    try:
        pyperclip.copy(pem)
        print("\n[Info] PEM copied to clipboard\n")
    except:
        print("\n[Warning] Copy failed, copy manually\n")
    print(pem)
    peer_pem = read_pem_from_stdin("Paste host PUBLIC KEY PEM:")
    if not peer_pem: return
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
        except Exception as e:
            connect_err = e
            break
        # Check for cancel typed
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
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
        return
    if not stop:
        handle_chat(s, session_key, nonce_ctr)

def main_menu():
    while True:
        print("""
===== Convoisum =====       
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
