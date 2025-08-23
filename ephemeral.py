
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
    print(f"{prompt} (enter full PEM block including headers)")
    lines = []
    while True:
        line = sys.stdin.readline()
        if not line:
            print("[!] Incomplete PEM; returning to menu.")
            return None
        line = line.rstrip("\r\n")
        lines.append(line)
        if line == "-----END PUBLIC KEY-----":
            break
    pem = "\n".join(lines) + "\n"
    if not pem.startswith("-----BEGIN PUBLIC KEY-----"):
        print("[!] Invalid PEM header; returning to menu.")
        return None
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
    _last_tor_proc = proc
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
            print(f"Peer: {msg}")
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
        sock.sendall(encrypt_message(session_key, msg, nonce_ctr, seq_send))
        if msg.strip().lower() == "exit":
            stop.set()
        seq_send += 1
    sock.close()

def run_host():
    print("\n=== Host Mode ===")
    port = random.randint(15000, 20000)
    print("[Info] Starting Tor HS... please wait")
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc: return
    print("[Success] HS ready")
    print(f"Onion: {onion}\nPort: {port}")
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()
    try:
        pyperclip.copy(pem)
        print("[Info] PEM copied to clipboard")
    except:
        print("[Warning] Copy failed; paste manually:")
    print(pem)
    peer_pem = read_pem_from_stdin("Paste peer PUBLIC KEY PEM:")
    if not peer_pem: return
    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified")
    except ValueError as e:
        print(f"[!] {e}")
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
        print("[Info] Aborted"); return
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    print("[Info] Waiting for peer (type 'cancel'):")
    stop_flag = threading.Event()
    def cancel_monitor():
        if input().strip().lower()=="cancel":
            stop_flag.set(); listener.close()
    threading.Thread(target=cancel_monitor, daemon=True).start()
    try:
        conn, _ = listener.accept()
        print("[Info] Peer connected")
    except:
        if stop_flag.is_set(): return
        print("[Error] Listener error"); return
    handle_chat(conn, session_key, nonce_ctr)

def run_client():
    print("\n=== Client Mode ===")
    onion = input("[Prompt] Host Onion (.onion): ").strip()
    if onion.lower()=="cancel": return
    if not strict_onion_v3_check(onion):
        print("[Error] Invalid onion"); return
    port_s = input("[Prompt] Host port: ").strip()
    if port_s.lower()=="cancel": return
    port = validate_port(port_s)
    if not port:
        print("[Error] Invalid port"); return
    if not is_listening("127.0.0.1", 9050):
        print("[Info] Starting Tor..."); 
        try:
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                if is_listening("127.0.0.1",9050): break
                time.sleep(1)
        except FileNotFoundError:
            print("[!] Tor missing"); return
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    pem = serialize_public_key(pub).decode()
    try:
        pyperclip.copy(pem)
        print("[Info] PEM copied to clipboard")
    except:
        print("[Warning] Copy failed; paste manually:")
    print(pem)
    peer_pem = read_pem_from_stdin("Paste host PUBLIC KEY PEM:")
    if not peer_pem: return
    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified")
    except ValueError as e:
        print(f"[!] {e}"); return
    transcript = build_transcript(
        peer_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        onion, port
    )
    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print(f"SAS: {sas}")
    if input("[Prompt] Proceed? (yes/no): ").strip().lower() != "yes":
        print("[Info] Aborted"); return
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    s.setblocking(True)
    print("[Info] Connecting (type 'cancel'):")
    err = None
    while True:
        try:
            s.connect((onion, port)); print("[Info] Connected"); break
        except BlockingIOError: pass
        except Exception as e:
            err = e; break
        if input().strip().lower()=="cancel":
            print("[Info] Cancelled"); return
        time.sleep(0.2)
    if err:
        print(f"[Error] {err}"); return
    handle_chat(s, session_key, nonce_ctr)

def main_menu():
    print("""
===== Convoisum =====
Hide | Chat | Erase | Repeat

[h] Host  [j] Join  [q] Quit
""")
    while True:
        choice = input("Choice: ").strip().lower()
        if choice=="h": run_host()
        elif choice=="j": run_client()
        elif choice=="q": break
        else: print("[Error] Enter 'h','j', or 'q'")

if __name__=="__main__":
    main_menu()
