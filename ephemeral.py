#!/usr/bin/env python3
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
import struct
import platform
import atexit
import signal
import socks
import re

from crypto_core import (
    generate_keys,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_key_with_context,
    derive_sas,
    encrypt_message,
    decrypt_message,
    SecureNonceCounter,
    SecureBytes
)
from cryptography.hazmat.primitives import serialization

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
    """
    Read exactly one PEM public key block, error immediately on invalid format.
    """
    print(f"\n{prompt}")
    header = sys.stdin.readline().strip()
    if header != "-----BEGIN PUBLIC KEY-----":
        print("[!] Invalid PEM header; returning to menu.")
        return None
    lines = [header]
    for _ in range(1000):
        line = sys.stdin.readline().rstrip("\r\n")
        lines.append(line)
        if line == "-----END PUBLIC KEY-----":
            pem = "\n".join(lines) + "\n"
            return pem.encode()
    print("[!] PEM did not terminate correctly; returning to menu.")
    return None

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
    os.makedirs(hs, mode=0o700)
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
        print("[!] Tor executable not found.")
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None, None

    _last_tor_proc = proc
    hostname_path = os.path.join(hs, "hostname")
    for _ in range(60):
        if os.path.exists(hostname_path):
            onion = open(hostname_path).read().strip()
            time.sleep(2)
            return proc, onion, tmp
        time.sleep(1)

    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
    print("[!] Timeout creating hidden service")
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
        while not stop.is_set():
            data = sock.recv(4096)
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
            print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
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
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc:
        return

    print(f"\nShare this with your peer:\n  Onion Address: {onion}\n  Port: {port}\n")

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    host_pem = serialize_public_key(pub)
    print(host_pem.decode())

    peer_pem = read_pem_from_stdin("Paste peer PUBLIC KEY PEM:")
    if not peer_pem:
        return
    try:
        peer_pub = deserialize_public_key(peer_pem)
    except ValueError as e:
        print(f"[!] {e}")
        return

    host_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_der = peer_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    transcript = build_transcript(host_der, client_der, onion, port)
    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print(f"\nVerification code: {sas}\nConfirm over secure channel.")
    if input("Proceed? (yes/no): ").strip().lower() != "yes":
        print("Aborted.")
        return

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    conn, _ = listener.accept()
    handle_chat(conn, session_key, nonce_ctr)
    listener.close()
    print("Host session ended.")

def run_client():
    print("\n=== Client Mode ===")
    onion = input("Onion address: ").strip()
    if not strict_onion_v3_check(onion):
        print("[!] Invalid .onion v3 address.")
        return
    port = validate_port(input("Port: ").strip())
    if not port:
        print("[!] Invalid port number.")
        return

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    client_pem = serialize_public_key(pub)
    print(client_pem.decode())

    peer_pem = read_pem_from_stdin("Paste host PUBLIC KEY PEM:")
    if not peer_pem:
        return
    try:
        peer_pub = deserialize_public_key(peer_pem)
    except ValueError as e:
        print(f"[!] {e}")
        return

    host_der = peer_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    transcript = build_transcript(host_der, client_der, onion, port)
    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print(f"\nVerification code: {sas}\nConfirm over secure channel.")
    if input("Proceed? (yes/no): ").strip().lower() != "yes":
        print("Aborted.")
        return

    if not is_listening("127.0.0.1", 9050):
        subprocess.Popen(
            ["tor", "SocksPort", "9050"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    s.connect((onion, port))
    handle_chat(s, session_key, nonce_ctr)
    print("Client session ended.")

def main_menu():
    print("Welcome to Convoisum!\n")
    while True:
        choice = input("Host(h)/Join(j)/Quit(q): ").strip().lower()
        if choice == "h":
            run_host()
        elif choice == "j":
            run_client()
        elif choice == "q":
            break

if __name__ == "__main__":
    try:
        main_menu()
    except SystemExit:
        pass
