# ephemeral.py

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
import socks

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

# Tor & SOCKS config
TOR_SOCKS_ADDR = os.getenv("TOR_SOCKS_ADDR", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_PATH       = os.getenv("TOR_PATH", "tor")
TOR_TORRC      = os.getenv("TOR_TORRC", "")

def canonical_pubkey_bytes(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def validate_onion_address(addr):
    if not addr or not addr.strip().lower().endswith(".onion"):
        return False
    a = addr.strip().lower()
    if len(a) != 62: return False
    return all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in a[:-6])

def validate_port(s):
    try:
        p = int(s)
        return p if 1024 <= p <= 65535 else None
    except:
        return None

def read_pem_from_stdin(prompt):
    print(f"\n{prompt}")
    lines, began = [], False
    while True:
        line = sys.stdin.readline()
        if line == "": break
        l = line.rstrip("\r\n")
        if not began:
            if "BEGIN PUBLIC KEY" in l:
                began = True
                lines.append(l)
        else:
            if l == "": break
            lines.append(l)
    text = "\n".join(lines).strip()
    if "BEGIN PUBLIC KEY" not in text:
        return None
    return (text + "\n").encode()

def is_listening(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout): return True
    except: return False

def start_tor_hidden_service(local_port):
    tmp = tempfile.mkdtemp(prefix="torchat_host_")
    hs = os.path.join(tmp, "hs")
    os.makedirs(hs, mode=0o700, exist_ok=True)
    torrc = os.path.join(tmp, "torrc")
    with open(torrc, "w") as f:
        f.write(f"""
SocksPort {TOR_SOCKS_PORT}
HiddenServiceDir {hs}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
""")
    try:
        proc = subprocess.Popen(
            [TOR_PATH, "-f", torrc] if TOR_TORRC else [TOR_PATH, "-f", torrc],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=not platform.system().lower().startswith("win")
        )
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        print("[!] Tor not found")
        return None, None, None
    hostname = os.path.join(hs, "hostname")
    for _ in range(60):
        if os.path.exists(hostname):
            addr = open(hostname).read().strip()
            time.sleep(2)
            return proc, addr, tmp
        time.sleep(1)
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
    print("[!] Timeout creating hidden service")
    return None, None, None

def ensure_tor_running_for_client():
    if is_listening(TOR_SOCKS_ADDR, TOR_SOCKS_PORT):
        return None, False
    try:
        args = [TOR_PATH] + (["-f", TOR_TORRC] if TOR_TORRC else ["SocksPort", str(TOR_SOCKS_PORT)])
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=not platform.system().lower().startswith("win"))
    except Exception as e:
        print(f"[!] Tor launch failed: {e}")
        return None, False
    for _ in range(20):
        time.sleep(0.5)
        if is_listening(TOR_SOCKS_ADDR, TOR_SOCKS_PORT):
            return proc, True
    return proc, True

def build_transcript(host_der, client_der, onion, port):
    timestamp = struct.pack(">Q", int(time.time()))
    salt = os.urandom(32)
    return host_der + client_der + onion.encode("ascii") + port.to_bytes(2,"big") + timestamp + salt

def handle_chat(sock, session_key, nonce_ctr):
    stop = threading.Event()
    def recv_loop():
        while not stop.is_set():
            try:
                data = sock.recv(4096)
                if not data:
                    print("\n[!] Peer disconnected")
                    stop.set(); break
                msg = decrypt_message(session_key, data)
                if msg is None:
                    print("\n[!] Decryption failed"); stop.set(); break
                print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
                if msg.strip().lower()=="exit":
                    stop.set(); break
            except:
                stop.set(); break
    threading.Thread(target=recv_loop, daemon=True).start()
    while not stop.is_set():
        try:
            msg = input("You: ")
        except:
            stop.set(); break
        if msg.strip().lower()=="exit":
            sock.sendall(encrypt_message(session_key, msg, nonce_ctr))
            stop.set(); break
        sock.sendall(encrypt_message(session_key, msg, nonce_ctr))
    sock.close()

def run_host():
    print("=== HOST MODE ===")
    port = random.randint(15000,20000)
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc: return
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    print(f"Onion: {onion} Port: {port}")
    host_pem = serialize_public_key(pub)
    print(host_pem.decode())
    peer_pem = read_pem_from_stdin("Paste peer PEM:")
    if not peer_pem: return
    peer_pub = deserialize_public_key(peer_pem)
    host_der = canonical_pubkey_bytes(pub)
    client_der = canonical_pubkey_bytes(peer_pub)
    transcript = build_transcript(host_der, client_der, onion, port)
    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print("\n" + "="*50)
    print(f"Verification code: {sas}")
    print("Compare over secure channel")
    print("="*50)
    if input("Confirm (yes/no): ").strip().lower()!="yes":
        print("Security fail"); return
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    try:
        conn, _ = listener.accept()
        handle_chat(conn, session_key, nonce_ctr)
    except socket.timeout:
        pass
    finally:
        listener.close()
        proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
        print("Host session ended")

def run_client():
    print("=== CLIENT MODE ===")
    onion = input("Onion address: ").strip()
    if not validate_onion_address(onion): return
    port = validate_port(input("Port: ").strip())
    if not port: return
    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    client_pem = serialize_public_key(pub)
    print(client_pem.decode())
    peer_pem = read_pem_from_stdin("Paste host PEM:")
    if not peer_pem: return
    peer_pub = deserialize_public_key(peer_pem)
    host_der = canonical_pubkey_bytes(peer_pub)
    client_der = canonical_pubkey_bytes(pub)
    transcript = build_transcript(host_der, client_der, onion, port)
    session_key = derive_shared_key_with_context(priv, peer_pub, transcript)
    sas = derive_sas(session_key, transcript)
    print("\n" + "="*50)
    print(f"Verification code: {sas}")
    print("="*50)
    if input("Confirm (yes/no): ").strip().lower()!="yes":
        print("Security fail"); return
    proc, started = ensure_tor_running_for_client()
    s = None
    for _ in range(20):
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, TOR_SOCKS_ADDR, TOR_SOCKS_PORT)
            s.connect((onion, port))
            break
        except:
            time.sleep(1)
    if not s:
        print("Connection failed"); return
    handle_chat(s, session_key, nonce_ctr)
    if proc and started:
        proc.terminate()
    print("Client session ended")

def main_menu():
    while True:
        choice = input("Host(h)/Join(j)/Quit(q): ").strip().lower()
        if choice=="h":
            run_host()
        elif choice=="j":
            run_client()
        elif choice=="q":
            break

if __name__=="__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted")
