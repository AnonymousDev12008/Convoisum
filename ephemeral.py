
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
    print(f"\n{prompt}")
    print("(Enter full PEM block, including BEGIN/END headers)")
    lines = []
    while True:
        line = sys.stdin.readline()
        if not line:
            print("[!] EOF without complete PEM; returning to menu.")
            return None
        line = line.rstrip("\r\n")
        lines.append(line)
        if line == "-----END PUBLIC KEY-----":
            break
    pem_str = "\n".join(lines) + "\n"
    if not pem_str.startswith("-----BEGIN PUBLIC KEY-----"):
        print("[!] Invalid PEM header; returning to menu.")
        return None
    return pem_str.encode()

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
    for i in range(120):
        if os.path.exists(hostname_path):
            onion = open(hostname_path).read().strip()
            time.sleep(2)
            return proc, onion, tmp
        if i % 10 == 0:
            print(f"[Info] Waiting for Tor hidden service deployment... {i+1} seconds elapsed")
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
            try:
                data = sock.recv(4096)
            except Exception:
                print("\n[!] Connection error or peer disconnected")
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
            print("\n[Info] Input interrupted, exiting chat.")
            stop.set()
            break
        if msg.strip().lower() == "cancel":
            print("[Info] Cancel command received, stopping chat session.")
            stop.set()
            break
        sock.sendall(encrypt_message(session_key, msg, nonce_ctr, seq_send))
        if msg.strip().lower() == "exit":
            stop.set()
        seq_send += 1
    sock.close()

def run_host():
    print("\n--- Hosting a new chat session ---")
    port = random.randint(15000, 20000)
    print("[Info] Creating your Tor hidden service... please wait.")
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc:
        return

    print("\n[Success] Hidden service created successfully!\n")
    print("[Connection Info] Share securely with your peer:")
    print(f"  - Onion address: {onion}")
    print(f"  - Port: {port}\n")

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    host_pem = serialize_public_key(pub)
    pem_text = host_pem.decode()

    try:
        pyperclip.copy(pem_text)
        print("[Info] Your public key PEM has been copied to clipboard for sharing.\n")
    except Exception:
        print("[Warning] Failed to copy to clipboard, please copy manually:\n")

    print(pem_text)

    peer_pem = read_pem_from_stdin("Paste your peer's public key PEM:")
    if not peer_pem:
        return
    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified.")
    except ValueError as e:
        print(f"[!] Failed to deserialize public key: {e}")
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
    print(f"\n[SAS] Verification code for confirmation:\n  {sas}\n")
    confirm = input("[Prompt] Proceed? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[Info] Session aborted. Returning to main menu.")
        return

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    print("[Info] Waiting for a peer to connect... (type 'cancel' to abort)")

    stop_flag = threading.Event()

    def input_monitor():
        while not stop_flag.is_set():
            try:
                cmd = input()
            except EOFError:
                break
            if cmd.strip().lower() == "cancel":
                print("[Info] Host cancelled. Closing listener.")
                stop_flag.set()
                try:
                    listener.close()
                except Exception:
                    pass
                break

    thread = threading.Thread(target=input_monitor, daemon=True)
    thread.start()

    try:
        conn, _ = listener.accept()
        print("[Info] Peer connected. Starting chat session.")
    except Exception:
        if stop_flag.is_set():
            return
        else:
            print("[Error] Listener encountered an exception.")
            return

    stop_flag.set()
    handle_chat(conn, session_key, nonce_ctr)
    print("[Info] Host session ended.")

def run_client():
    print("\n--- Join an existing chat session ---")
    onion = input("[Prompt] Enter host Onion address (.onion): ").strip()
    if onion.lower() == "cancel":
        print("[Info] Operation cancelled. Returning to main menu.")
        return
    if not strict_onion_v3_check(onion):
        print("[Error] Invalid .onion v3 address.")
        return

    port_s = input("[Prompt] Enter host port number: ").strip()
    if port_s.lower() == "cancel":
        print("[Info] Operation cancelled. Returning to main menu.")
        return
    port = validate_port(port_s)
    if not port:
        print("[Error] Invalid port number.")
        return

    if not is_listening("127.0.0.1", 9050):
        print("[Info] Starting Tor locally... please wait.")
        try:
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                if is_listening("127.0.0.1", 9050):
                    break
                time.sleep(1)
            else:
                print("[Warning] Timeout waiting for Tor proxy on port 9050.")
        except FileNotFoundError:
            print("[!] Tor not found; please start Tor manually and retry.")
            return

    priv, pub = generate_keys()
    nonce_ctr = SecureNonceCounter()
    client_pem = serialize_public_key(pub)
    pem_text = client_pem.decode()

    try:
        pyperclip.copy(pem_text)
        print("[Info] Your public key PEM has been copied to clipboard for sharing.\n")
    except Exception:
        print("[Warning] Failed to copy to clipboard, please copy manually:\n")

    print(pem_text)

    peer_pem = read_pem_from_stdin("Paste host's public key PEM:")
    if not peer_pem:
        return
    try:
        peer_pub = deserialize_public_key(peer_pem)
        print("[Success] Public key verified.")
    except ValueError as e:
        print(f"[!] Failed to deserialize public key: {e}")
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
    print(f"\n[SAS] Verification code for confirmation:\n  {sas}\n")
    confirm = input("[Prompt] Proceed? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[Info] Session aborted. Returning to main menu.")
        return

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    s.setblocking(False)
    print("[Info] Connecting to peer... (type 'cancel' to abort)")
    connect_err = None
    while True:
        try:
            s.connect((onion, port))
            print("[Info] Connected! Starting chat. Type 'exit' to leave.")
            break
        except BlockingIOError:
            pass
        except Exception as e:
            connect_err = e
            break
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            cmd = sys.stdin.readline().strip().lower()
            if cmd == "cancel":
                print("[Info] Connection cancelled. Returning to menu.")
                return
        time.sleep(0.2)
    if connect_err:
        print(f"[Error] Could not connect: {connect_err}")
        return

    handle_chat(s, session_key, nonce_ctr)
    print("[Info] Client session ended.")

def main_menu():
    print("""
==========================================
           ========  Convoisum ========
       *** Hide ** Chat ** Erase ** Repeat ***
                   Welcome !!!

Select your action:
  [h] Host a chat session
  [j] Join a chat session
  [q] Quit the program
""")
    while True:
        choice = input("Enter choice (h/j/q): ").strip().lower()
        if choice == "h":
            run_host()
        elif choice == "j":
            run_client()
        elif choice == "q":
            print("[Info] Exiting Convoisum. Goodbye!")
            break
        else:
            print("[Error] Invalid choice, please enter 'h', 'j', or 'q'.\n")

if __name__ == "__main__":
    main_menu()
