import os
import sys
import socket
import threading
import tempfile
import subprocess
import time
import random
import shutil

import socks

from crypto_core import (
    generate_keys,
    serialize_public_key,
    derive_shared_key_with_context,
    derive_sas,
    encrypt_message,
    decrypt_message,
    NonceCounter,
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

TOR_SOCKS_ADDR = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def canonical_pubkey_bytes(pubkey_obj):
    return pubkey_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def validate_onion_address(addr):
    if not addr:
        return False
    addr = addr.strip().lower()
    if not addr.endswith('.onion'):
        return False
    if len(addr) != 62:  # v3 onion length incl. ".onion"
        return False
    base32_part = addr[:-6]
    valid_chars = set('abcdefghijklmnopqrstuvwxyz234567')
    return set(base32_part).issubset(valid_chars)

def validate_port_number(port_str):
    try:
        port = int(port_str.strip())
    except Exception:
        return None
    if 1024 <= port <= 65535:
        return port
    return None

def read_pem_from_stdin(prompt_title="Paste peer's public key PEM (end with blank line):"):
    # Robustly read a PEM block, tolerating a leading newline and extra whitespace
    print(f"\n{prompt_title}")
    lines = []
    saw_begin = False
    while True:
        line = sys.stdin.readline()
        if line == "":  # EOF
            break
        stripped = line.rstrip("\r\n")
        if not saw_begin:
            if stripped == "":
                continue
            if "BEGIN PUBLIC KEY" not in stripped:
                # ignore preface until the BEGIN marker appears
                continue
            saw_begin = True
        if stripped == "" and saw_begin:
            break
        lines.append(stripped)
        if "END PUBLIC KEY" in stripped:
            # allow a blank line right after END marker to finish
            continue
    pem_text = "\n".join(lines).strip()
    if not pem_text or "BEGIN PUBLIC KEY" not in pem_text or "END PUBLIC KEY" not in pem_text:
        return None
    return (pem_text + "\n").encode("ascii", errors="ignore")

def start_tor_hidden_service(local_port):
    temp_dir = tempfile.mkdtemp(prefix="torchat_host_")
    hs_dir = os.path.join(temp_dir, "hs")
    os.makedirs(hs_dir, mode=0o700, exist_ok=True)
    torrc_path = os.path.join(temp_dir, "torrc")

    with open(torrc_path, "w") as f:
        f.write(f"""
SocksPort {TOR_SOCKS_PORT}
HiddenServiceDir {hs_dir}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
""")

    try:
        tor_proc = subprocess.Popen(
            ["tor", "-f", torrc_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        print("[!] Error: Tor executable not found. Make sure Tor is installed and in your PATH.")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None, None

    onion_path = os.path.join(hs_dir, "hostname")
    print("[*] Starting Tor, waiting for hidden service address...")

    for _ in range(60):
        if os.path.exists(onion_path):
            with open(onion_path, "r") as f:
                onion_addr = f.read().strip()
            print(f"[*] Hidden service ready: {onion_addr} (port {local_port})")
            # Tiny grace delay to allow HS to fully publish
            time.sleep(1.0)
            return tor_proc, onion_addr, temp_dir
        time.sleep(1)

    tor_proc.terminate()
    shutil.rmtree(temp_dir, ignore_errors=True)
    print("[!] Timeout waiting for Tor hidden service.")
    return None, None, None

def handle_client(conn, session_key, nonce_counter):
    print("[*] Client connected! Type 'exit' to quit.")
    stop_flag = threading.Event()

    def recv_loop():
        while not stop_flag.is_set():
            try:
                data = conn.recv(4096)
                if not data:
                    print("\n[!] Peer disconnected.")
                    stop_flag.set()
                    break
                msg = decrypt_message(session_key, data)
                if msg is None:
                    print("\n[!] Message decryption failed - possible tampering!")
                    stop_flag.set()
                    break
                print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
                if msg.strip().lower() == "exit":
                    print("[*] Peer ended the chat. Closing session.")
                    stop_flag.set()
                    break
            except Exception as ex:
                print(f"\n[!] Connection error: {ex}")
                stop_flag.set()
                break

    threading.Thread(target=recv_loop, daemon=True).start()

    while not stop_flag.is_set():
        try:
            msg = input("You: ")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Input interrupted, exiting chat.")
            stop_flag.set()
            break

        if len(msg) > 4000:
            print("[!] Message too long (max 4000 chars)")
            continue

        if msg.strip().lower() == "exit":
            stop_flag.set()
            break
        try:
            ct = encrypt_message(session_key, msg, nonce_counter)
            conn.sendall(ct)
        except Exception as e:
            print(f"[!] Send error: {e}")
            stop_flag.set()
            break

    try:
        conn.close()
    except Exception:
        pass

def run_host():
    print("====== ephemeral chat: HOST mode ======")
    local_port = random.randint(15000, 20000)
    print(f"[*] Starting chat server on localhost:{local_port}")

    tor_proc, onion_addr, temp_dir = start_tor_hidden_service(local_port)
    if not tor_proc:
        print("[!] Failed to start Tor. Returning to main menu.")
        return

    listener = None
    try:
        private_key, public_key = generate_keys()
        nonce_counter = NonceCounter()

        print("\n*** Share this .onion address with your peer ***")
        print(onion_addr)
        print(f"Port: {local_port}")

        print("\n*** Share this public key with your peer ***")
        host_pubkey_pem = serialize_public_key(public_key)
        print(host_pubkey_pem.decode())

        peer_pem = read_pem_from_stdin("Paste peer's public key PEM (end with blank line):")
        if not peer_pem:
            print("[!] Invalid or empty PEM input. Returning to main menu.")
            return

        try:
            peer_public_key = load_pem_public_key(peer_pem)
        except Exception as e:
            print(f"[!] Failed to parse peer public key PEM: {e}")
            print("[!] Returning to main menu.")
            return

        # Canonicalize keys and normalize onion/port
        host_der = canonical_pubkey_bytes(public_key)
        client_der = canonical_pubkey_bytes(peer_public_key)
        onion_norm = onion_addr.strip().lower().encode("ascii")
        port_norm = int(local_port).to_bytes(2, "big")

        # Fixed order: host + client + onion + port
        transcript = host_der + client_der + onion_norm + port_norm

        session_key = derive_shared_key_with_context(private_key, peer_public_key, transcript)
        sas = derive_sas(session_key, transcript)

        # Create listener BEFORE prompting SAS so it's ready when client dials
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", local_port))
        listener.listen(1)
        listener.settimeout(300)  # 5 minutes

        # Small grace pause to ensure readiness
        time.sleep(1.0)

        print("\n" + "=" * 50)
        print("*** SECURITY VERIFICATION REQUIRED ***")
        print("=" * 50)
        print(f"Verification code: {sas}")
        print("\nIMPORTANT: Compare this code with your peer over voice/video call.")
        print("This prevents man-in-the-middle attacks.")
        print("=" * 50)

        while True:
            confirmed = input("\nDoes your peer confirm this EXACT code? (yes/no): ").strip().lower()
            if confirmed == "yes":
                break
            elif confirmed == "no":
                print("\n" + "!" * 50)
                print("!!! SECURITY ALERT: Verification FAILED !!!")
                print("!!! POSSIBLE MAN-IN-THE-MIDDLE ATTACK !!!")
                print("!!! DO NOT PROCEED WITH CHAT !!!")
                print("!!! Returning to main menu. !!!")
                print("!" * 50)
                return
            else:
                print("Please enter 'yes' or 'no'")

        print("\n[*] Security verification passed!")
        print("[*] Session key derived. Waiting for a connection...\n")

        try:
            conn, addr = listener.accept()
        except socket.timeout:
            print("[!] Timeout waiting for connection. Returning to main menu.")
            return

        with conn:
            print(f"[*] Peer connected from {addr}")
            handle_client(conn, session_key, nonce_counter)

    finally:
        print("\n[*] Cleaning up...")
        try:
            if listener:
                listener.close()
        except Exception:
            pass
        if tor_proc:
            tor_proc.terminate()
            tor_proc.wait()
        if temp_dir:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        print("[*] Host session ended.")

def receive_loop(sock, session_key, stop_flag):
    while not stop_flag.is_set():
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[!] Peer disconnected.")
                stop_flag.set()
                break
            msg = decrypt_message(session_key, data)
            if msg is None:
                print("\n[!] Message decryption failed - possible tampering!")
                stop_flag.set()
                break
            print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
            if msg.strip().lower() == "exit":
                print("[*] Peer ended the chat. Closing session.")
                stop_flag.set()
                break
        except Exception as ex:
            print(f"\n[!] Socket error: {ex}")
            stop_flag.set()
            break

def run_client():
    print("====== ephemeral chat: CLIENT mode ======")

    onion_addr = input("Enter host's .onion address: ").strip()
    if not validate_onion_address(onion_addr):
        print("[!] Invalid .onion address format. Returning to main menu.")
        return

    port_str = input("Enter port (shown by host): ").strip()
    port = validate_port_number(port_str)
    if port is None:
        print("[!] Invalid port. Must be an integer between 1024-65535.")
        print("[!] Returning to main menu.")
        return

    private_key, public_key = generate_keys()
    nonce_counter = NonceCounter()

    print("\n*** Send this public key to the host ***")
    client_pubkey_pem = serialize_public_key(public_key)
    print(client_pubkey_pem.decode())

    peer_pem = read_pem_from_stdin("Paste host's public key PEM (end with blank line):")
    if not peer_pem:
        print("[!] Invalid or empty PEM input. Returning to main menu.")
        return

    try:
        peer_public_key = load_pem_public_key(peer_pem)
    except Exception as e:
        print(f"[!] Failed to parse host public key PEM: {e}")
        print("[!] Returning to main menu.")
        return

    # Canonicalize keys and normalize onion/port
    host_der = canonical_pubkey_bytes(peer_public_key)
    client_der = canonical_pubkey_bytes(public_key)
    onion_norm = onion_addr.strip().lower().encode("ascii")
    port_norm = int(port).to_bytes(2, "big")

    # Fixed order: host + client + onion + port
    transcript = host_der + client_der + onion_norm + port_norm

    try:
        session_key = derive_shared_key_with_context(private_key, peer_public_key, transcript)
        sas = derive_sas(session_key, transcript)
    except Exception as e:
        print(f"[!] Failed to derive session key: {e}")
        print("[!] Returning to main menu.")
        return

    print("\n" + "=" * 50)
    print("*** SECURITY VERIFICATION REQUIRED ***")
    print("=" * 50)
    print(f"Verification code: {sas}")
    print("\nIMPORTANT: Compare this code with the host over voice/video call.")
    print("This prevents man-in-the-middle attacks.")
    print("=" * 50)

    while True:
        confirmed = input("\nDoes the host confirm this EXACT code? (yes/no): ").strip().lower()
        if confirmed == "yes":
            break
        elif confirmed == "no":
            print("\n" + "!" * 50)
            print("!!! SECURITY ALERT: Verification FAILED !!!")
            print("!!! POSSIBLE MAN-IN-THE-MIDDLE ATTACK !!!")
            print("!!! DO NOT PROCEED WITH CHAT !!!")
            print("!!! Returning to main menu. !!!")
            print("!" * 50)
            return
        else:
            print("Please enter 'yes' or 'no'")

    print("\n[*] Security verification passed!")
    print("[*] Session key derived. Connecting...\n")

    # Retry with fresh SOCKS socket per attempt to avoid Bad file descriptor
    connected_sock = None
    max_tries = 10
    last_error = None
    for attempt in range(1, max_tries + 1):
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, TOR_SOCKS_ADDR, TOR_SOCKS_PORT)
            s.settimeout(30)
            s.connect((onion_addr, port))
            connected_sock = s
            print("[*] Connected to host!")
            break
        except Exception as e:
            last_error = e
            try:
                s.close()
            except Exception:
                pass
            if attempt == max_tries:
                print(f"[!] Failed to connect after {max_tries} tries: {last_error}")
                print("[!] Returning to main menu.")
                return
            time.sleep(1.0)

    stop_flag = threading.Event()
    t = threading.Thread(target=receive_loop, args=(connected_sock, session_key, stop_flag), daemon=True)
    t.start()

    try:
        while not stop_flag.is_set():
            try:
                msg = input("You: ")
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Input interrupted, exiting chat.")
                stop_flag.set()
                break

            if len(msg) > 4000:
                print("[!] Message too long (max 4000 chars)")
                continue

            if msg.strip().lower() == "exit":
                stop_flag.set()
                break
            try:
                ct = encrypt_message(session_key, msg, nonce_counter)
                connected_sock.sendall(ct)
            except Exception as e:
                print(f"[!] Send error: {e}")
                stop_flag.set()
                break
    finally:
        try:
            connected_sock.close()
        except Exception:
            pass
        print("\n[*] Client session ended.")

def main_menu():
    print("====== Convoisum - Ephemeral Tor Chat ======")
    print("Privacy-focused, ephemeral, peer-to-peer chat over Tor")
    print("=" * 48)
    while True:
        choice = input("Host (h), Join (j), Quit (q): ").strip().lower()
        if choice == "h":
            run_host()
        elif choice == "j":
            run_client()
        elif choice == "q":
            print("Goodbye!")
            break
        else:
            print("Invalid input. Please enter 'h', 'j', or 'q'.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")
