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

# Import your tested crypto_core functions
from crypto_core import (
    generate_keys,
    serialize_public_key,
    derive_shared_key,
    encrypt_message,
    decrypt_message,
)

TOR_SOCKS_ADDR = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def start_tor_hidden_service(local_port):
    temp_dir = tempfile.mkdtemp(prefix="torchat_host_")
    hs_dir = os.path.join(temp_dir, "hs")
    os.makedirs(hs_dir, exist_ok=True)
    torrc_path = os.path.join(temp_dir, "torrc")
    with open(torrc_path, "w") as f:
        f.write(f"""
SocksPort {TOR_SOCKS_PORT}
HiddenServiceDir {hs_dir}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
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
    for _ in range(60):  # wait up to 60 seconds
        if os.path.exists(onion_path):
            onion_addr = open(onion_path, "r").read().strip()
            print(f"[*] Hidden service ready: {onion_addr} (port {local_port})")
            return tor_proc, onion_addr, temp_dir
        time.sleep(1)
    tor_proc.terminate()
    shutil.rmtree(temp_dir, ignore_errors=True)
    print("[!] Timeout waiting for Tor hidden service.")
    return None, None, None

def handle_client(conn, session_key):
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
                try:
                    msg = decrypt_message(session_key, data)
                    print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
                    if msg.strip().lower() == "exit":
                        print("[*] Peer ended the chat. Closing session.")
                        stop_flag.set()
                        break
                except Exception as e:
                    print(f"\n[!] Decrypt error: {e}")
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
        
        if msg.strip().lower() == "exit":
            stop_flag.set()
            break
        try:
            ct = encrypt_message(session_key, msg)
            conn.sendall(ct)
        except Exception as e:
            print(f"[!] Send error: {e}")
            stop_flag.set()
            break

    conn.close()

def run_host():
    print("====== ephemeral chat: HOST mode ======")
    local_port = random.randint(15000, 20000)
    print(f"[*] Starting chat server on localhost:{local_port}")
    tor_proc, onion_addr, temp_dir = start_tor_hidden_service(local_port)
    if not tor_proc:
        print("[!] Failed to start Tor. Cannot continue.")
        return

    try:
        private_key, public_key = generate_keys()

        print("\n*** Share this .onion address with your peer ***")
        print(onion_addr)
        print(f"Port: {local_port}")

        print("\n*** Share this public key with your peer ***")
        print(serialize_public_key(public_key).decode())

        print("\nPaste peer's public key PEM (end with blank line):")
        peer_lines = []
        while True:
            line = sys.stdin.readline()
            if line.strip() == "":
                break
            peer_lines.append(line)
        peer_pem = "".join(peer_lines).encode()

        try:
            session_key = derive_shared_key(private_key, peer_pem)
        except Exception as e:
            print(f"[!] Failed to derive session key: {e}")
            return

        print("[*] Session key derived. Waiting for a connection...\n")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", local_port))
            s.listen(1)
            conn, addr = s.accept()
            with conn:
                print(f"[*] Peer connected from {addr}")
                handle_client(conn, session_key)

    finally:
        print("\n[*] Cleaning up...")
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
            try:
                msg = decrypt_message(session_key, data)
                print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
                if msg.strip().lower() == "exit":
                    print("[*] Peer ended the chat. Closing session.")
                    stop_flag.set()
                    break
            except Exception as e:
                print(f"\n[!] Decrypt error: {e}")
        except Exception as ex:
            print(f"\n[!] Socket error: {ex}")
            stop_flag.set()
            break

def run_client():
    print("====== ephemeral chat: CLIENT mode ======")
    onion_addr = input("Enter host's .onion address: ").strip()
    try:
        port = int(input("Enter port (shown by host): ").strip())
    except ValueError:
        print("[!] Invalid port.")
        return

    private_key, public_key = generate_keys()

    print("\n*** Send this public key to the host ***")
    print(serialize_public_key(public_key).decode())

    print("\nPaste host's public key PEM (end with blank line):")
    peer_lines = []
    while True:
        line = sys.stdin.readline()
        if line.strip() == "":
            break
        peer_lines.append(line)
    peer_pem = "".join(peer_lines).encode()

    try:
        session_key = derive_shared_key(private_key, peer_pem)
    except Exception as e:
        print(f"[!] Failed to derive session key: {e}")
        return

    print("[*] Session key derived. Connecting...\n")

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, TOR_SOCKS_ADDR, TOR_SOCKS_PORT)

    try:
        s.connect((onion_addr, port))
    except Exception as e:
        print(f"[!] Failed to connect to {onion_addr}:{port} via Tor: {e}")
        return

    stop_flag = threading.Event()
    t = threading.Thread(target=receive_loop, args=(s, session_key, stop_flag), daemon=True)
    t.start()

    try:
        while not stop_flag.is_set():
            try:
                msg = input("You: ")
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Input interrupted, exiting chat.")
                stop_flag.set()
                break
            
            if msg.strip().lower() == "exit":
                stop_flag.set()
                break
            try:
                ct = encrypt_message(session_key, msg)
                s.sendall(ct)
            except Exception as e:
                print(f"[!] Send error: {e}")
                stop_flag.set()
                break
    finally:
        s.close()
        print("\n[*] Client session ended.")

def main_menu():
    print("====== ephemeral chat ======")
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
