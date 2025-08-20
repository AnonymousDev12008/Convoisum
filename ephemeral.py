# updated ephemeral.py with all the critical security fixes


import os
import sys
import socket
import threading
import tempfile
import subprocess
import time
import random
import shutil
import hashlib

import socks

# Import your tested crypto_core functions
from crypto_core import (
    generate_keys,
    serialize_public_key,
    derive_shared_key_with_context,
    derive_sas,
    encrypt_message,
    decrypt_message,
    NonceCounter,
)

# Import PEM loader from cryptography
from cryptography.hazmat.primitives.serialization import load_pem_public_key

TOR_SOCKS_ADDR = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def validate_onion_address(addr):
    """Validate .onion address format"""
    if not addr.endswith('.onion'):
        return False
    if len(addr) != 62:  # v3 onion length including .onion
        return False
    # Basic base32 validation (simplified)
    try:
        base32_part = addr[:-6]  # Remove .onion
        # Check if it contains only valid base32 chars
        valid_chars = set('abcdefghijklmnopqrstuvwxyz234567')
        if not set(base32_part.lower()).issubset(valid_chars):
            return False
        return True
    except:
        return False

def validate_port(port):
    """Validate port range"""
    return 1024 <= port <= 65535

def start_tor_hidden_service(local_port):
    temp_dir = tempfile.mkdtemp(prefix="torchat_host_")
    hs_dir = os.path.join(temp_dir, "hs")
    # FIXED: Secure directory permissions
    os.makedirs(hs_dir, mode=0o700, exist_ok=True)
    torrc_path = os.path.join(temp_dir, "torrc")
    
    with open(torrc_path, "w") as f:
        f.write(f"""
SocksPort {TOR_SOCKS_PORT}
HiddenServiceDir {hs_dir}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
Log notice stdout
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
            with open(onion_path, "r") as f:
                onion_addr = f.read().strip()
            print(f"[*] Hidden service ready: {onion_addr} (port {local_port})")
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
                    print("\\n[!] Peer disconnected.")
                    stop_flag.set()
                    break
                try:
                    msg = decrypt_message(session_key, data)
                    if msg is None:
                        print("\\n[!] Message decryption failed - possible tampering!")
                        stop_flag.set()
                        break
                    print(f"\\nPeer: {msg}\\nYou: ", end="", flush=True)
                    if msg.strip().lower() == "exit":
                        print("[*] Peer ended the chat. Closing session.")
                        stop_flag.set()
                        break
                except Exception as e:
                    print(f"\\n[!] Decrypt error: {e}")
                    stop_flag.set()
                    break
            except Exception as ex:
                print(f"\\n[!] Connection error: {ex}")
                stop_flag.set()
                break

    threading.Thread(target=recv_loop, daemon=True).start()

    while not stop_flag.is_set():
        try:
            msg = input("You: ")
        except (EOFError, KeyboardInterrupt):
            print("\\n[*] Input interrupted, exiting chat.")
            stop_flag.set()
            break
        
        # FIXED: Input validation
        if len(msg) > 4000:  # Reasonable message length limit
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
        nonce_counter = NonceCounter()

        print("\n*** Share this .onion address with your peer ***")
        print(onion_addr)
        print(f"Port: {local_port}")

        print("\n*** Share this public key with your peer ***")
        host_pubkey_pem = serialize_public_key(public_key)
        print(host_pubkey_pem.decode())

        print("\nPaste peer's public key PEM (end with blank line):")
        peer_lines = []
        while True:
            line = sys.stdin.readline()
            if line.strip() == "":
                break
            peer_lines.append(line)
        peer_pem = "".join(peer_lines).encode()

        try:
            # Load peer's public key
            peer_public_key = load_pem_public_key(peer_pem)
            
            # FIXED: Enhanced key derivation with session context
            transcript = host_pubkey_pem + peer_pem + onion_addr.encode() + str(local_port).encode()
            session_key = derive_shared_key_with_context(private_key, peer_public_key, transcript)
            
            # CRITICAL FIX: Add Short Authentication String verification
            sas = derive_sas(session_key, transcript)
            
            print("\n" + "="*50)
            print("*** SECURITY VERIFICATION REQUIRED ***")
            print("="*50)
            print(f"Verification code: {sas}")
            print("\nIMPORTANT: Compare this code with your peer over voice/video call.")
            print("This prevents man-in-the-middle attacks.")
            print("="*50)
            
            while True:
                confirmed = input("\\nDoes your peer confirm this EXACT code? (yes/no): ").strip().lower()
                if confirmed == "yes":
                    break
                elif confirmed == "no":
                    print("\n" + "!"*50)
                    print("!!! SECURITY ALERT: Verification FAILED !!!")
                    print("!!! POSSIBLE MAN-IN-THE-MIDDLE ATTACK !!!")
                    print("!!! DO NOT PROCEED WITH CHAT !!!")
                    print("!!! Check your connection and try again !!!")
                    print("!"*50)
                    return
                else:
                    print("Please enter 'yes' or 'no'")

        except Exception as e:
            print(f"[!] Failed to derive session key: {e}")
            return

        print("\n[*] Security verification passed!")
        print("[*] Session key derived. Waiting for a connection...\n")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", local_port))
            s.listen(1)
            s.settimeout(300)  # 5 minute timeout
            try:
                conn, addr = s.accept()
            except socket.timeout:
                print("[!] Timeout waiting for connection.")
                return
                
            with conn:
                print(f"[*] Peer connected from {addr}")
                handle_client(conn, session_key, nonce_counter)

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
                if msg is None:
                    print("\n[!] Message decryption failed - possible tampering!")
                    stop_flag.set()
                    break
                print(f"\nPeer: {msg}\\nYou: ", end="", flush=True)
                if msg.strip().lower() == "exit":
                    print("[*] Peer ended the chat. Closing session.")
                    stop_flag.set()
                    break
            except Exception as e:
                print(f"\n[!] Decrypt error: {e}")
                stop_flag.set()
                break
        except Exception as ex:
            print(f"\n[!] Socket error: {ex}")
            stop_flag.set()
            break

def run_client():
    print("====== ephemeral chat: CLIENT mode ======")
    
    # FIXED: Input validation
    while True:
        onion_addr = input("Enter host's .onion address: ").strip()
        if validate_onion_address(onion_addr):
            break
        print("[!] Invalid .onion address format. Please try again.")
    
    while True:
        try:
            port = int(input("Enter port (shown by host): ").strip())
            if validate_port(port):
                break
            print("[!] Invalid port. Must be between 1024-65535.")
        except ValueError:
            print("[!] Invalid port format. Please enter a number.")

    private_key, public_key = generate_keys()
    nonce_counter = NonceCounter()

    print("\\n*** Send this public key to the host ***")
    client_pubkey_pem = serialize_public_key(public_key)
    print(client_pubkey_pem.decode())

    print("\\nPaste host's public key PEM (end with blank line):")
    peer_lines = []
    while True:
        line = sys.stdin.readline()
        if line.strip() == "":
            break
        peer_lines.append(line)
    peer_pem = "".join(peer_lines).encode()

    try:
        # Load host's public key
        peer_public_key = load_pem_public_key(peer_pem)
        
        # FIXED: Enhanced key derivation with session context
        # Note: Order must match host (host_pubkey + client_pubkey + onion + port)
        transcript = peer_pem + client_pubkey_pem + onion_addr.encode() + str(port).encode()
        session_key = derive_shared_key_with_context(private_key, peer_public_key, transcript)
        
        # CRITICAL FIX: Add Short Authentication String verification
        sas = derive_sas(session_key, transcript)
        
        print("\n" + "="*50)
        print("*** SECURITY VERIFICATION REQUIRED ***")
        print("="*50)
        print(f"Verification code: {sas}")
        print("\nIMPORTANT: Compare this code with the host over voice/video call.")
        print("This prevents man-in-the-middle attacks.")
        print("="*50)
        
        while True:
            confirmed = input("\\nDoes the host confirm this EXACT code? (yes/no): ").strip().lower()
            if confirmed == "yes":
                break
            elif confirmed == "no":
                print("\n" + "!"*50)
                print("!!! SECURITY ALERT: Verification FAILED !!!")
                print("!!! POSSIBLE MAN-IN-THE-MIDDLE ATTACK !!!")
                print("!!! DO NOT PROCEED WITH CHAT !!!")
                print("!!! Check your connection and try again !!!")
                print("!"*50)
                return
            else:
                print("Please enter 'yes' or 'no'")

    except Exception as e:
        print(f"[!] Failed to derive session key: {e}")
        return

    print("\n[*] Security verification passed!")
    print("[*] Session key derived. Connecting...\n")

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, TOR_SOCKS_ADDR, TOR_SOCKS_PORT)
    s.settimeout(30)  # 30 second connection timeout

    try:
        s.connect((onion_addr, port))
        print("[*] Connected to host!")
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
            
            # FIXED: Input validation
            if len(msg) > 4000:  # Reasonable message length limit
                print("[!] Message too long (max 4000 chars)")
                continue
                
            if msg.strip().lower() == "exit":
                stop_flag.set()
                break
            try:
                ct = encrypt_message(session_key, msg, nonce_counter)
                s.sendall(ct)
            except Exception as e:
                print(f"[!] Send error: {e}")
                stop_flag.set()
                break
    finally:
        s.close()
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


print("Updated ephemeral.py code has been generated with all critical security fixes:")
print("\n1. Short Authentication String (SAS) verification to prevent MITM")
print("2. Enhanced key derivation with session context")
print("3. Input validation for .onion addresses and ports")
print("4. Secure Tor directory permissions (0o700)")
print("5. Message length limits")
print("6. Better error handling for decryption failures")
print("7. Connection timeouts")
print("8. Updated to use NonceCounter from crypto_core")
