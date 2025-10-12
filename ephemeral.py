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
import base64
from typing import Optional, Tuple, List
import queue

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

from prompt_toolkit import Application
from prompt_toolkit.application.current import get_app
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.margins import ScrollbarMargin
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.styles import Style

DEBUG = False
USE_CLIPBOARD = False  # Default off for safety
MAX_MESSAGE_LENGTH = 512

_last_tmp_dir = None
_last_tor_proc = None

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
                print("[!] Incomplete PEM; returning to menu.\n")
                return None
            line = line.rstrip("\n")
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

def send_frame(sock: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(4, 'big')
    sock.sendall(header + data)

def recv_frames(sock: socket.socket, buffer: bytearray) -> Optional[List[bytes]]:
    frames = []
    try:
        chunk = sock.recv(4096)
    except Exception:
        return None
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

def start_tor_hidden_service(local_port: int):
    global _last_tmp_dir, _last_tor_proc
    tmp = tempfile.mkdtemp(prefix="convoisim_v2_")
    os.chmod(tmp, 0o700)
    _last_tmp_dir = tmp
    hs = os.path.join(tmp, "hs")
    os.makedirs(hs, 0o700)
    torrc_path = os.path.join(tmp, "torrc")
    with open(torrc_path, "w") as f:
        f.write(f"""
HiddenServiceDir {hs}
HiddenServicePort {local_port} 127.0.0.1:{local_port}
HiddenServiceVersion 3
ClientOnly 1
""")
    try:
        proc = subprocess.Popen(
            ["tor", "-f", torrc_path],
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
    print("[!] HS creation timeout\n")
    return None, None, None

def build_transcript(host_der: bytes, client_der: bytes, onion: str, port: int) -> bytes:
    return host_der + client_der + onion.encode() + port.to_bytes(2, "big")

def make_log_box(log_text: str) -> str:
    lines = log_text.splitlines()
    width = max(len(line) for line in lines)
    top = "┌" + "─" * (width + 2) + "┐"
    bottom = "└" + "─" * (width + 2) + "┘"
    boxed_lines = [top]
    for line in lines:
        boxed_lines.append("│ " + line.ljust(width) + " │")
    boxed_lines.append(bottom)
    return "\n".join(boxed_lines)

def handle_chat(sock: socket.socket, session_key: SecureBytes, nonce_ctr: SecureNonceCounter):
    stop = threading.Event()
    seq_send = 0
    seq_recv = 0
    recv_buffer = bytearray()
    message_queue = queue.Queue()
    chat_messages = []
    style = Style.from_dict({
        'peer': 'ansicyan',
        'user': 'ansigreen bold',
        'log': 'ansiyellow italic',
        'info': 'ansigreen',
        'error': 'ansired bold',
    })
    kb = KeyBindings()
    @kb.add('c-c')
    @kb.add('c-q')
    def _(event):
        stop.set()
        event.app.exit()
    def recv_loop():
        nonlocal seq_recv
        sock.setblocking(True)
        while not stop.is_set():
            try:
                frames = recv_frames(sock, recv_buffer)
                if frames is None:
                    message_queue.put(('[Peer disconnected]', 'info'))
                    stop.set()
                    return
            except ConnectionResetError:
                message_queue.put(('[Connection reset by peer]', 'error'))
                stop.set()
                return
            except Exception as e:
                message_queue.put((f'[recv error: {e}]', 'error'))
                stop.set()
                return
            for data in frames:
                nonce = data[:12]
                ct = data[12:]
                msg = decrypt_message(session_key, data, seq_recv)
                if msg is None:
                    message_queue.put(('[Decryption error or replay]', 'error'))
                    stop.set()
                    return
                peer_block = f"<peer>Peer: {msg}</peer>"
                log_text = f"Seq: {seq_recv}\nNonce: {nonce.hex()}\nPayload (b64): {base64.b64encode(ct).decode()}"
                log_box = make_log_box(log_text)
                colored_log_box = f"<log>{log_box}</log>"
                message_queue.put((peer_block, 'peerblock'))
                message_queue.put((colored_log_box, 'logblock'))
                if msg.strip().lower() == "exit":
                    message_queue.put(('[Peer exited the chat]', 'info'))
                    stop.set()
                    return
                seq_recv += 1
    threading.Thread(target=recv_loop, daemon=True).start()
    def get_chat_text():
        result = []
        for m, typ in chat_messages:
            if typ == 'peerblock':
                result.append(('class:peer', m))
            elif typ == 'userblock':
                result.append(('class:user', m))
            elif typ == 'logblock':
                result.append(('class:log', m))
            elif typ == 'info':
                result.append(('class:info', m))
            elif typ == 'error':
                result.append(('class:error', m))
            else:
                result.append(('', m))
            result.append(('', "\n"))
        return result
    chat_text_control = FormattedTextControl(get_chat_text, focusable=False)
    chat_window = Window(content=chat_text_control,
                         wrap_lines=True,
                         scrollbar=True,
                         right_margins=[ScrollbarMargin()])
    input_buffer = Buffer()
    def accept_text(buff):
        nonlocal stop, seq_send
        user_input = buff.text
        if not user_input.strip():
            return
        if user_input.strip().lower() == 'exit':
            stop.set()
            get_app().exit()
            return
        if len(user_input) > MAX_MESSAGE_LENGTH:
            message_queue.put(('[Error] Message too long.', 'error'))
            return
        ct = encrypt_message(session_key, user_input, nonce_ctr, seq_send)
        nonce = ct[:12]
        ct_payload = ct[12:]
        send_frame(sock, ct)
        user_block = f"You: {user_input}"
        log_text = f"Seq: {seq_send}\nNonce: {nonce.hex()}\nPayload (b64): {base64.b64encode(ct_payload).decode()}"
        log_box = make_log_box(log_text)
        colored_log_box = f"<log>{log_box}</log>"
        message_queue.put((user_block, 'userblock'))
        message_queue.put((colored_log_box, 'logblock'))
        seq_send += 1
        buff.text = ''
    input_buffer.accept_handler = accept_text
    input_text_area = TextArea(
        height=1,
        prompt='You: ',
        multiline=False,
        wrap_lines=False,
        buffer=input_buffer)
    root_container = HSplit([
        chat_window,
        input_text_area,
    ])
    application = Application(
        layout=Layout(root_container),
        key_bindings=kb,
        style=style,
        full_screen=True,
        refresh_interval=0.2
    )
    def message_consumer():
        while not stop.is_set():
            try:
                msg = message_queue.get(timeout=0.5)
                chat_messages.append(msg)
            except queue.Empty:
                continue
    threading.Thread(target=message_consumer, daemon=True).start()
    try:
        application.run()
    except Exception as e:
        print(f"[Error] Application crashed: {e}")
    try:
        sock.close()
    except Exception:
        pass
    print("[Info] Chat session ended.")

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
    print("\n=== Host Mode (Convoisum-v2) ===\n")
    listener, port = _prebind_local_listener()
    if listener is None:
        print("[Error] Could not find an available local port\n")
        return
    print("[Info] Starting Tor HS... please wait\n")
    proc, onion, tmp = start_tor_hidden_service(port)
    if not proc or not onion:
        try:
            listener.close()
        except Exception:
            pass
        return
    print("[Success] HS ready\n")
    print("[Warning] THIS IS YOUR PUBLIC KEY PEM. SHARE IT SECURELY ONLY (e.g., video call).\n")
    print(f"Onion address: {onion}")
    print(f"Port: {port}\n")
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
    print("[Info] Waiting for peer (type 'cancel' to abort):\n")
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
    print("\n=== Client Mode (Convoisum-v2) ===\n")
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
    print("[Info] Connecting to peer... (type 'cancel' to abort)\n")
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

def main_menu():
    while True:
        print("""
===== Convoisum-v2 =====
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
