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
from typing import Tuple, Optional
import queue

import socks
try:
    import pyperclip
except ImportError:
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
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.styles import Style

DEBUG = False
USE_CLIPBOARD = False
MAX_MESSAGE_LENGTH = 512

_last_tmp_dir = None
_last_tor_proc = None

def cleanup():
    global _last_tor_proc, _last_tmp_dir
    if _last_tor_proc:
        try:
            _last_tor_proc.terminate()
            _last_tor_proc.wait(timeout=5)
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
        print(f"\n{prompt} (full PEM or 'cancel')")
        lines = []
        while True:
            line = sys.stdin.readline()
            if not line:
                return None
            line = line.rstrip("\n")
            if line.lower() == "cancel":
                return None
            lines.append(line)
            if line == "-----END PUBLIC KEY-----":
                break
        pem = "\n".join(lines) + "\n"
        if pem.startswith("-----BEGIN PUBLIC KEY-----"):
            return pem.encode()
        print("[Error] Invalid PEM, try again or 'cancel'.")

def is_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def send_frame(sock: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(4, 'big')
    sock.sendall(header + data)

def recv_frames(sock: socket.socket, buffer: bytearray):
    frames = []
    try:
        chunk = sock.recv(4096)
    except Exception:
        return None
    if not chunk:
        return None
    buffer.extend(chunk)
    while True:
        if len(buffer) < 4:
            break
        length = int.from_bytes(buffer[:4], 'big')
        if length < 0 or length > 10_000_000:
            raise ValueError("Invalid frame length")
        if len(buffer) < 4 + length:
            break
        frames.append(bytes(buffer[4:4+length]))
        del buffer[:4+length]
    return frames

def start_tor_hidden_service(local_port: int):
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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=not platform.system().startswith("Windows")
        )
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None, None
    hostname = os.path.join(hs, "hostname")
    for _ in range(60):
        if os.path.exists(hostname):
            onion = open(hostname).read().strip()
            _last_tor_proc = proc
            return proc, onion, tmp
        time.sleep(1)
    proc.terminate()
    shutil.rmtree(tmp, ignore_errors=True)
    return None, None, None

def build_transcript(h_der: bytes, c_der: bytes, onion: str, port: int) -> bytes:
    return h_der + c_der + onion.encode() + port.to_bytes(2, "big")

def make_log_box(txt: str) -> str:
    lines = txt.splitlines()
    w = max(len(l) for l in lines) if lines else 0
    top = "┌" + "─"*(w+2) + "┐"
    bot = "└" + "─"*(w+2) + "┘"
    box = [top] + [f"│ {l.ljust(w)} │" for l in lines] + [bot]
    return "\n".join(box)

def handle_chat(sock, session_key, nonce_ctr):
    stop = threading.Event()
    seq_send = 0
    seq_recv = 0
    recv_buf = bytearray()
    queue_msgs = queue.Queue()
    user_scrolled_up = False

    style = Style.from_dict({
        'peer': 'ansicyan','user':'ansigreen bold',
        'log':'ansiyellow italic','info':'ansigreen',
        'error':'ansired bold'
    })

    # Chat display area
    chat_area = TextArea(
        text="",
        read_only=True,
        focusable=False,
        wrap_lines=True
    )
    # Input area
    input_area = TextArea(
        height=1,
        prompt="You: ",
        multiline=False,
        wrap_lines=False
    )

    kb = KeyBindings()

    @kb.add('c-c')
    @kb.add('c-q')
    def _(e):
        stop.set()
        e.app.exit()

    @kb.add('up')
    def _(e):
        nonlocal user_scrolled_up
        chat_area.buffer.cursor_up(1)
        user_scrolled_up = chat_area.buffer.cursor_position < len(chat_area.text) - 1

    @kb.add('down')
    def _(e):
        nonlocal user_scrolled_up
        chat_area.buffer.cursor_down(1)
        user_scrolled_up = chat_area.buffer.cursor_position < len(chat_area.text) - 1

    @kb.add('pageup')
    def _(e):
        nonlocal user_scrolled_up
        chat_area.buffer.cursor_up(10)
        user_scrolled_up = True

    @kb.add('pagedown')
    def _(e):
        nonlocal user_scrolled_up
        chat_area.buffer.cursor_down(10)
        user_scrolled_up = chat_area.buffer.cursor_position < len(chat_area.text) - 1

    def recv_loop():
        nonlocal seq_recv
        sock.setblocking(True)
        while not stop.is_set():
            frames = recv_frames(sock, recv_buf)
            if frames is None:
                queue_msgs.put("[Peer disconnected]")
                stop.set()
                return
            for data in frames:
                nonce = data[:12]
                ct = data[12:]
                msg = decrypt_message(session_key, data, seq_recv)
                if msg is None:
                    queue_msgs.put("[Decryption error]")
                    stop.set()
                    return
                peer = f"Peer: {msg}"
                log = make_log_box(
                    f"Seq: {seq_recv}\nNonce: {nonce.hex()}\nPayload: {base64.b64encode(ct).decode()}"
                )
                queue_msgs.put(f"{peer}\n{log}")
                if msg.lower()=="exit":
                    queue_msgs.put("[Peer exited]")
                    stop.set()
                    return
                seq_recv += 1

    threading.Thread(target=recv_loop, daemon=True).start()

    def accept(buf):
        nonlocal seq_send
        txt = buf.text.strip()
        if not txt: return
        if txt.lower()=="exit":
            stop.set()
            get_app().exit()
            return
        if len(txt)>MAX_MESSAGE_LENGTH:
            queue_msgs.put("[Error] Too long")
            return
        ct = encrypt_message(session_key, txt, nonce_ctr, seq_send)
        send_frame(sock, ct)
        you = f"You: {txt}"
        nonce = ct[:12]
        payload = ct[12:]
        log = make_log_box(
            f"Seq: {seq_send}\nNonce: {nonce.hex()}\nPayload: {base64.b64encode(payload).decode()}"
        )
        queue_msgs.put(f"{you}\n{log}")
        seq_send += 1
        buf.text = ""
        app.layout.focus(input_area)

    input_area.buffer.accept_handler = accept

    root = HSplit([chat_area, input_area])
    app = Application(
        layout=Layout(root),
        key_bindings=kb,
        style=style,
        full_screen=True,
        refresh_interval=0.2
    )
    app.layout.focus(input_area)

    def consumer():
        nonlocal user_scrolled_up
        while not stop.is_set():
            try:
                m = queue_msgs.get(timeout=0.5)
                at_bottom = chat_area.buffer.cursor_position >= len(chat_area.text)-1
                chat_area.text = (chat_area.text + "\n" + m) if chat_area.text else m
                if at_bottom and not user_scrolled_up:
                    chat_area.buffer.cursor_position = len(chat_area.text)
                app.invalidate()
            except queue.Empty:
                pass

    threading.Thread(target=consumer, daemon=True).start()

    try:
        app.run()
    except Exception as e:
        print(f"[Error] {e}")
    finally:
        try: sock.close()
        except: pass

def _prebind_listener() -> Optional[tuple]:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    for _ in range(30):
        p=random.randint(15000,20000)
        try:
            s.bind(("127.0.0.1",p)); s.listen(1)
            return s,p
        except OSError:
            continue
    return None

def run_host():
    print("=== Host ===")
    res=_prebind_listener()
    if not res: return
    lstn,port=res
    print("Starting Tor...");proc,onion,tmp=start_tor_hidden_service(port)
    if not proc: return
    print(f"Onion: {onion}, Port: {port}")
    priv,pub=generate_keys();nonce_ctr=SecureNonceCounter()
    pem=serialize_public_key(pub).decode()
    print(pem)
    peer=read_pem_from_stdin("Paste peer PUBLIC KEY PEM:")
    if not peer: return
    peer_pub=deserialize_public_key(peer)
    sess=derive_shared_key_with_context(priv,peer_pub,
        build_transcript(pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),
                         peer_pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),
                         onion,port)
    )
    sas=derive_sas(sess,sess);print(f"SAS: {sas}")
    if input("Proceed? (yes/no): ").strip().lower()!="yes": return
    conn,_=lstn.accept();lstn.close()
    handle_chat(conn,sess,nonce_ctr)

def run_client():
    print("=== Client ===")
    onion=input("Host Onion: ").strip()
    port_s=input("Host port: ").strip()
    port=validate_port(port_s)
    if not port: return
    if not is_listening("127.0.0.1",9050):
        subprocess.Popen(["tor"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(20):
            if is_listening("127.0.0.1",9050): break
            time.sleep(1)
    priv,pub=generate_keys();nonce_ctr=SecureNonceCounter()
    pem=serialize_public_key(pub).decode();print(pem)
    peer=read_pem_from_stdin("Paste host PUBLIC KEY PEM:")
    if not peer: return
    peer_pub=deserialize_public_key(peer)
    transcript=build_transcript(
        peer_pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),
        pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),
        onion,port
    )
    sess=derive_shared_key_with_context(priv,peer_pub,transcript)
    sas=derive_sas(sess,transcript);print(f"SAS: {sas}")
    if input("Proceed? (yes/no): ").strip().lower()!="yes": return
    s=socks.socksocket();s.set_proxy(socks.SOCKS5,"127.0.0.1",9050)
    s.connect((onion,port))
    handle_chat(s,sess,nonce_ctr)

def main_menu():
    while True:
        print(""" === Convoisum V2 ===
              
              [h] Host  [j] Join  [q] Quit
              
              """)
        c=input("Choice: ").strip().lower()
        if c=="h": run_host()
        elif c=="j": run_client()
        elif c=="q": break

if __name__=="__main__":
    main_menu()
