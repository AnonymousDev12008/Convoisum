Below is a complete, ready-to-paste README.md for Convoisim v2. It includes a clickable Table of Contents with working quick links, clearly marked sections, and code blocks formatted in a readable palette style. Replace placeholders like <your-repo-url> with your actual repository URL before publishing.

# Convoisim v2 — Privacy-Focused Ephemeral P2P Chat over Tor v3

Convoisim is a command-line tool for secure, anonymous, and ephemeral chat routed through Tor v3 hidden services. Each session uses fresh end-to-end encryption, keys are bound to a session transcript, peers authenticate via a human-verifiable SAS, and no persistent data is kept by design.

Note: v2 introduces framed messaging and strict sequencing and is not wire-compatible with v1. Both peers must run v2.

## Table of Contents
- [Overview](#overview)
- [What’s New in v200](#whats-new-in-v200)
- [Security Model and Strength](#security-model-and-strength)
- [Security Recommendations](#security-recommendations)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Linux](#linux)
  - [Windows PowerShell](#windows-powershell)
  - [Termux Android](#termux-android)
- [Usage](#usage)
  - [Hosting a Chat Session](#hosting-a-chat-session)
  - [Joining a Chat Session](#joining-a-chat-session)
  - [Chat Controls](#chat-controls)
- [Troubleshooting](#troubleshooting)
- [Quick Links](#quick-links)
- [Release Notes](#release-notes)
- [License and Acknowledgments](#license-and-acknowledgments)

## Overview
- Ephemeral Tor v3 hidden services (unique .onion per session)
- ECDH P-256 key agreement with transcript-bound HKDF derivation
- AES-GCM authenticated encryption, per-sender nonces via secure counter
- Strict per-direction sequence numbers bound via AEAD associated data
- 6-word SAS for human verification (~48 bits)
- No persistent logs or transcripts; temporary files are removed on exit

## What’s New in v2.0.0
- Security
  - Length-prefixed framing to prevent TCP boundary issues
  - Strict per-direction sequence numbers bound via AEAD associated data (replay/out-of-order mitigation)
  - Transcript-derived salts for HKDF (bind session key and SAS to context)
  - Stronger SAS: 6 words from a 256-word list (~48 bits)
  - Quiet key validation (no sensitive prints)
  - Hardened Tor host config (no SocksPort to avoid conflicts, ClientOnly=1)
- Reliability
  - Host pre-binds a local port before creating the onion service
- UX/Safety
  - Clipboard copying disabled by default (opt-in)
- Compatibility
  - Not wire-compatible with v1; both peers must use v2

## Security Model and Strength
- Cryptography
  - Key agreement: ECDH over P-256 SECP256R1
  - KDF: HKDF-SHA256 with transcript-derived salt and info bindings
  - AEAD: AES-GCM with 96-bit nonces (per-sender, never reused)
  - SAS: 6-word code from 256-word list (~48 bits) to detect MitM
- Protocol properties
  - Transcript binding includes role ordering, both DER-encoded public keys, onion, and port
  - Strict, monotonic per-direction sequence numbers are incorporated as AEAD associated data
  - Length-prefixed frames ensure robust message boundaries over TCP
- Out of scope
  - Endpoint compromise (malware, keyloggers, clipboard snoopers)
  - Global traffic correlation attacks on Tor
  - Physical access and live memory forensics

## Security Recommendations
- Verify the SAS over a trusted channel (e.g., in-person or known-identity video call). Any mismatch should immediately abort the session.
- Never exchange public keys or SAS via the same chat channel; use a separate authenticated channel.
- Keep Tor and the OS fully updated; avoid any clearnet fallback.
- For sensitive use, run inside an isolated VM/container; disable clipboard sharing.
- Leave clipboard copying disabled (default). If enabling, ensure the environment is trusted.
- Keep sessions short and share only necessary information.

## Requirements
- Python 3.10+ recommended
- Tor installed and available on PATH
- Python packages:
  - cryptography
  - PySocks
  - pyperclip optional

Example requirements.txt:
```text
cryptography==43.0.1
PySocks==1.7.1
pyperclip==1.9.0
```

## Installation

### Linux
Update system:
```bash
sudo apt update && sudo apt upgrade -y
```

Install prerequisites:
```bash
sudo apt install -y python3 python3-pip git tor
```

Clone and install:
```bash
git clone https://github.com/AnonymousDev12008/Convoisum.git
cd Convoisum
pip3 install -r requirements.txt
```

Notes:
- Ensure tor is on PATH; otherwise start it manually before use.

### Windows PowerShell
Install:
- Python 3.x added to PATH
- Git for Windows
- Tor Expert Bundle (ensure tor.exe is on PATH or note its full path)

Clone and install:
```powershell
git clone https://github.com/AnonymousDev12008/Convoisum.git
cd Convoisum
pip install -r requirements.txt
```

Notes:
- If tor.exe isn’t found, start Tor manually before using the app.
- Use Windows Terminal/PowerShell with UTF-8 for best results.

### Termux Android
Update and install:
```bash
pkg update && pkg upgrade -y
pkg install -y python git tor
```

Clone and install:
```bash
git clone https://github.com/AnonymousDev12008/Convoisum.git
cd Convoisum
pip install -r requirements.txt
```

Notes:
- Allow enough time for Tor to bootstrap; keep Termux awake during service creation.

## Usage
Run:
```bash
python3 ephemeral.py
```

Main menu:
- h   Host a session and create a Tor v3 onion service
- j   Join a session via Tor SOCKS 127.0.0.1:9050
- q   Quit

### Hosting a Chat Session
1) Choose h
2) The app pre-binds a local port, starts an onion service, and shows:
   - Onion address and port
   - Your public key PEM
   - SAS (6 words) after both PEMs are provided and the session key is derived
3) Share your PEM via a trusted channel
4) Paste the peer’s PEM when prompted
5) Verify SAS matches over the trusted channel; proceed only on match
6) Wait for the peer to connect and chat

### Joining a Chat Session
1) Choose j
2) Enter the host onion and port
3) The app shows your public key PEM; share it via a trusted channel if needed
4) Paste the host’s PEM when prompted
5) Verify SAS matches over the trusted channel; proceed only on match
6) Begin chatting

### Chat Controls
- Type a message and press Enter to send
- Type exit to end the session
- Type cancel during prompts to abort
- Messages are limited to 512 characters

## Troubleshooting
- Tor not found
  - Install Tor and ensure tor or tor.exe is on PATH
- Tor not bootstrapping
  - Start Tor first; confirm SOCKS at 127.0.0.1:9050
- Connection fails or stalls
  - Verify onion address/port; ensure both peers are online and Tor is running
  - Check local firewall rules
- SAS mismatch
  - Abort immediately; do not proceed

## Quick Links
- [Overview](#overview)
- [What’s New](#whats-new-in-v200)
- [Security Model](#security-model-and-strength)
- [Security Recommendations](#security-recommendations)
- [Installation](#installation)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Release Notes](#release-notes)
- [License](#license-and-acknowledgments)

## Release Notes
v2.0.0 2025-08-24
- Security: framed messaging, strict sequencing, transcript-derived salts, stronger SAS, quiet validation
- Hardening: Tor host config, pre-bind local port
- UX: Clipboard optional, default off
- Compatibility: Not wire-compatible with v1

## License and Acknowledgments
- License: MIT
- Built with Python and cryptography
- Uses Tor v3 hidden services for network anonymity

Contributions and independent reviews are welcome. For high-stakes use, consider a dedicated, hardened environment, pinned dependencies, and external security review.

