# Ephemeral Tor Chat

A **privacy-focused, ephemeral, peer-to-peer chat application** running over Tor hidden services.  
It uses fresh ephemeral cryptographic keys for every session, routes traffic anonymously via Tor, and destroys all data on exit. Perfect for secure, anonymous, and temporary chat sessions.

## Table of Contents

- [About](#about)  
- [How It Works](#how-it-works)  
- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Using on Termux (Android)](#using-on-termux-android)  
- [Cleanup](#cleanup)  
- [Security Considerations](#security-considerations)  
- [License](#license)

## About

`ephemeral Tor chat` creates a temporary chat room using a Tor hidden service as the host. Clients connect to the `.onion` address over Tor. Both peers exchange ephemeral public keys, derive a shared session key, and communicate with end-to-end encrypted messages. The host establishes a Tor hidden service with a fresh `.onion` address each session. All session data and keys are destroyed on exit, ensuring no lasting trace.

## How It Works

- **Host:** Creates a new Tor hidden service with a unique `.onion` address. Generates ephemeral cryptographic keys and prints its public key PEM.  
- **Client:** Connects to the host’s `.onion` address via Tor SOCKS5 proxy, also generates ephemeral keys and sends its public key PEM.  
- Both derive a shared symmetric session key via Elliptic Curve Diffie-Hellman (ECDH).  
- Messages are encrypted end-to-end using AES-GCM.  
- Communication flows entirely inside the Tor network, hiding IP addresses.  
- When either side types `exit`, the session ends, Tor subprocess and temporary files are cleaned up, making the chat fully ephemeral.

## Features

- Strong anonymity leveraging Tor hidden services  
- Ephemeral, one-time-use `.onion` addresses per session  
- End-to-end encryption with ephemeral keys  
- Peer-to-peer direct connections with no central servers  
- Simple CLI interface with a unified host/join menu  
- Cross-platform: Windows, Linux, macOS, and Android (Termux)  
- Lightweight, minimal dependencies (Python, cryptography, PySocks, Tor)  

## Requirements

- Python 3.7+  
- Tor installed and in your system PATH (or accessible as `tor` command)  
- Python packages:
  - `cryptography`
  - `PySocks`  

## Installation

### 1. Install Tor

- **Windows/macOS/Linux:** Download and install the official [Tor Expert Bundle or Tor Browser](https://www.torproject.org/).  
- Ensure `tor` command runs from terminal or is accessible in your PATH.

### 2. Install Python Dependencies

    pip install -r requirements.txt


## Usage

1. Put `ephemeral.py` and `crypto_core.py` in the same directory.

2. Run the script:

   python ephemeral.py


3. Follow the on-screen menu:

Host (h), Join (j), Quit (q):

- To **host** a chat:
  - Choose `h`.
  - The program starts a Tor hidden service and displays a `.onion` address and port.
  - It prints your public key PEM; share this and the `.onion` address & port with your peer.
  - Paste your peer’s public key PEM when prompted.
  - Wait for the client to connect, then start chatting.
  - Type `'exit'` to terminate the session cleanly.

- To **join** a chat:
  - Choose `j`.
  - Enter the host’s `.onion` address and port.
  - The client displays its own public key PEM; send this to the host.
  - Paste the host’s public key PEM when prompted.
  - Begin chatting.
  - Type `'exit'` to leave.

## Using on Termux (Android)

1. Install Termux from [F-Droid](https://f-droid.org/en/packages/com.termux/).

2. Update packages:

   pkg update && pkg upgrade

3. Install dependencies:

   pkg install python tor git
   pip install cryptography PySocks


4. Clone your repository or transfer your scripts to Termux home.

   git clone https://github.com/Anonymous Dev12008/Ephemeral-chat.git


5. Make sure Tor is running (the script will start and manage Tor automatically, but you can also run it manually with `tor &`).

6. Run the chat app:
  
   python ephemeral.py


7. Use the same menu-based workflow as desktop.

8. **Note:** Closing the Termux session will stop all running processes, including Tor and your chat session, ensuring ephemeral cleanup.

## Cleanup

- All ephemeral keys, Tor hidden service directories, and subprocesses are cleaned automatically on chat exit or when you type `exit`.
- To manually clean leftover temp files on Termux:

   rm -rf /data/data/com.termux/files/usr/tmp/torchat_host_*


Replace with the actual temp directory paths printed by the script if needed.

## Security Considerations

- Exchange public key PEM data *securely* out-of-band to avoid man-in-the-middle risks.
- Tor provides strong network anonymity but is not invulnerable to global adversaries.
- End-to-end encryption and ephemeral keys protect your chat content even if Tor traffic is observed.
- Sessions end when you type `exit` or close the app; ephemeral data is destroyed.
- Only one client connection supported at a time.
- Keep Python packages and Tor updated.

## License

Distributed under the MIT License. See `LICENSE` for details.

Contributions and suggestions are welcome!

---

Feel free to contact the maintainer or open issues/pull requests on the Git repository.




   


