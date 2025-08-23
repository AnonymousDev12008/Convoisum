# Convoisum

### Privacy-Focused Ephemeral Peer-to-Peer Chat Over Tor v3

***

## Table of Contents

1. [Overview](#overview)  
2. [Key Features](#key-features)  
3. [Security Recommendations](#security-recommendations)  
4. [Prerequisites & Installation](#prerequisites--installation)  
   - [Linux / Termux Setup](#linux--termux-setup)  
   - [Windows PowerShell Setup](#windows-powershell-setup)  
5. [Configuration](#configuration)  
6. [Usage Instructions](#usage-instructions)  
   - [Hosting a Chat Session](#hosting-a-chat-session)  
   - [Joining a Chat Session](#joining-a-chat-session)  
7. [Notes and Best Practices](#notes-and-best-practices)  
8. [Disclaimer](#disclaimer)  

***

## Overview

Convoisum is a command-line chat tool designed to enable **secure, anonymous, and ephemeral conversations** routed through the Tor v3 network’s hidden services. It uses **strong end-to-end encryption**, **manual SAS verification**, and **Tor anonymity** features to protect user privacy and prevent common network attacks.

***

## Key Features

- Creates ephemeral Tor hidden services with unique .onion addresses  
- Secure peer authentication via public key exchange and SAS verification  
- Clipboard support for easy key sharing with security reminders  
- Role selection: host or join chat sessions  
- Length-limiting chat messages to prevent abuse  
- Cancel commands at almost every step for safety  
- Clear, consistent tagged console prompts and statuses  
- Cross-platform with support for Linux, Windows PowerShell, and Termux

***

## Security Recommendations

- Always **exchange public keys through a secure, authenticated channel** such as a video call to prevent man-in-the-middle attacks.  
- Confirm the SAS string displayed on both sides before chatting.  
- Keep Tor and all system software updated.  
- Prefer ephemeral sessions with minimal persistent information.  
- Avoid sending overly long messages to maintain stability and reduce attack surface.

***

## Prerequisites & Installation

### Linux / Termux Setup

1. **Update & Upgrade system packages**
   ```bash
   pkg update && pkg upgrade    # Termux
   sudo apt update && sudo apt upgrade -y   # Debian/Ubuntu Linux
   ```
2. **Install required tools**
   ```bash
   pkg install python git tor rust -y    # Termux
   sudo apt install python3 python3-pip git tor rustc build-essential -y   # Linux
   ```
3. **Clone and install Convoisum**
   ```bash
   git clone https://github.com/AnonymousDev12008/convoisum.git
   cd convoisum
   pip3 install -r requirements.txt
   ```
4. **Start Tor daemon manually if desired**
   ```bash
   tor &
   ```
   Or let the app start Tor automatically.

***

### Windows PowerShell Setup

1. **Install prerequisites**
   - Install [Python 3.x](https://www.python.org/downloads/windows/) and add it to your PATH  
   - Install [Git for Windows](https://gitforwindows.org/)  
   - Install [Tor Expert Bundle](https://www.torproject.org/download/tor/) and run tor.exe manually or as service  

2. **Clone the repository**
   ```powershell
   git clone https://github.com/AnonymousDev12008/convoisum.git
   cd convoisum
   ```
3. **Install dependencies**
   ```powershell
   pip install -r requirements.txt
   ```
4. **Run the app**
   ```powershell
   python ephemeral.py
   ```

***

## Configuration

- Ensure Tor ports (default 9050 for SOCKS proxy) are accessible and unblocked by firewalls.  
- Update `requirements.txt` for any dependencies or security patches before installation.  
- Customize `ephemeral.py` debug flag to enable verbose output during troubleshooting.

***

## Usage Instructions

### Hosting a Chat Session

- Select `h` at the main menu.  
- The app will create a Tor hidden service (it may take some time).  
- You will see your `.onion` address and port, plus your PEM public key with a **security reminder to share it only securely**.  
- Paste your peer’s public key PEM when asked (or type `cancel` to abort).  
- Verify the SAS code with your peer out-of-band.  
- Confirm to proceed, then wait for the peer to connect.  
- Chat securely. Type `exit` to quit or `cancel` to abort.

### Joining a Chat Session

- Select `j`.  
- Enter the host’s onion address and port.  
- Your PEM public key will be shown and copied for sharing.  
- Paste the host’s PEM key when requested.  
- Verify SAS codes and confirm to safely start chatting.

***

## Notes and Best Practices

- Use **secure, authenticated channels** like video calls or face-to-face to exchange PEM keys for SAS validation.  
- Always confirm SAS before proceeding to chat to mitigate MitM risks.  
- Keep Tor running/Giving it time to bootstrap before using Convoisum.  
- Limit chat message length to 512 characters for best stability & denial-of-service protection.  
- Use the `cancel` command liberally to abort processes as needed.  
- Run both peers behind reliable internet connections and hardened Tor setups.  

***

## Disclaimer

Convoisum improves privacy and security but does not eliminate all risks. Users must practice secure behavior, confirm SAS codes carefully, and keep systems fully patched. No liability is accepted for misuse, misconfiguration, or evolving security threats.

***

Thank you for choosing Convoisum for your secure communications!


