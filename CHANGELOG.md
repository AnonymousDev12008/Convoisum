# [2.0.0] - 2025 - 08 - 24

Security: length‑prefixed framing to prevent TCP message boundary issues

Security: strict per‑direction sequence numbers bound in AEAD associated data

Security: transcript‑derived salts for HKDF (session key and SAS)

Security: SAS strengthened to 6 words from a 256‑word list (~48 bits)

Security: removed sensitive prints in public key validation

Security: hardened Tor host config (no SocksPort, ClientOnly 1)

Reliability: pre‑bind local port before creating onion service

UX: clipboard copying disabled by default; can be enabled in code

Docs: README updated with v2 notes and compatibility warning
