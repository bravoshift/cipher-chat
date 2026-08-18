# Cipher Chat

A peer-to-peer encrypted chat application using RSA-2048 and AES-256-GCM cryptography with WebSocket relay architecture.

## Overview

Cipher Chat is an end-to-end encrypted messaging system designed to demonstrate secure communication patterns. Two clients connect through a central WebSocket relay server, perform cryptographic key exchange, and establish an encrypted session for bidirectional message exchange. The relay server cannot decrypt messages—it operates as a blind intermediary.

## Features

- **End-to-End Encryption**: All messages encrypted with AES-256-GCM symmetric cipher
- **Key Exchange**: RSA-2048 OAEP with SHA-256 hashing for secure session key establishment
- **Async I/O**: Built on asyncio and websockets for non-blocking communication
- **Peer Detection**: Automatic peer discovery and key exchange handshake
- **Clean Exit**: `/quit` command for graceful disconnection

## Architecture

```
┌─────────────┐          ┌──────────────┐          ┌─────────────┐
│   Client A  │──────────│ Relay Server │──────────│   Client B  │
└─────────────┘          └──────────────┘          └─────────────┘
  │           │                                       │           │
  └─ RSA-2048 Key Exchange ──────────────────────────┘           │
     (Public Key Distribution)                                    │
                                                                  │
  └──────────── AES-256-GCM Encrypted Messages ─────────────────┘
     (Session Key: Encrypted with recipient's public key)
```

## Installation

### Requirements
- Python 3.8+
- Dependencies listed in `requirements.txt`

### Setup

```bash
pip install -r requirements.txt
```

## Running Cipher Chat

Cipher Chat requires three terminals: one for the relay server and two for clients.

### Terminal 1: Start the Relay Server
```bash
python server.py
```

Expected output:
```
Cipher Chat relay running on ws://localhost:8765
```

### Terminal 2: Start Client A
```bash
python client.py
```

### Terminal 3: Start Client B
```bash
python client.py
```

Once both clients connect, they will:
1. Exchange public keys via WebSocket
2. Establish AES-256 session key
3. Begin encrypted message exchange

Type messages and press Enter. Use `/quit` to exit.

## Test Result

**Observed. Sealed. Verified.**

When running the three-terminal setup above, messages sent from one client are received encrypted by the relay server, decrypted only by the peer client using the shared AES-256 session key.

## Cryptography Details

### Key Exchange: RSA-2048 OAEP
- **Algorithm**: RSA with Optimal Asymmetric Encryption Padding (OAEP)
- **Key Size**: 2048 bits
- **Hash**: SHA-256
- **Public Exponent**: 65537
- **Purpose**: Secure transmission of the symmetric session key

### Message Encryption: AES-256-GCM
- **Algorithm**: Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 12 bytes (random per message)
- **Associated Authenticated Data (AAD)**: `cipher-chat-v1` (prevents tampering)
- **Purpose**: Fast, authenticated encryption of chat messages

### Key Generation
- Session key: Cryptographically secure random 256-bit value
- Nonce: Cryptographically secure random 12-byte value per message

## Project Structure

```
cipher-chat/
├── server.py          # WebSocket relay server
├── client.py          # Client application with crypto logic
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

## Security Limitations

⚠️ **Educational Use Only**

The current implementation has the following security limitations:

1. **No Identity Authentication**: The public key exchange lacks authentication. A man-in-the-middle (MITM) attacker can intercept public keys and inject their own, allowing interception of messages.

2. **No Certificate Validation**: No mechanism to verify that a public key belongs to the intended peer.

3. **No Perfect Forward Secrecy**: Compromise of long-term keys allows decryption of past sessions.

4. **WebSocket Security**: No TLS/SSL encryption for the relay connection itself (not suitable for untrusted networks).

5. **No User Authentication**: No mechanism to verify user identity or prevent impersonation.

**This project is designed for educational purposes to demonstrate cryptographic principles. It is not suitable for production or sensitive communications.**

## Dependencies

- `cryptography>=42.0,<47.0` – Cryptographic operations
- `websockets>=12.0,<16.0` – WebSocket server and client

## License

Educational project. Use and modify freely for learning purposes.
End-to-end encrypted two-user chat using Python, RSA, AES-GCM, and WebSockets.
