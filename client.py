import asyncio
import base64
import json
import secrets
import sys

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SERVER = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8765"
AAD = b"cipher-chat-v1"


class CipherClient:
    def __init__(self):
        self.client_id = secrets.token_hex(8)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.peer_id = None
        self.peer_public_key = None
        self.session_key = None
        self.ready = asyncio.Event()

    def public_key_packet(self, reply=False):
        public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return json.dumps({
            "type": "public_key",
            "reply": reply,
            "from": self.client_id,
            "key": base64.b64encode(public_pem).decode(),
        })

    async def receive(self, websocket):
        async for raw_packet in websocket:
            try:
                packet = json.loads(raw_packet)
                packet_type = packet.get("type")

                if packet.get("from") == self.client_id:
                    continue

                if packet_type == "public_key":
                    await self.handle_public_key(packet, websocket)

                elif packet_type == "session_key":
                    self.handle_session_key(packet)

                elif packet_type == "message":
                    self.handle_message(packet)

            except Exception as error:
                print(f"\n[!] Rejected invalid packet: {error}")

    async def handle_public_key(self, packet, websocket):
        self.peer_id = packet["from"]
        public_pem = base64.b64decode(packet["key"])

        self.peer_public_key = serialization.load_pem_public_key(
            public_pem
        )

        print("\n[+] Peer public key received.")
        if not packet.get("reply"):
            await websocket.send(self.public_key_packet(reply=True))

        if self.client_id < self.peer_id and self.session_key is None:
            self.session_key = AESGCM.generate_key(bit_length=256)

            encrypted_key = self.peer_public_key.encrypt(
                self.session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            await websocket.send(json.dumps({
                "type": "session_key",
                "from": self.client_id,
                "to": self.peer_id,
                "key": base64.b64encode(encrypted_key).decode(),
            }))

            self.ready.set()
            print("[+] AES-256 session established.")

    def handle_session_key(self, packet):
        if
