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
        if packet.get("to") != self.client_id:
            return

        encrypted_key = base64.b64decode(packet["key"])

        self.session_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        self.ready.set()
        print("\n[+] AES-256 session established.")

    def handle_message(self, packet):
        if not self.session_key:
            return

        nonce = base64.b64decode(packet["nonce"])
        ciphertext = base64.b64decode(packet["ciphertext"])

        plaintext = AESGCM(self.session_key).decrypt(
            nonce,
            ciphertext,
            AAD,
        )

        print(f"\nPeer: {plaintext.decode()}")
        print("You: ", end="", flush=True)

    async def send_messages(self, websocket):
        print("[*] Waiting for a second user...")
        await self.ready.wait()
        print("[*] Secure chat ready. Type /quit to exit.")

        while True:
            message = await asyncio.to_thread(input, "You: ")

            if message.strip().lower() == "/quit":
                await websocket.close()
                return

            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(self.session_key).encrypt(
                nonce,
                message.encode(),
                AAD,
            )

            await websocket.send(json.dumps({
                "type": "message",
                "from": self.client_id,
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }))

    async def run(self):
        async with websockets.connect(SERVER) as websocket:
            print(f"[*] Connected as {self.client_id}")
            await websocket.send(self.public_key_packet())

            receiver = asyncio.create_task(self.receive(websocket))
            sender = asyncio.create_task(self.send_messages(websocket))

            done, pending = await asyncio.wait(
                {receiver, sender},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(CipherClient().run())
    except KeyboardInterrupt:
        print("\nDisconnected.")
