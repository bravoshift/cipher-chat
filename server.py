import asyncio
import websockets

connected_clients = set()


async def relay(websocket):
    connected_clients.add(websocket)
    print(f"Client connected. Total: {len(connected_clients)}")

    try:
        async for encrypted_packet in websocket:
            recipients = connected_clients - {websocket}

            if recipients:
                await asyncio.gather(
                    *(client.send(encrypted_packet) for client in recipients),
                    return_exceptions=True,
                )

            print(
                f"Relayed encrypted packet "
                f"({len(encrypted_packet)} bytes)"
            )

    except websockets.ConnectionClosed:
        pass

    finally:
        connected_clients.discard(websocket)
        print(f"Client disconnected. Total: {len(connected_clients)}")


async def main():
    print("Cipher Chat relay running on ws://localhost:8765")

    async with websockets.serve(relay, "0.0.0.0", 8765):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
