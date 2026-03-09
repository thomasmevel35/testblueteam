from __future__ import annotations

import argparse
import asyncio

from p2p.node import Node


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run a minimal blockchain P2P node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peer", action="append", default=[], help="peer as host:port")
    args = parser.parse_args()

    node = Node(args.host, args.port)
    for peer in args.peer:
        host, port = peer.split(":", 1)
        node.add_peer(host, int(port))

    await node.start()
    print(f"Node started on {args.host}:{args.port} with peers={node.peers}")
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
