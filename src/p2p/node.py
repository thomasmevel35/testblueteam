from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from core.blockchain import Blockchain
from core.models import Block, Transaction


@dataclass
class PeerConnection:
    host: str
    port: int


@dataclass
class Node:
    host: str
    port: int
    blockchain: Blockchain = field(default_factory=Blockchain)

    def __post_init__(self) -> None:
        self.peers: set[tuple[str, int]] = set()
        self.seen_messages: set[str] = set()
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_connection, self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def add_peer(self, host: str, port: int) -> None:
        if (host, port) != (self.host, self.port):
            self.peers.add((host, port))

    async def broadcast(self, msg_type: str, payload: dict[str, Any], source: tuple[str, int] | None = None) -> None:
        message = {
            "id": str(uuid.uuid4()),
            "type": msg_type,
            "payload": payload,
        }
        self.seen_messages.add(message["id"])
        data = (json.dumps(message) + "\n").encode("utf-8")
        for peer in self.peers:
            if source and peer == source:
                continue
            try:
                reader, writer = await asyncio.open_connection(*peer)
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except OSError:
                continue

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_name = writer.get_extra_info("peername")
        source = (peer_name[0], peer_name[1]) if peer_name else None
        try:
            raw = await reader.readline()
            if not raw:
                return
            message = json.loads(raw.decode("utf-8"))
            await self._on_message(message, source)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _on_message(self, message: dict[str, Any], source: tuple[str, int] | None) -> None:
        msg_id = message.get("id")
        if msg_id in self.seen_messages:
            return
        self.seen_messages.add(msg_id)

        msg_type = message["type"]
        payload = message["payload"]

        if msg_type == "peer_announce":
            self.add_peer(payload["host"], payload["port"])
        elif msg_type == "transaction":
            tx = Transaction.from_dict(payload)
            self.blockchain.add_transaction(tx)
        elif msg_type == "block":
            block = Block.from_dict(payload)
            self.blockchain.append_block(block)
        elif msg_type == "chain":
            candidate = Blockchain.import_chain(payload["chain"])
            self.blockchain.replace_chain(candidate)

        await self._relay_message(message, source)

    async def _relay_message(self, message: dict[str, Any], source: tuple[str, int] | None) -> None:
        data = (json.dumps(message) + "\n").encode("utf-8")
        for peer in self.peers:
            if source and peer == source:
                continue
            try:
                reader, writer = await asyncio.open_connection(*peer)
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except OSError:
                continue
