from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SimulatedNode:
    node_id: str
    inbox: list[dict[str, Any]] = field(default_factory=list)


class InMemoryNetwork:
    def __init__(self) -> None:
        self.nodes: dict[str, SimulatedNode] = {}
        self.peers: dict[str, set[str]] = {}
        self.seen_messages: set[str] = set()

    def add_node(self, node_id: str) -> None:
        self.nodes[node_id] = SimulatedNode(node_id)
        self.peers[node_id] = set()

    def connect(self, a: str, b: str) -> None:
        self.peers[a].add(b)
        self.peers[b].add(a)

    def broadcast(self, origin: str, message: dict[str, Any]) -> None:
        msg_id = message["id"]
        if msg_id in self.seen_messages:
            return
        self.seen_messages.add(msg_id)
        self._flood(origin, message, visited={origin})

    def _flood(self, current: str, message: dict[str, Any], visited: set[str]) -> None:
        for peer in self.peers[current]:
            if peer in visited:
                continue
            self.nodes[peer].inbox.append(message)
            visited.add(peer)
            self._flood(peer, message, visited)
