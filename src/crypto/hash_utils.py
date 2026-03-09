from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_dict(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_hex(canonical)


def merkle_root(items: list[dict[str, Any]]) -> str:
    if not items:
        return sha256_hex(b"")

    level = [hash_dict(item) for item in items]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            sha256_hex((level[i] + level[i + 1]).encode("utf-8"))
            for i in range(0, len(level), 2)
        ]
    return level[0]
