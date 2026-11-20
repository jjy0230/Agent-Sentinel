"""IPC Protocol framing for sub-millisecond local communication."""

import json
from typing import Any, Dict, Optional


def encode_message(data: Dict[str, Any], auth_token: Optional[str] = None) -> bytes:
    """Encode payload to single-line JSON with optional auth token framing."""
    if auth_token and "auth_token" not in data:
        data = dict(data)
        data["auth_token"] = auth_token
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def decode_message(line: bytes) -> Dict[str, Any]:
    """Decode raw bytes from single-line JSON."""
    return json.loads(line.decode("utf-8"))
