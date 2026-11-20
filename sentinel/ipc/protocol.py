"""IPC Protocol framing for sub-millisecond local communication."""

import json
from typing import Any, Dict


def encode_message(data: Dict[str, Any]) -> bytes:
    """Encode payload to single-line JSON with newline framing."""
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def decode_message(line: bytes) -> Dict[str, Any]:
    """Decode raw bytes from single-line JSON."""
    return json.loads(line.decode("utf-8"))
