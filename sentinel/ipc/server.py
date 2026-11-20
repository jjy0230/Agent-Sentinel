"""Agent-Sentinel Daemon Server.

Listens for incoming command inspection requests over local IPC
(Unix Domain Socket on POSIX, Localhost TCP loopback on Windows)
and responds within sub-millisecond overhead.
"""

import asyncio
import logging
import os
import sys
from typing import Optional
from sentinel.core.gateway import DualPathGateway
from sentinel.decision.base import BaseDecisionEngine
from sentinel.ipc.protocol import decode_message, encode_message
from sentinel.models import CommandContext

logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = "/tmp/agent_sentinel.sock"
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 49190


class SentinelServer:
    """High-throughput async daemon server."""

    def __init__(
        self,
        gateway: Optional[DualPathGateway] = None,
        socket_path: str = DEFAULT_SOCKET_PATH,
        tcp_port: int = DEFAULT_TCP_PORT,
    ) -> None:
        self.gateway = gateway or DualPathGateway()
        self.socket_path = socket_path
        self.tcp_port = tcp_port
        self._server: Optional[asyncio.AbstractServer] = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break

                req_data = decode_message(line)
                ctx = CommandContext.from_dict(req_data)

                # Evaluate synchronously in executor if heavy, or directly for fast path
                result = self.gateway.evaluate(ctx)

                resp_bytes = encode_message(result.to_dict())
                writer.write(resp_bytes)
                await writer.drain()
        except Exception as exc:
            logger.error("Error processing sentinel request: %s", exc)
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        """Start listening on socket/port."""
        if sys.platform != "win32":
            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self.socket_path
            )
            logger.info("Sentinel Daemon listening on Unix socket: %s", self.socket_path)
        else:
            self._server = await asyncio.start_server(
                self._handle_client, host=DEFAULT_TCP_HOST, port=self.tcp_port
            )
            logger.info("Sentinel Daemon listening on TCP: %s:%d", DEFAULT_TCP_HOST, self.tcp_port)

        async with self._server:
            await self._server.serve_forever()

    def stop(self) -> None:
        """Stop server."""
        if self._server:
            self._server.close()
            if sys.platform != "win32" and os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
