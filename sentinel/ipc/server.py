"""Agent-Sentinel Daemon Server.

Listens for incoming command inspection requests over local IPC
(Unix Domain Socket on POSIX, Localhost TCP loopback on Windows)
and responds within sub-millisecond overhead.
"""

import asyncio
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Optional
from sentinel.core.gateway import DualPathGateway
from sentinel.ipc.protocol import decode_message, encode_message
from sentinel.models import CommandContext

logger = logging.getLogger(__name__)

SENTINEL_DIR = Path.home() / ".sentinel"
DEFAULT_SOCKET_PATH = str(SENTINEL_DIR / "sentinel.sock") if sys.platform != "win32" else "/tmp/agent_sentinel.sock"
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 49190
AUTH_TOKEN_FILE = SENTINEL_DIR / "auth.token"


class SentinelServer:
    """High-throughput async daemon server with session authentication."""

    def __init__(
        self,
        gateway: Optional[DualPathGateway] = None,
        socket_path: str = DEFAULT_SOCKET_PATH,
        tcp_port: int = DEFAULT_TCP_PORT,
        require_auth: bool = True,
    ) -> None:
        self.gateway = gateway or DualPathGateway()
        self.socket_path = socket_path
        self.tcp_port = tcp_port
        self.require_auth = require_auth
        self._server: Optional[asyncio.AbstractServer] = None
        self.auth_token: Optional[str] = None

        SENTINEL_DIR.mkdir(parents=True, exist_ok=True)
        if self.require_auth:
            self._init_auth_token()

    def _init_auth_token(self) -> None:
        """Generate and securely persist session auth token."""
        self.auth_token = secrets.token_hex(16)
        try:
            with open(AUTH_TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(self.auth_token)
            if sys.platform != "win32":
                os.chmod(AUTH_TOKEN_FILE, 0o600)
            logger.debug("Session auth token written to %s", AUTH_TOKEN_FILE)
        except OSError as exc:
            logger.warning("Could not persist auth token file (%s)", exc)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break

                req_data = decode_message(line)

                # Validate auth token if enabled
                if self.require_auth and self.auth_token:
                    client_token = req_data.get("auth_token")
                    if client_token != self.auth_token:
                        logger.warning("Rejected unauthorized client connection (token mismatch)")
                        err_resp = {"error": "Unauthorized: invalid auth_token"}
                        writer.write(encode_message(err_resp))
                        await writer.drain()
                        break

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
            socket_dir = os.path.dirname(self.socket_path)
            if socket_dir:
                os.makedirs(socket_dir, exist_ok=True)
            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass

            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self.socket_path
            )
            # Restrict socket permissions to current user only (0600)
            try:
                os.chmod(self.socket_path, 0o600)
            except OSError:
                pass
            logger.info("Sentinel Daemon listening on Unix socket: %s", self.socket_path)
        else:
            self._server = await asyncio.start_server(
                self._handle_client, host=DEFAULT_TCP_HOST, port=self.tcp_port
            )
            logger.info("Sentinel Daemon listening on TCP: %s:%d", DEFAULT_TCP_HOST, self.tcp_port)

        async with self._server:
            await self._server.serve_forever()

    def stop(self) -> None:
        """Stop server and clean up temporary socket files."""
        if self._server:
            self._server.close()
            if sys.platform != "win32" and os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
        if AUTH_TOKEN_FILE.exists():
            try:
                AUTH_TOKEN_FILE.unlink()
            except OSError:
                pass
