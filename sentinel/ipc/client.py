"""Sentinel Client for fast command evaluation."""

import json
import logging
import socket
import sys
import time
from pathlib import Path
from typing import Optional
from sentinel.ipc.protocol import decode_message, encode_message
from sentinel.models import ActionEnum, CommandContext, EvaluationResult, RiskLevel, SecurityVerdict

logger = logging.getLogger(__name__)

SENTINEL_DIR = Path.home() / ".sentinel"
DEFAULT_SOCKET_PATH = str(SENTINEL_DIR / "sentinel.sock") if sys.platform != "win32" else "/tmp/agent_sentinel.sock"
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 49190
AUTH_TOKEN_FILE = SENTINEL_DIR / "auth.token"


class SentinelClient:
    """Sync client used by preexec hooks, bash shims, and MCP middleware."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        tcp_port: int = DEFAULT_TCP_PORT,
        timeout_sec: float = 0.040,  # 40ms strict timeout
        auth_token: Optional[str] = None,
    ) -> None:
        self.socket_path = socket_path
        self.tcp_port = tcp_port
        self.timeout_sec = timeout_sec
        self.auth_token = auth_token or self._load_auth_token()
        self._cached_sock: Optional[socket.socket] = None

    def _load_auth_token(self) -> Optional[str]:
        if AUTH_TOKEN_FILE.exists():
            try:
                return AUTH_TOKEN_FILE.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        return None

    def _get_connection(self) -> socket.socket:
        """Create or return active socket."""
        sock: socket.socket
        if sys.platform != "win32":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_sec)
            sock.connect(self.socket_path)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_sec)
            sock.connect((DEFAULT_TCP_HOST, self.tcp_port))
        return sock

    def check(self, ctx: CommandContext) -> EvaluationResult:
        """Send command context to Sentinel daemon and return decision."""
        t0 = time.perf_counter_ns()
        try:
            sock = self._get_connection()
            with sock:
                payload = encode_message(ctx.to_dict(), auth_token=self.auth_token)
                sock.sendall(payload)

                buffer = b""
                while b"\n" not in buffer:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk

                if not buffer:
                    raise IOError("Empty response from Sentinel daemon")

                data = decode_message(buffer.split(b"\n")[0])
                if "error" in data:
                    raise PermissionError(data["error"])

                res = EvaluationResult.from_dict(data)
                return res

        except (ConnectionRefusedError, FileNotFoundError) as exc:
            # Immediate connection failure: Daemon is simply not running
            t1 = time.perf_counter_ns()
            elapsed_ms = round((t1 - t0) / 1_000_000, 3)
            logger.debug("Sentinel daemon not running (%s)", exc)
            raise ConnectionError(f"Sentinel daemon not reachable: {exc}")

        except Exception as exc:
            # Fallback policy when daemon is unreachable or timed out:
            # Enforce Fail-Closed or Require Human Confirm
            t1 = time.perf_counter_ns()
            elapsed_ms = round((t1 - t0) / 1_000_000, 3)
            logger.warning("Sentinel Daemon check failed (%s) after %sms", exc, elapsed_ms)

            return EvaluationResult(
                action=ActionEnum.REQUIRE_HUMAN_CONFIRM,
                risk_level=RiskLevel.HIGH,
                verdict=SecurityVerdict(p_confirm=1.0),
                reasons=[f"Sentinel daemon unreachable/timeout ({exc}); fail-safe confirmation required"],
                latency_ms=elapsed_ms,
                evaluator_tier="FALLBACK_SAFETY",
                context=ctx,
            )
