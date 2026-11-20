"""Model Context Protocol (MCP) Security Proxy.

Integrates seamlessly with Claude Code, Cursor, and Windsurf by exposing an MCP
server that intercepts terminal/bash execution tools before delegating to the OS.
"""

import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional
from sentinel.core.gateway import DualPathGateway
from sentinel.ipc.client import SentinelClient
from sentinel.models import ActionEnum, CommandContext, EvaluationResult

logger = logging.getLogger(__name__)


class MCPSecurityProxy:
    """MCP JSON-RPC Stdio server intercepting tool execution calls."""

    def __init__(self, use_daemon: bool = True) -> None:
        self.use_daemon = use_daemon
        self.client = SentinelClient() if use_daemon else None
        self.embedded_gateway = DualPathGateway() if not use_daemon else None

    def evaluate_command(self, cmd: str, intent: Optional[str] = None, workspace: Optional[str] = None) -> EvaluationResult:
        ctx = CommandContext(
            raw_command=cmd,
            agent_intent=intent,
            workspace_path=workspace or os.getcwd(),
            caller_agent="mcp-agent",
        )
        if self.client:
            try:
                return self.client.check(ctx)
            except Exception as e:
                logger.warning("Daemon check failed in MCP proxy (%s), falling back to embedded gateway", e)
                if not self.embedded_gateway:
                    self.embedded_gateway = DualPathGateway()
                return self.embedded_gateway.evaluate(ctx)
        elif self.embedded_gateway:
            return self.embedded_gateway.evaluate(ctx)
        else:
            raise RuntimeError("No evaluation backend configured")

    def run_stdio_loop(self) -> None:
        """Standard JSON-RPC 2.0 loop reading from stdin and writing to stdout."""
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                req = json.loads(line)
                method = req.get("method")
                req_id = req.get("id")

                if method == "initialize":
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {
                                "tools": {}
                            },
                            "serverInfo": {
                                "name": "agent-sentinel-mcp-guard",
                                "version": "0.1.0"
                            }
                        }
                    }
                    self._send_response(resp)

                elif method == "tools/list":
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "tools": [
                                {
                                    "name": "bash",
                                    "description": "Execute a terminal bash command safely protected by Agent-Sentinel guardrails",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {
                                            "command": {"type": "string", "description": "Command to run"},
                                            "intent": {"type": "string", "description": "Goal or rationale for the command"},
                                            "confirmed": {"type": "boolean", "description": "Set to true only after the user explicitly confirmed ambiguous high-risk operations"}
                                        },
                                        "required": ["command"]
                                    }
                                }
                            ]
                        }
                    }
                    self._send_response(resp)

                elif method == "tools/call":
                    params = req.get("params", {})
                    tool_name = params.get("name")
                    args = params.get("arguments", {})

                    if tool_name in ["bash", "execute_command"]:
                        cmd = args.get("command", "")
                        intent = args.get("intent")
                        user_confirmed = bool(args.get("confirmed", False))
                        eval_res = self.evaluate_command(cmd, intent=intent)

                        # Hard BLOCK
                        if eval_res.action == ActionEnum.BLOCK:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "isError": True,
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": (
                                                f"[AGENT-SENTINEL SECURITY ALERT] Command execution BLOCKED.\n"
                                                f"Command: {cmd}\n"
                                                f"Reasons: {', '.join(eval_res.reasons)}\n"
                                                f"Risk Level: {eval_res.risk_level.value}\n"
                                                f"Audit Latency: {eval_res.latency_ms} ms"
                                            )
                                        }
                                    ]
                                }
                            }
                            self._send_response(resp)
                            continue

                        # REQUIRE_HUMAN_CONFIRM
                        elif eval_res.action == ActionEnum.REQUIRE_HUMAN_CONFIRM:
                            if not user_confirmed:
                                resp = {
                                    "jsonrpc": "2.0",
                                    "id": req_id,
                                    "result": {
                                        "isError": True,
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": (
                                                    f"[AGENT-SENTINEL GUARD] Command execution paused pending human approval.\n"
                                                    f"Command: {cmd}\n"
                                                    f"Reasons: {', '.join(eval_res.reasons)}\n"
                                                    f"Action Required: You MUST ask the user in chat for explicit permission before proceeding. "
                                                    f"Once the user approves, re-invoke this tool with confirmed=true."
                                                )
                                            }
                                        ]
                                    }
                                }
                                self._send_response(resp)
                                continue

                        # ALLOW or Confirmed: Execute command transparently
                        try:
                            proc = subprocess.run(
                                cmd,
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=120,
                            )
                            output = proc.stdout + (("\nSTDERR:\n" + proc.stderr) if proc.stderr else "")
                            resp = {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "isError": proc.returncode != 0,
                                    "content": [
                                        {"type": "text", "text": output}
                                    ]
                                }
                            }
                        except Exception as e:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "isError": True,
                                    "content": [{"type": "text", "text": f"Execution failed: {e}"}]
                                }
                            }
                        self._send_response(resp)

                else:
                    if req_id is not None:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32601, "message": "Method not found"}
                        }
                        self._send_response(resp)

            except Exception as exc:
                sys.stderr.write(f"MCP Proxy error: {exc}\n")

    def _send_response(self, resp: Dict[str, Any]) -> None:
        payload = json.dumps(resp)
        sys.stdout.write(payload + "\n")
        sys.stdout.flush()
