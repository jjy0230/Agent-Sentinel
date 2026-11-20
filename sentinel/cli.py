"""Command Line Interface for Agent-Sentinel."""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from sentinel.core.gateway import DualPathGateway
from sentinel.decision.anyjev_adapter import AnyJevAdapter
from sentinel.decision.mock_engine import MockDecisionEngine
from sentinel.interceptors.mcp_proxy import MCPSecurityProxy
from sentinel.ipc.client import SentinelClient
from sentinel.ipc.server import SentinelServer
from sentinel.models import ActionEnum, CommandContext

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """Agent-Sentinel: Ultra-low-latency terminal security gateway for AI agents."""
    pass


@main.command()
@click.option("--port", default=49190, help="Localhost TCP port (Windows)")
@click.option("--socket-path", default="/tmp/agent_sentinel.sock", help="Unix domain socket path (POSIX)")
@click.option("--engine", type=click.Choice(["mock", "anyjev"]), default="mock", help="Decision engine backend")
@click.option("--model", default="Qwen/Qwen2.5-Coder-1.5B-Instruct", help="Model path for AnyJev backend")
def daemon(port: int, socket_path: str, engine: str, model: str) -> None:
    """Start the Sentinel security daemon."""
    console.print(f"[bold cyan]Starting Agent-Sentinel Daemon...[/bold cyan]")
    if engine == "anyjev":
        decider = AnyJevAdapter(model_name_or_path=model)
    else:
        decider = MockDecisionEngine()

    gateway = DualPathGateway(decision_engine=decider)
    server = SentinelServer(gateway=gateway, socket_path=socket_path, tcp_port=port)

    console.print(f"[green]Decision Engine: {decider.engine_name}[/green]")
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping Sentinel Daemon...[/yellow]")
        server.stop()


@main.command()
@click.argument("command_text")
@click.option("--intent", default=None, help="Agent intent or goal")
@click.option("--standalone", is_flag=True, help="Force local embedded evaluation without contacting daemon")
@click.option("--silent", is_flag=True, help="Silent mode (returns exit code 0 if ALLOW, 1 otherwise)")
@click.option("--json-out", is_flag=True, help="Output decision in JSON format")
def check(command_text: str, intent: str, standalone: bool, silent: bool, json_out: bool) -> None:
    """Inspect a command directly or via running daemon."""
    ctx = CommandContext(
        raw_command=command_text,
        agent_intent=intent,
        workspace_path=os.getcwd(),
        caller_agent="cli-check",
    )

    if standalone:
        gw = DualPathGateway(decision_engine=MockDecisionEngine())
        res = gw.evaluate(ctx)
    else:
        client = SentinelClient()
        try:
            res = client.check(ctx)
            if res.evaluator_tier == "FALLBACK_SAFETY":
                gw = DualPathGateway(decision_engine=MockDecisionEngine())
                res = gw.evaluate(ctx)
                res.reasons.insert(0, "Note: Daemon not running, evaluated via embedded engine")
        except ConnectionError:
            gw = DualPathGateway(decision_engine=MockDecisionEngine())
            res = gw.evaluate(ctx)
            res.reasons.insert(0, "Note: Daemon not running, evaluated via embedded engine")

    if silent:
        sys.exit(0 if res.action == ActionEnum.ALLOW else 1)

    if json_out:
        click.echo(res.to_json())
        sys.exit(0 if res.action == ActionEnum.ALLOW else 1)

    table = Table(title="Agent-Sentinel Evaluation", show_header=True)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    action_style = "green" if res.action == ActionEnum.ALLOW else ("red" if res.action == ActionEnum.BLOCK else "yellow")
    table.add_row("Action", f"[{action_style}]{res.action.value}[/{action_style}]")
    table.add_row("Risk Level", res.risk_level.value)
    table.add_row("Latency", f"{res.latency_ms:.3f} ms")
    table.add_row("Evaluator", res.evaluator_tier)
    table.add_row("P(ALLOW)", f"{res.verdict.p_allow:.4f}")
    table.add_row("P(BLOCK)", f"{res.verdict.p_block:.4f}")
    table.add_row("P(CONFIRM)", f"{res.verdict.p_confirm:.4f}")
    table.add_row("Is Destructive", str(res.verdict.is_destructive))
    table.add_row("Is Exfiltration", str(res.verdict.is_exfiltration))
    table.add_row("Is Obfuscated", str(res.verdict.is_obfuscated))
    table.add_row("Reasons", "\n".join(res.reasons) if res.reasons else "None")

    console.print(table)
    sys.exit(0 if res.action == ActionEnum.ALLOW else 1)


@main.command()
@click.option("--no-daemon", is_flag=True, help="Run embedded evaluation without daemon")
def mcp(no_daemon: bool) -> None:
    """Start MCP Security Proxy stdio server."""
    proxy = MCPSecurityProxy(use_daemon=not no_daemon)
    proxy.run_stdio_loop()


@main.command()
@click.option("--iterations", default=500, help="Number of benchmark iterations")
def bench(iterations: int) -> None:
    """Benchmark end-to-end evaluation latency across L1 and L2 paths."""
    from benchmarks.bench_latency import run_benchmark
    run_benchmark(iterations)


@main.command(name="eval")
def eval_security() -> None:
    """Evaluate FPR, Recall, and Obfuscation Detection across benchmark datasets."""
    from benchmarks.eval_security import run_security_eval
    run_security_eval()


@main.command()
@click.option("--config-path", default=None, help="Path to claude.json (defaults to ~/.claude.json)")
def configure_claude(config_path: str) -> None:
    """Automatically register Agent-Sentinel MCP server into Claude Code configuration."""
    target = Path(config_path) if config_path else (Path.home() / ".claude.json")
    config_data = {}
    if target.exists():
        try:
            config_data = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            pass

    mcp_servers = config_data.setdefault("mcpServers", {})
    mcp_servers["agent-sentinel"] = {
        "command": sys.executable,
        "args": ["-m", "sentinel.cli", "mcp"],
    }

    target.write_text(json.dumps(config_data, indent=2), encoding="utf-8")
    console.print(f"[bold green]Successfully configured Agent-Sentinel MCP server in: {target}[/bold green]")


@main.command()
@click.option("--shell", type=click.Choice(["bash", "zsh"]), default="bash", help="Target shell")
def install_hook(shell: str) -> None:
    """Inject Sentinel preexec hook source into shell RC profile."""
    rc_file = Path.home() / (".bashrc" if shell == "bash" else ".zshrc")
    hook_script = Path(__file__).resolve().parent / "interceptors" / "shell_hooks" / f"sentinel.{shell}"

    source_line = f"\n# Added by Agent-Sentinel\n[ -f \"{hook_script}\" ] && source \"{hook_script}\"\n"

    existing = rc_file.read_text(encoding="utf-8") if rc_file.exists() else ""
    if str(hook_script) in existing:
        console.print(f"[yellow]Hook is already present in {rc_file}[/yellow]")
        return

    with open(rc_file, "a", encoding="utf-8") as f:
        f.write(source_line)

    console.print(f"[bold green]Successfully installed {shell} preexec hook into {rc_file}[/bold green]")


@main.command()
def configure_cursor() -> None:
    """Output Cursor IDE MCP and Terminal integration settings."""
    cursor_json = {
        "mcpServers": {
            "agent-sentinel": {
                "command": sys.executable,
                "args": ["-m", "sentinel.cli", "mcp"]
            }
        }
    }
    console.print("[bold cyan]To integrate with Cursor, add this to Cursor Settings -> Features -> MCP:[/bold cyan]")
    console.print(json.dumps(cursor_json, indent=2))


if __name__ == "__main__":
    main()
