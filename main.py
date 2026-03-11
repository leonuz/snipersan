#!/usr/bin/env python3
"""SniperSan - AI-powered Web Penetration Testing Agent."""
import sys
import os
import argparse
from pathlib import Path

# Ensure we can import from project root
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

console = Console()

BANNER = """
[bold magenta]
███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ ███████╗ █████╗ ███╗   ██╗
██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗████╗  ██║
███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝███████╗███████║██╔██╗ ██║
╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══██║██║╚██╗██║
███████║██║ ╚████║██║██║     ███████╗██║  ██║███████║██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold magenta]
[dim cyan]          AI-Powered Web Penetration Testing Agent v1.0[/dim cyan]
[dim red]          For authorized testing only. Use responsibly.[/dim red]
"""


def show_menu() -> str:
    """Display main menu and return choice."""
    table = Table(box=box.ROUNDED, border_style="magenta", show_header=False)
    table.add_column("Key", style="bold cyan", width=4)
    table.add_column("Option", style="white")
    table.add_row("1", "Auto Mode  — Full automated pentest (agent-driven)")
    table.add_row("2", "Chat Mode  — Interactive mode (you guide the agent)")
    table.add_row("3", "Quick Scan — Fast recon only (no active exploiting)")
    table.add_row("q", "Quit")
    console.print(table)
    return Prompt.ask("\n[bold cyan]Select mode[/bold cyan]", choices=["1", "2", "3", "q"])


def get_target() -> str:
    """Prompt for target with validation."""
    while True:
        target = Prompt.ask("\n[bold yellow]Enter target[/bold yellow] [dim](domain or URL)[/dim]")
        target = target.strip()
        if not target:
            console.print("[red]Target cannot be empty.[/red]")
            continue

        # Normalize — IPs default to http, domains to https
        if not target.startswith(("http://", "https://")):
            import re as _re
            if _re.match(r"^\d+\.\d+\.\d+\.\d+", target):
                target = "http://" + target
            else:
                target = "https://" + target

        console.print(f"  [dim]→ Target: {target}[/dim]")
        return target


def get_report_format() -> str:
    """Prompt for report format."""
    table = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    table.add_column("Key", style="bold cyan", width=4)
    table.add_column("Format")
    table.add_row("1", "HTML  (rich, visual dashboard)")
    table.add_row("2", "Markdown (structured text)")
    table.add_row("3", "JSON  (machine-readable)")
    console.print("\n[bold]Report format:[/bold]")
    console.print(table)

    choice = Prompt.ask("Format", choices=["1", "2", "3"], default="1")
    return {"1": "html", "2": "markdown", "3": "json"}[choice]


def disclaimer_check() -> bool:
    """Show legal disclaimer and get confirmation."""
    console.print(Panel(
        "[bold red]LEGAL DISCLAIMER[/bold red]\n\n"
        "This tool is for [bold]authorized security testing only[/bold].\n"
        "Using this tool against systems without explicit written permission\n"
        "is [bold red]illegal[/bold red] and may result in criminal prosecution.\n\n"
        "By continuing, you confirm:\n"
        "  • You have explicit authorization to test the target\n"
        "  • You understand and accept all legal responsibility\n"
        "  • This is used for: CTF, authorized pentest, or your own systems",
        border_style="red"
    ))
    return Confirm.ask("[bold]I have authorization to test the target[/bold]", default=False)


def run_quick_scan(target: str) -> None:
    """Quick passive recon without exploitation."""
    from tools import recon
    from tools.reporter import generate_report

    console.print(Panel(
        f"[bold]Quick Scan[/bold]: {target}",
        title="Recon Only Mode", border_style="cyan"
    ))

    findings = {}

    steps = [
        ("Headers", lambda: recon.check_headers(target)),
        ("SSL/TLS", lambda: recon.check_ssl(target)),
        ("Robots/Sitemap", lambda: recon.check_robots_sitemap(target)),
        ("Technology", lambda: recon.fingerprint_tech(target)),
        ("Port Scan", lambda: recon.run_nmap(target, "quick")),
    ]

    for name, fn in steps:
        with console.status(f"[cyan]Running {name}...[/cyan]"):
            try:
                result = fn()
                key = name.lower().replace("/", "_").replace(" ", "_")
                findings[key] = result
                console.print(f"  [green]✓ {name}[/green]")
            except Exception as e:
                console.print(f"  [red]✗ {name}: {e}[/red]")

    fmt = get_report_format()
    path = generate_report(target, findings, fmt, "Quick reconnaissance scan results.")
    console.print(f"\n[bold green]Report saved: {path}[/bold green]")


def parse_args():
    """Parse CLI arguments for non-interactive operation."""
    parser = argparse.ArgumentParser(
        description="SniperSan — AI-Powered Web Penetration Testing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                                    # Interactive mode
  python3 main.py -t https://example.com -m auto    # Fully automated pentest
  python3 main.py -t https://example.com -m quick   # Quick passive recon
  python3 main.py -t https://example.com -m auto -f markdown
        """
    )
    parser.add_argument("-t", "--target", help="Target URL or domain")
    parser.add_argument("-m", "--mode", choices=["auto", "chat", "quick"],
                        help="Scan mode: auto, chat, or quick")
    parser.add_argument("-f", "--format", dest="fmt",
                        choices=["html", "markdown", "json"], default="html",
                        help="Report format (default: html)")
    parser.add_argument("-p", "--profile",
                        choices=["stealth", "aggressive", "api-only", "wordpress"],
                        help="Scan profile: stealth (passive only), aggressive (all tools), api-only (API focus), wordpress (WP-specific)")
    parser.add_argument("--llm", choices=["claude", "ollama"],
                        help="LLM backend to use (skips interactive selector)")
    parser.add_argument("--model",
                        help="Model name for Ollama backend (e.g. qwen3.5:9b, llama3.1:8b)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip legal disclaimer (confirm you have authorization)")
    return parser.parse_args()


def main():
    args = parse_args()
    console.print(BANNER)

    # LLM selector
    from llm import select_llm
    llm_backend = select_llm(llm_flag=args.llm, model_flag=getattr(args, "model", None))
    console.print(f"\n[bold magenta]LLM:[/bold magenta] {llm_backend.name}\n")

    # Legal disclaimer
    if args.yes:
        console.print("[dim]Authorization confirmed via --yes flag.[/dim]")
    elif not disclaimer_check():
        console.print("\n[red]Aborted. Authorization not confirmed.[/red]")
        sys.exit(0)

    # Target
    target = args.target if args.target else get_target()
    if not target.startswith(("http://", "https://")):
        # IPs default to http (rarely have valid SSL certs)
        import re as _re
        if _re.match(r"^\d+\.\d+\.\d+\.\d+", target):
            target = "http://" + target
        else:
            target = "https://" + target

    # Mode
    if args.mode:
        choice = {"auto": "1", "chat": "2", "quick": "3"}[args.mode]
    else:
        choice = show_menu()

    if choice == "q":
        console.print("\n[dim]Goodbye.[/dim]")
        sys.exit(0)

    elif choice == "3":
        run_quick_scan(target)

    elif choice in ("1", "2"):
        from agent import PentestAgent

        if choice == "1":
            fmt = args.fmt if args.mode else get_report_format()
            console.print(f"\n[bold green]Starting automated pentest...[/bold green]\n")
            agent = PentestAgent(llm_backend=llm_backend)
            result = agent.run(target, fmt, profile=getattr(args, 'profile', None))

            if result.get("report_path"):
                console.print(Panel(
                    f"[bold green]Pentest Complete![/bold green]\n\n"
                    f"Report: [cyan]{result['report_path']}[/cyan]\n"
                    f"Iterations: {result['iterations']}",
                    border_style="green"
                ))
            else:
                console.print("\n[yellow]No report generated.[/yellow]")

        else:  # choice == "2"
            agent = PentestAgent(llm_backend=llm_backend)
            agent.chat(target)


if __name__ == "__main__":
    main()
