from __future__ import annotations

import argparse
import getpass
import sys

import paramiko
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table

from .audit import AuditLog
from .config import Settings
from .llm import CommandGenerator, LLMError
from .safety import Risk, Verdict, classify
from .ssh_client import SSHSession

console = Console()
RISK_STYLE = {Risk.LOW: "green", Risk.MEDIUM: "yellow", Risk.HIGH: "red", Risk.BLOCKED: "bold red"}

HELP = """[bold]Perintah:[/]
  /help      tampilkan bantuan
  /context   info server yang dikirim ke LLM
  /history   riwayat sesi
  /dryrun    toggle dry-run (hanya tampilkan command, tidak dijalankan)
  /exit      keluar
Selain itu, ketik permintaan dalam bahasa natural, mis. [italic]"cek disk yang hampir penuh"[/]."""


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="ssh-copilot", description="Natural Language to SSH Command Executor")
    p.add_argument("target", help="[user@]host")
    p.add_argument("-p", "--port", type=int, default=22)
    p.add_argument("-i", "--identity", help="Path private key")
    p.add_argument("--password", action="store_true", help="Prompt password (disarankan pakai key)")
    p.add_argument("--model", help="Override model Claude")
    p.add_argument("--auto-approve-low", action="store_true", help="Jalankan otomatis command risiko LOW")
    p.add_argument("--dry-run", action="store_true", help="Jangan eksekusi, hanya tampilkan")
    p.add_argument("--summarize", action="store_true", help="Rangkum output dengan LLM")
    p.add_argument("--accept-new", action="store_true", help="Terima host key baru (TIDAK aman untuk jaringan tak tepercaya)")
    return p.parse_args(argv)


def render_proposal(command: str, explanation: str, verdict: Verdict) -> None:
    style = RISK_STYLE[verdict.risk]
    table = Table.grid(padding=(0, 1))
    table.add_row("[bold]Risiko[/]", f"[{style}]{verdict.risk.name}[/]")
    table.add_row("[bold]Alasan[/]", "; ".join(verdict.reasons))
    if explanation:
        table.add_row("[bold]Penjelasan[/]", explanation)
    console.print(Panel(Syntax(command, "bash", theme="ansi_dark", word_wrap=True), title="Command", border_style=style))
    console.print(table)

def confirm(command: str, explanation: str, verdict: Verdict, auto_low: bool) -> str | None:
    """Return command final yang boleh dijalankan, atau None jika dibatalkan/diblokir."""
    while True:
        render_proposal(command, explanation, verdict)
        if verdict.risk == Risk.BLOCKED:
            console.print("[bold red]⛔ Command DIBLOKIR oleh kebijakan keamanan. Tidak akan dijalankan.[/]")
            return None
        if verdict.risk == Risk.LOW and auto_low:
            return command
        if verdict.risk == Risk.HIGH:
            ans = Prompt.ask("[red]Risiko TINGGI.[/] Ketik 'yes' untuk jalankan, 'e' untuk edit, Enter untuk batal", default="")
            ans = ans.strip().lower()
            if ans == "yes":
                return command
            if ans != "e":
                return None
        else:
            ans = Prompt.ask("Jalankan? ([y]a / [n]o / [e]dit)", choices=["y", "n", "e"], default="n")
            if ans == "y":
                return command
            if ans == "n":
                return None
        command = Prompt.ask("Edit command", default=command).strip()
        verdict = classify(command)
        explanation = "(diedit manual)"

