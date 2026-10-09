from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _audit_path() -> Path:
    raw = os.getenv("SSH_COPILOT_AUDIT_LOG")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".ssh_copilot" / "audit.log"


@dataclass(frozen=True)
class Settings:
    model: str = field(default_factory=lambda: os.getenv("SSH_COPILOT_MODEL", "claude-sonnet-5-5"))
    command_timeout: int = field(default_factory=lambda: int(os.getenv("SSH_COPILOT_TIMEOUT", "30")))
    max_output_bytes: int = field(default_factory=lambda: int(os.getenv("SSH_COPILOT_MAX_OUTPUT", "20000")))
    audit_log: Path = field(default_factory=_audit_path)
