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
from .safety