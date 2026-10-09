"""Wrapper Paramiko: koneksi, context server, dan eksekusi command dengan timeout."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import paramiko


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def combined(self) -> str:
        parts = [p for p in (self.stdout, self.stderr) if p]
        return "\n".join(parts)


class SSHSession:
    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_file: str | None = None,
        password: str | None = None,
        accept_new_host_keys: bool = False,
        connect_timeout: int = 10,
    ):
        self.host, self.user, self.port = host, user, port
        self.key_file, self.password = key_file, password
        self.accept_new = accept_new_host_keys
        self.connect_timeout = connect_timeout
        self.client = paramiko.SSHClient()

    def connect(self) -> None:
        self.client.load_system_host_keys()
        known = Path.home() / ".ssh" / "known_hosts"
        if known.exists():
            self.client.load_host_keys(str(known))
        # Default STRICT: host tak dikenal ditolak (cegah MITM). Opt-in lewat --accept-new.
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if self.accept_new else paramiko.RejectPolicy()
        )
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            key_filename=str(Path(self.key_file).expanduser()) if self.key_file else None,
            password=self.password,
            timeout=self.connect_timeout,
            allow_agent=True,
            look_for_keys=True,
        )

    def close(self) -> None:
        self.client.close()

    def run(self, command: str, timeout: int = 30, max_bytes: int = 20000) -> ExecResult:
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise ConnectionError("Koneksi SSH terputus.")
        chan = transport.open_session()
        start = time.monotonic()
        deadline = start + timeout
        out, err = bytearray(), bytearray()
        truncated = timed_out = False
        chan.exec_command(command)

        def drain() -> None:
            nonlocal truncated
            while chan.recv_ready():
                data = chan.recv(65536)
                if len(out) < max_bytes:
                    out.extend(data[: max_bytes - len(out)])
                else:
                    truncated = True
            while chan.recv_stderr_ready():
                data = chan.recv_stderr(65536)
                if len(err) < max_bytes:
                    err.extend(data[: max_bytes - len(err)])
                else:
                    truncated = True

        while True:
            drain()
            if chan.exit_status_ready():
                time.sleep(0.05)
                drain()
                break
            if time.monotonic() > deadline:
                timed_out = True
                chan.close()
                break
            time.sleep(0.02)

        code = -1 if timed_out else chan.recv_exit_status()
        chan.close()
        return ExecResult(
            stdout=out.decode("utf-8", "replace"),
            stderr=err.decode("utf-8", "replace"),
            exit_code=code,
            duration=time.monotonic() - start,
            timed_out=timed_out,
            truncated=truncated,
        )

    def gather_context(self) -> dict[str, str]:
        """Ambil info dasar server (read-only) agar LLM menghasilkan command yang tepat."""
        probes = {
            "os": "(. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\") || uname -s",
            "kernel": "uname -r",
            "user": "whoami",
            "is_root": "[ \"$(id -u)\" = 0 ] && echo yes || echo no",
            "shell": "echo $SHELL",
            "cwd": "pwd",
            "has_systemd": "[ -d /run/systemd/system ] && echo yes || echo no",
            "has_docker": "command -v docker >/dev/null 2>&1 && echo yes || echo no",
        }
        ctx = {"host": self.host}
        for key, cmd in probes.items():
            try:
                ctx[key] = self.run(cmd, timeout=5, max_bytes=500).stdout.strip() or "unknown"
            except Exception:
                ctx[key] = "unknown"
        return ctx
