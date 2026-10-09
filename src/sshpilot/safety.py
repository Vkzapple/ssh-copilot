"""Rule-based safety classifier.

Lapisan ini TIDAK bergantung pada LLM. Hasil akhir risiko = max(risiko LLM, risiko rule),
dan status BLOCKED hanya bisa ditentukan oleh rule (tidak bisa di-override LLM maupun user).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class Risk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    BLOCKED = 4

    @classmethod
    def parse(cls, value: str | None) -> "Risk":
        try:
            return cls[(value or "").strip().upper()]
        except KeyError:
            return cls.MEDIUM  # nilai tak dikenal -> hati-hati


@dataclass
class Verdict:
    risk: Risk
    reasons: list[str] = field(default_factory=list)


# --- Pola yang DIBLOKIR total -------------------------------------------------
BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+(?:-\S+\s+)*-\S*[rR]\S*\s+(?:-\S+\s+)*(?:--no-preserve-root\s+)?(?:/|/\*|~|~/|\$HOME)\s*(?:$|[;&|])",
     "Menghapus root/home secara rekursif"),
    (r"\brm\s+.*--no-preserve-root", "Menggunakan --no-preserve-root"),
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb"),
    (r"\bmkfs(\.\w+)?\b", "Memformat filesystem"),
    (r"\bdd\b[^\n]*\bof=/dev/(?:sd|hd|vd|xvd|nvme|mmcblk)", "Menimpa block device dengan dd"),
    (r">\s*/dev/(?:sd|hd|vd|xvd|nvme|mmcblk)", "Redirect ke block device"),
    (r"\bchmod\s+(?:-\S+\s+)*-R\s+0?777\s+/(?:\s|$)", "chmod -R 777 pada /"),
    (r"\bchown\s+(?:-\S+\s+)*-R\s+\S+\s+/(?:\s|$)", "chown -R pada /"),
    (r"\bwipefs\b|\bshred\b[^\n]*\s/dev/", "Menghapus signature/isi disk"),
]

# --- Pola HIGH ---------------------------------------------------------------
HIGH_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s", "Menghapus file"),
    (r"\b(?:reboot|shutdown|poweroff|halt|init\s+[06])\b", "Mematikan/restart server"),
    (r"\bsystemctl\s+(?:stop|disable|mask|isolate|kill)\b", "Menghentikan/menonaktifkan service"),
    (r"\b(?:kill|pkill|killall)\b", "Menghentikan proses"),
    (r"\b(?:iptables|ip6tables|nft|ufw|firewall-cmd)\b", "Mengubah firewall"),
    (r"\b(?:userdel|deluser|usermod|passwd|chpasswd|visudo)\b", "Mengubah akun/kredensial"),
    (r"\bchown\s+(?:-\S+\s+)*-R\b|\bchmod\s+(?:-\S+\s+)*-R\b", "Mengubah permission rekursif"),
    (r"\b(?:apt(?:-get)?|yum|dnf|apk|zypper)\s+(?:remove|purge|autoremove|erase|del)\b", "Menghapus paket"),
    (r"\bpacman\s+-R", "Menghapus paket"),
    (r"\bpip3?\s+uninstall\b|\bnpm\s+(?:uninstall|rm)\b", "Menghapus paket"),
    (r"\bdocker\s+(?:rm|rmi|system\s+prune|volume\s+rm|volume\s+prune|network\s+rm|kill)\b", "Menghapus resource Docker"),
    (r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", "Eksekusi script dari internet"),
    (r"\b(?:truncate|mv)\b[^\n]*\s/(?:etc|boot|bin|sbin|usr|lib)\b", "Memodifikasi direktori sistem"),
    (r"\b(?:drop\s+(?:database|table)|truncate\s+table|delete\s+from)\b", "Operasi destruktif database"),
    (r"\bcrontab\s+-r\b", "Menghapus seluruh crontab"),
    (r"\bgit\s+(?:reset\s+--hard|clean\s+-\S*f|push\s+(?:.*\s)?(?:-f|--force))", "Operasi git destruktif"),
]

# --- Pola MEDIUM -------------------------------------------------------------
MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"\bsudo\b", "Menggunakan hak root"),
    (r"\b(?:apt(?:-get)?|yum|dnf|apk|zypper)\s+(?:install|upgrade|update|dist-upgrade)\b", "Mengubah paket sistem"),
    (r"\bpip3?\s+install\b|\bnpm\s+(?:install|i)\b", "Menginstall paket"),
    (r"\bsystemctl\s+(?:start|restart|reload|enable|daemon-reload)\b|\bservice\s+\S+\s+(?:start|restart|reload)\b",
     "Mengubah state service"),
    (r"\b(?:mv|cp|mkdir|touch|ln|chmod|chown|tee|sed\s+-i|install)\b", "Memodifikasi filesystem"),
    (r"\bdocker\s+(?:run|stop|start|restart|compose|exec|build|pull)\b", "Mengubah state Docker"),
    (r"\bgit\s+(?:pull|checkout|merge|rebase|commit|push)\b", "Mengubah repo git"),
    (r"\b(?:tar|unzip|gunzip|zip)\b", "Mengekstrak/membuat arsip"),
]

# --- Perintah read-only yang dianggap LOW ------------------------------------
READONLY_COMMANDS = {
    "ls", "cat", "head", "tail", "less", "more", "df", "du", "free", "uptime", "ps", "top", "htop",
    "whoami", "id", "hostname", "hostnamectl", "uname", "date", "pwd", "echo", "wc", "sort", "uniq",
    "grep", "egrep", "awk", "cut", "tr", "stat", "file", "which", "whereis", "type", "env", "printenv",
    "ss", "netstat", "ip", "ping", "dig", "nslookup", "host", "lsblk", "lscpu", "lsmod", "lsof",
    "journalctl", "dmesg", "last", "w", "who", "vmstat", "iostat", "mpstat", "nproc", "lsb_release",
    "find", "tree", "realpath", "basename", "dirname", "md5sum", "sha256sum", "ulimit", "getent",
}
READONLY_MULTI = [
    r"^systemctl\s+(?:status|is-active|is-enabled|list-units|list-unit-files|show|cat)\b",
    r"^docker\s+(?:ps|images|logs|inspect|stats|info|version|top|network\s+ls|volume\s+ls)\b",
    r"^git\s+(?:status|log|diff|branch|remote|show)\b",
    r"^(?:pip3?|npm)\s+(?:list|ls|show)\b",
    r"^(?:apt|dpkg|rpm)\s+(?:list|-l|-qa|show|search)\b",
    r"^sed\s+(?!.*-i)",
]

_SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\||\n")
_SAFE_REDIRECTS = re.compile(r"\d?>\s*/dev/null|\d>&\d|&>\s*/dev/null")


def _match_any(patterns: list[tuple[str, str]], command: str) -> list[str]:
    return [reason for pat, reason in patterns if re.search(pat, command, re.IGNORECASE)]


def _is_readonly(command: str) -> bool:
    cleaned = _SAFE_REDIRECTS.sub("", command)
    # Redirect penulisan file, command substitution, atau subshell -> bukan read-only murni
    if ">" in cleaned or "`" in cleaned or "$(" in cleaned:
        return False
    segments = [s.strip() for s in _SEGMENT_SPLIT.split(cleaned) if s.strip()]
    if not segments:
        return False
    for seg in segments:
        seg = re.sub(r"^(?:\w+=\S+\s+)+", "", seg)  # buang prefix VAR=val
        first = seg.split()[0] if seg.split() else ""
        if first == "sudo":
            return False
        if first == "find" and re.search(r"-(?:delete|exec|execdir|ok)\b|-fprint", seg):
            return False
        if first in READONLY_COMMANDS:
            continue
        if any(re.search(p, seg) for p in READONLY_MULTI):
            continue
        return False
    return True


def classify(command: str, llm_risk: str | Risk | None = None) -> Verdict:
    """Klasifikasikan risiko command. Hasil = max(rule, LLM) kecuali BLOCKED (hanya rule)."""
    command = command.strip()
    if not command:
        return Verdict(Risk.LOW, ["Command kosong"])

    blocked = _match_any(BLOCKED_PATTERNS, command)
    if blocked:
        return Verdict(Risk.BLOCKED, blocked)

    high = _match_any(HIGH_PATTERNS, command)
    if high:
        rule_risk, reasons = Risk.HIGH, high
    else:
        medium = _match_any(MEDIUM_PATTERNS, command)
        if medium:
            rule_risk, reasons = Risk.MEDIUM, medium
        elif _is_readonly(command):
            rule_risk, reasons = Risk.LOW, ["Perintah read-only"]
        else:
            rule_risk, reasons = Risk.MEDIUM, ["Tidak dikenali sebagai read-only"]

    if llm_risk is not None:
        llm = llm_risk if isinstance(llm_risk, Risk) else Risk.parse(llm_risk)
        if llm == Risk.BLOCKED:
            llm = Risk.HIGH  # LLM tidak berwenang memblokir, tapi naikkan ke HIGH
        if llm > rule_risk:
            reasons = reasons + [f"LLM menilai risiko {llm.name}"]
            rule_risk = llm
    return Verdict(rule_risk, reasons)
