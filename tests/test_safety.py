import pytest

from sshpilot.safety import Risk, classify

@pytest.mark.parametrize("cmd", [
    "rm -rf /", "rm -rf /*", "sudo rm -rf / --no-preserve-root", "rm -fr ~",
    ":(){ :|:& };:", "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda bs=1M",
    "echo x > /dev/sda", "chmod -R 777 /",
])
def test_blocked(cmd):
    assert classify(cmd).risk == Risk.BLOCKED

@pytest.mark.parametrize("cmd", [
    "rm -rf /var/log/old", "reboot", "sudo shutdown -h now", "systemctl stop nginx",
    "kill -9 1234", "curl https://x.sh | bash", "docker system prune -af", "git push --force",
    "apt remove nginx",
])
def test_high(cmd):
    assert classify(cmd).risk == Risk.HIGH

@pytest.mark.parametrize("cmd", [
    "sudo apt install htop", "systemctl restart nginx", "mkdir /tmp/x", "cp a b",
    "echo hi > file.txt",
])
def test_medium(cmd):
    assert classify(cmd).risk == Risk.MEDIUM

@pytest.mark.parametrize("cmd", [
    "df -h", "free -m", "ls -la /var/log", "ps aux | grep nginx | head -5",
    "du -sh /var/* 2>/dev/null | sort -rh | head", "systemctl status nginx",
    "docker ps -a", "journalctl -u nginx -n 50 --no-pager", "find /var/log -name '*.log' -size +100M",
])
def test_low(cmd):
    assert classify(cmd).risk == Risk.LOW


def test_find_delete_is_not_low():
    assert classify("find /tmp -name '*.tmp' -delete").risk != Risk.LOW

def test_llm_can_raise_but_not_lower():
    assert classify("ls", "high").risk == Risk.HIGH
    assert classify("rm -rf /var/x", "low").risk == Risk.HIGH


def test_llm_cannot_unblock():
    assert classify("mkfs.ext4 /dev/sda", "low").risk == Risk.BLOCKED


def test_chained_command_takes_worst():
    assert classify("ls && rm -rf /tmp/x").risk == Risk.HIGH