import json
from pathlib import Path

import pytest

from hostproof.model import FixtureExecutor
from hostproof.runner import Context

K8S = Path(__file__).parent / "fixtures" / "k8s"

HARDENED_SSHD = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n"
DROPIN = "PermitRootLogin no\nPasswordAuthentication no\n"
LSBLK_CRYPT = json.dumps({"blockdevices": [{"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None],
    "children": [{"name": "nvme0n1p1", "type": "part", "fstype": "vfat", "mountpoints": ["/boot"]},
                 {"name": "nvme0n1p2", "type": "part", "fstype": "crypto_LUKS", "mountpoints": [None],
                  "children": [{"name": "root", "type": "crypt", "fstype": "xfs", "mountpoints": ["/"]}]}]}]})
LSBLK_PLAIN = json.dumps({"blockdevices": [{"name": "sda", "type": "disk", "fstype": None, "mountpoints": [None],
    "children": [{"name": "sda1", "type": "part", "fstype": "ext4", "mountpoints": ["/"]}]}]})


def host(hardened: bool) -> FixtureExecutor:
    yes = (0, "active\n")
    no = (3, "inactive\n")
    cmds = {
        "sshd -T": (1, ""),  # non-root: forces the config-file fallback
        "systemctl is-active firewalld": yes if hardened else no,
        "systemctl is-active nftables": no, "systemctl is-active ufw": no, "systemctl is-active iptables": no,
        "lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS": (0, LSBLK_CRYPT if hardened else LSBLK_PLAIN),
        "timedatectl show -p NTPSynchronized --value": (0, "yes\n" if hardened else "no\n"),
        "systemctl is-active auditd": yes if hardened else no,
        "systemctl is-enabled dnf-automatic.timer": (0, "enabled\n") if hardened else (1, "disabled\n"),
        "systemctl is-enabled dnf-automatic-install.timer": (1, "disabled\n"),
        "systemctl is-enabled unattended-upgrades.service": (1, ""),
        "systemctl is-enabled apt-daily-upgrade.timer": (1, ""),
    }
    files = {
        "/etc/ssh/sshd_config": HARDENED_SSHD if hardened else "PermitRootLogin yes\n",
        "/etc/login.defs": "PASS_MAX_DAYS\t90\n" if hardened else "PASS_MAX_DAYS\t99999\n",
        "/etc/passwd": "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n"
                       + ("" if hardened else "toor:x:0:0::/root:/bin/sh\n"),
    }
    if hardened:
        files["/etc/ssh/sshd_config.d/50-hardening.conf"] = DROPIN
    return FixtureExecutor(cmds, files, paths={"/var/log/journal"} if hardened else set())


class K8sFixture:
    def __init__(self, inner, d=K8S):
        self.inner, self.d = inner, d

    def run(self, argv):
        if argv[:2] == ["kubectl", "get"]:
            return 0, (self.d / f"{argv[2]}.json").read_text(), ""
        return self.inner.run(argv)

    def __getattr__(self, n):
        return getattr(self.inner, n)


@pytest.fixture
def hardened():
    return Context(ex=host(True))


@pytest.fixture
def weak():
    return Context(ex=host(False))


@pytest.fixture
def cluster():
    return Context(ex=K8sFixture(host(True)), kubectl=["kubectl"])
