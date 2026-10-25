"""Read-only Linux host checks. Each returns (status, detail, evidence).

Nothing here needs root. Where root would give a better answer (sshd -T, nft list
ruleset), the check falls back to config files and service state and says so.
"""

from __future__ import annotations

from ..model import ERROR, FAIL, NA, PASS, WARN, Check, Evidence


def _cmd(ctx, argv):
    rc, out, err = ctx.ex.run(argv)
    return rc, out, err, Evidence("$ " + " ".join(argv), (out or err).strip()[:4000], rc)


def _file(ctx, path):
    text = ctx.ex.read(path)
    return text, Evidence("file:" + path, (text or "<unreadable>")[:4000])


def sshd_effective(ctx) -> tuple[dict[str, str], list[Evidence]]:
    """Effective sshd options. sshd uses the FIRST value it sees, and Include
    lines are expanded in place, so a drop-in can override the main file."""
    evidence: list[Evidence] = []
    rc, out, err, ev = _cmd(ctx, ["sshd", "-T"])
    if rc == 0 and out.strip():
        evidence.append(ev)
        opts = {}
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            opts.setdefault(k.lower(), v.strip().lower())
        return opts, evidence

    opts: dict[str, str] = {}

    def parse(path: str, depth: int = 0):
        text, fev = _file(ctx, path)
        if text is None or depth > 4:
            return
        evidence.append(fev)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":  # options after Match are conditional; stop at the first block
                return
            if key == "include":
                for pat in val.split():
                    if not pat.startswith("/"):
                        pat = "/etc/ssh/" + pat
                    for inc in ctx.ex.glob(pat):
                        parse(inc, depth + 1)
                continue
            opts.setdefault(key, val.lower())

    parse("/etc/ssh/sshd_config")
    return opts, evidence


def check_ssh_root_login(ctx):
    opts, ev = sshd_effective(ctx)
    if not ev:
        return NA, "no sshd config found (sshd not installed?)", ev
    val = opts.get("permitrootlogin", "prohibit-password")  # OpenSSH default since 7.0
    src = "set explicitly" if "permitrootlogin" in opts else "OpenSSH default"
    if val == "no":
        return PASS, f"PermitRootLogin no ({src})", ev
    if val in ("prohibit-password", "without-password", "forced-commands-only"):
        return WARN, f"PermitRootLogin {val} ({src}): root can still log in with a key", ev
    return FAIL, f"PermitRootLogin {val} ({src})", ev


def check_ssh_password_auth(ctx):
    opts, ev = sshd_effective(ctx)
    if not ev:
        return NA, "no sshd config found (sshd not installed?)", ev
    val = opts.get("passwordauthentication", "yes")
    src = "set explicitly" if "passwordauthentication" in opts else "OpenSSH default"
    if val == "no":
        return PASS, f"PasswordAuthentication no ({src})", ev
    return FAIL, f"PasswordAuthentication {val} ({src}): password logins are accepted", ev


def check_firewall(ctx):
    ev = []
    active = []
    for unit in ("firewalld", "nftables", "ufw", "iptables"):
        rc, out, err, e = _cmd(ctx, ["systemctl", "is-active", unit])
        ev.append(e)
        if out.strip() == "active":
            active.append(unit)
    if active:
        return PASS, "host firewall service active: " + ", ".join(active), ev
    return FAIL, "no firewalld, nftables, ufw or iptables service is active", ev


def check_disk_encryption(ctx):
    rc, out, err, e = _cmd(ctx, ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"])
    if rc != 0:
        return ERROR, "lsblk failed: " + err.strip(), [e]
    import json
    devs = json.loads(out).get("blockdevices", [])
    crypt, mounted_plain = [], []

    def walk(nodes, under_crypt=False):
        for n in nodes:
            is_crypt = n.get("type") == "crypt" or n.get("fstype") == "crypto_LUKS"
            if n.get("type") == "crypt":
                crypt.append(n["name"])
            mps = [m for m in (n.get("mountpoints") or []) if m]
            if mps and not (under_crypt or is_crypt) and n.get("fstype") not in ("vfat", "swap", None):
                mounted_plain.append(f"{n['name']} ({n.get('fstype')}) on {', '.join(mps)}")
            walk(n.get("children") or [], under_crypt or is_crypt)

    walk(devs)
    if mounted_plain:
        return FAIL, "unencrypted mounted filesystems: " + "; ".join(mounted_plain), [e]
    if crypt:
        return PASS, "all mounted data filesystems sit on dm-crypt: " + ", ".join(crypt), [e]
    return WARN, "no mounted data filesystems found to judge", [e]


def check_time_sync(ctx):
    rc, out, err, e = _cmd(ctx, ["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if rc != 0:
        return ERROR, "timedatectl failed: " + (err or out).strip(), [e]
    if out.strip() == "yes":
        return PASS, "system clock is NTP-synchronized", [e]
    return FAIL, "system clock is not NTP-synchronized", [e]


def check_audit_logging(ctx):
    ev = []
    rc, out, err, e = _cmd(ctx, ["systemctl", "is-active", "auditd"])
    ev.append(e)
    auditd = out.strip() == "active"
    persistent = ctx.ex.exists("/var/log/journal")
    ev.append(Evidence("path:/var/log/journal", "exists" if persistent else "missing"))
    if auditd:
        return PASS, "auditd is active" + (" and journald is persistent" if persistent else ""), ev
    if persistent:
        return WARN, "auditd is not running; only persistent journald logs exist", ev
    return FAIL, "auditd is not running and journald logs are volatile (lost on reboot)", ev


def check_password_aging(ctx, max_days: int = 90):
    text, e = _file(ctx, "/etc/login.defs")
    if text is None:
        return NA, "/etc/login.defs not readable", [e]
    val = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "PASS_MAX_DAYS":
            val = int(parts[1])
    if val is None:
        return WARN, "PASS_MAX_DAYS not set", [e]
    if val <= max_days:
        return PASS, f"PASS_MAX_DAYS {val} (policy: <= {max_days})", [e]
    return FAIL, f"PASS_MAX_DAYS {val} (policy: <= {max_days})", [e]


def check_uid0_accounts(ctx):
    text, e = _file(ctx, "/etc/passwd")
    if text is None:
        return ERROR, "/etc/passwd not readable", [e]
    uid0 = [l.split(":")[0] for l in text.splitlines() if l.count(":") >= 3 and l.split(":")[2] == "0"]
    extra = [u for u in uid0 if u != "root"]
    # only the uid-0 lines are kept as evidence, the rest of passwd is not needed
    e = Evidence("file:/etc/passwd (uid 0 lines)", "\n".join(l for l in text.splitlines()
                                                         if l.count(":") >= 3 and l.split(":")[2] == "0"))
    if extra:
        return FAIL, "accounts other than root with UID 0: " + ", ".join(extra), [e]
    return PASS, "root is the only UID 0 account", [e]


def check_auto_updates(ctx):
    ev = []
    units = ("dnf-automatic.timer", "dnf-automatic-install.timer", "unattended-upgrades.service",
             "apt-daily-upgrade.timer")
    enabled = []
    for u in units:
        rc, out, err, e = _cmd(ctx, ["systemctl", "is-enabled", u])
        ev.append(e)
        if out.strip() == "enabled":
            enabled.append(u)
    if enabled:
        return PASS, "automatic security updates enabled: " + ", ".join(enabled), ev
    return FAIL, "no dnf-automatic or unattended-upgrades unit is enabled", ev


CHECKS = [
    Check("linux.ssh_root_login", "SSH root login is disabled", ["CC6.1"], ["A.8.2", "A.8.5"],
          check_ssh_root_login, "linux"),
    Check("linux.ssh_password_auth", "SSH password authentication is disabled", ["CC6.1"], ["A.8.5"],
          check_ssh_password_auth, "linux"),
    Check("linux.firewall", "Host firewall is active", ["CC6.6"], ["A.8.20"], check_firewall, "linux"),
    Check("linux.disk_encryption", "Data filesystems are encrypted at rest", ["CC6.1", "CC6.7"], ["A.8.24"],
          check_disk_encryption, "linux"),
    Check("linux.time_sync", "Clock is synchronized to NTP", ["CC7.2"], ["A.8.17"], check_time_sync, "linux"),
    Check("linux.audit_logging", "Audit logging is enabled and persistent", ["CC7.2"], ["A.8.15"],
          check_audit_logging, "linux"),
    Check("linux.password_aging", "Local password maximum age is enforced", ["CC6.1"], ["A.5.17"],
          check_password_aging, "linux"),
    Check("linux.uid0_accounts", "No extra UID 0 accounts", ["CC6.2", "CC6.3"], ["A.8.2"],
          check_uid0_accounts, "linux"),
    Check("linux.auto_updates", "Automatic security updates are enabled", ["CC7.1"], ["A.8.8"],
          check_auto_updates, "linux"),
]
