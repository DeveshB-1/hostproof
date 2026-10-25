"""Core data types: a check, its result, and the executor that gathers raw output."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Protocol

PASS, FAIL, WARN, ERROR, NA = "pass", "fail", "warn", "error", "not_applicable"


@dataclass
class Evidence:
    """One raw observation: the exact command (or file) and what it returned."""

    source: str  # e.g. "$ timedatectl show -p NTPSynchronized --value" or "file:/etc/login.defs"
    output: str
    exit_code: int | None = None


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str
    detail: str
    soc2: list[str]
    iso27001: list[str]
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Executor(Protocol):
    def run(self, argv: list[str]) -> tuple[int, str, str]: ...

    def read(self, path: str) -> str | None: ...

    def glob(self, pattern: str) -> list[str]: ...

    def exists(self, path: str) -> bool: ...


class LocalExecutor:
    """Runs read-only commands on this machine. Never escalates privileges."""

    def __init__(self, timeout: int = 20):
        self.timeout = timeout

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"{argv[0]}: command not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {self.timeout}s"

    def read(self, path: str) -> str | None:
        try:
            return Path(path).read_text(errors="replace")
        except (OSError, UnicodeError):
            return None

    def glob(self, pattern: str) -> list[str]:
        p = Path(pattern)
        return sorted(str(x) for x in Path(p.parent).glob(p.name)) if p.parent.exists() else []

    def exists(self, path: str) -> bool:
        return Path(path).exists()


class FixtureExecutor:
    """Replays canned command output and files. Used by tests and the offline demo."""

    def __init__(self, commands: dict[str, tuple[int, str]] | None = None,
                 files: dict[str, str] | None = None, paths: set[str] | None = None):
        self.commands = commands or {}
        self.files = files or {}
        self.paths = (paths or set()) | set(self.files)

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        key = " ".join(argv)
        if key not in self.commands:
            return 127, "", f"{argv[0]}: command not found"
        rc, out = self.commands[key]
        return rc, out, ""

    def read(self, path: str) -> str | None:
        return self.files.get(path)

    def glob(self, pattern: str) -> list[str]:
        import fnmatch
        return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))

    def exists(self, path: str) -> bool:
        return path in self.paths


@dataclass
class Check:
    check_id: str
    title: str
    soc2: list[str]
    iso27001: list[str]
    fn: Callable[..., tuple[str, str, list[Evidence]]]
    scope: str  # "linux" or "k8s"

    def run(self, ctx) -> CheckResult:
        try:
            status, detail, ev = self.fn(ctx)
        except Exception as e:  # a broken check must not take down the run
            status, detail, ev = ERROR, f"check crashed: {type(e).__name__}: {e}", []
        return CheckResult(self.check_id, self.title, status, detail, self.soc2, self.iso27001, ev)
