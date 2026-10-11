from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

# owner/repo segments: what the three hosts actually permit, and nothing that
# git could read as an option or a path traversal.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class FetchError(Exception):
    """The repository could not be fetched."""


@dataclass(frozen=True)
class RepoRef:
    host: str
    owner: str
    name: str
    ref: str | None = None

    @property
    def clone_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}.git"

    @property
    def display(self) -> str:
        return f"{self.owner}/{self.name}"


def parse_repo_url(url: str, ref: str | None = None) -> RepoRef:
    """Validate a user-supplied repository URL.

    Only https URLs on a fixed set of public hosts are accepted. Anything else
    (ssh, file://, local paths, arbitrary hosts) would let a caller point the
    clone at the server's own filesystem or internal network.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        raise FetchError("only https repository URLs are supported")
    if parsed.username or parsed.password or parsed.port:
        raise FetchError("credentials and ports are not allowed in the URL")

    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in ALLOWED_HOSTS:
        raise FetchError(f"host must be one of {sorted(ALLOWED_HOSTS)}, got {host!r}")

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise FetchError("URL must point at a repository: https://<host>/<owner>/<repo>")
    owner, name = parts[0], parts[1].removesuffix(".git")

    # github.com/owner/repo/tree/<branch> — take the branch from the URL when
    # no explicit ref was given.
    if ref is None and len(parts) >= 4 and parts[2] == "tree":
        ref = "/".join(parts[3:])

    for segment in (owner, name):
        if not _SEGMENT.match(segment):
            raise FetchError(f"invalid repository path segment: {segment!r}")
    if ref is not None:
        ref = ref.strip() or None
    if ref is not None and (not _REF.match(ref) or ".." in ref):
        raise FetchError(f"invalid ref: {ref!r}")

    return RepoRef(host=host, owner=owner, name=name, ref=ref)


def _tree_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def clone(
    repo: RepoRef,
    dest: Path,
    timeout_seconds: int = 300,
    max_bytes: int = 1024 * 1024 * 1024,
) -> str:
    """Shallow-clone `repo` into `dest` and return the checked-out commit sha.

    The clone is depth 1, without submodules or LFS, with interactive
    credential prompts disabled so a private or nonexistent repo fails fast
    instead of hanging the worker. `.git` is removed afterwards so scanners
    never see repository metadata.
    """
    if shutil.which("git") is None:
        raise FetchError("git is not installed")

    cmd = [
        "git", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false",
        "clone", "--depth", "1", "--no-tags", "--single-branch",
    ]
    if repo.ref:
        cmd += ["--branch", repo.ref]
    cmd += ["--", repo.clone_url, str(dest)]

    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "/bin/echo",
    }
    try:
        subprocess.run(cmd, env=env, capture_output=True, text=True,
                       timeout=timeout_seconds, check=True)
    except subprocess.TimeoutExpired:
        raise FetchError(f"clone timed out after {timeout_seconds}s") from None
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()
        message = detail[-1] if detail else "git clone failed"
        if "could not read Username" in (exc.stderr or "") or "not found" in message.lower():
            message = "repository not found or not public"
        raise FetchError(message[:300]) from None

    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    shutil.rmtree(dest / ".git", ignore_errors=True)

    if _tree_bytes(dest) > max_bytes:
        raise FetchError(f"repository exceeds the {max_bytes // (1024 * 1024)} MB size limit")
    return sha
