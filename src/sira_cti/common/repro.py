"""Config loading and hashing -- the project-wide reproducibility convention.

README, Contributing Conventions: "record the config hash with every results
file." Shared across modules, so it lives in ``common/`` alongside the other
project-wide plumbing rather than inside Module 1 specifically. This module
does not touch ``schemas.py`` or ``llm.py``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any, Optional, Sequence

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    """Parse a YAML config file (e.g. ``configs/default.yaml``)."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def config_hash(path: str | Path, *, length: int = 12) -> str:
    """A short, stable hash of a config file's exact bytes.

    Hashing the raw file (not the parsed dict) means whitespace/comment-only
    edits still change the hash -- deliberate, since a "the config changed
    but the hash didn't" surprise is worse than an over-sensitive one for a
    field meant to answer "was this the run I think it was".
    """
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return digest[:length]


def load_env_file(path: str | Path = ".env") -> list[str]:
    """Read ``KEY=value`` lines from a ``.env`` file into ``os.environ``.

    Returns the **names** that were set, never the values: API keys live in
    ``.env`` (git-ignored) and nothing in this project may print or log one.
    A variable already present in the environment wins, and a missing file
    is not an error.
    """
    path = Path(path)
    if not path.exists():
        return []
    loaded: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        value = value.strip().strip("'\"")
        if key and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


CODE_PATHS = ("src", "scripts", "configs")
"""The folders whose contents decide what a run does. Documentation, tests and
generated indexes are deliberately not here: writing up a finding half-way
through a two-day run must not make that run impossible to resume."""


def code_version(
    repo_dir: str | Path = ".", paths: Sequence[str] = CODE_PATHS
) -> Optional[dict[str, Any]]:
    """Which version of the code is about to run, for the run manifest.

    * ``code_commit`` -- the last git commit that changed anything under
      ``paths``. This is the identity a resume is checked against.
    * ``dirty`` -- True if anything under ``paths`` differs from that commit
      (edited, staged, or new and untracked). A dirty tree means the commit
      hash does **not** describe the code that ran.
    * ``head`` -- the current commit of the whole repository, for reference.

    Returns ``None`` when this is not a git checkout or git is unavailable.
    """
    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo_dir), *args], capture_output=True, text=True, check=True, timeout=30
        ).stdout.rstrip()       # not strip(): a status line starts with a meaningful space

    try:
        head = _git("rev-parse", "HEAD")
        code_commit = _git("log", "-1", "--format=%H", "--", *paths)
        status = _git("status", "--porcelain", "--", *paths)
    except (OSError, subprocess.SubprocessError):
        return None
    changed = [line[3:] for line in status.splitlines() if line.strip()]
    return {
        "head": head,
        "code_commit": code_commit or head,
        "dirty": bool(changed),
        "dirty_files": changed[:20],
        "paths": list(paths),
    }


def full_run_blocker(version: Optional[dict[str, Any]]) -> Optional[str]:
    """Why a full-corpus run must not start on this code, or ``None`` if it may.

    A full run takes days and cannot be cheaply redone, so it has to be
    traceable to an exact commit. Uncommitted changes make that impossible.
    """
    if version is None:
        return None     # not a git checkout: nothing to check against
    if version["dirty"]:
        files = "\n".join(f"  {f}" for f in version["dirty_files"])
        return (
            "Refusing to start a full-corpus run: there are uncommitted changes in "
            f"{', '.join(version['paths'])}, so no commit hash describes the code that would run.\n"
            f"{files}\nCommit (or discard) them and start again."
        )
    return None
