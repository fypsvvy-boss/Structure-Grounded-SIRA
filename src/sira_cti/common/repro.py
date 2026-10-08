"""Config loading and hashing -- the project-wide reproducibility convention.

README, Contributing Conventions: "record the config hash with every results
file." Shared across modules, so it lives in ``common/`` alongside the other
project-wide plumbing rather than inside Module 1 specifically. This module
does not touch ``schemas.py`` or ``llm.py``.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

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
