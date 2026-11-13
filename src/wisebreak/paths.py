"""Filesystem path resolution for WISEBREAK.

Resolves config, data, cache, and bundled-resource locations. Honors the
XDG base-directory spec via platformdirs but allows an explicit override
from the config file.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

from platformdirs import PlatformDirs

APP_NAME = "wisebreak"

_dirs = PlatformDirs(appname=APP_NAME, appauthor=False)


def config_dir() -> Path:
    """User config directory (e.g. ~/.config/wisebreak)."""
    return Path(_dirs.user_config_dir)


def default_config_file() -> Path:
    return config_dir() / "wisebreak.toml"


def expand(path: str | os.PathLike[str]) -> Path:
    """Expand ``$USER``, ``~`` and environment variables in a path string."""
    text = os.path.expandvars(str(path))
    return Path(text).expanduser()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def resource_path(relative: str) -> Path:
    """Locate a file bundled inside the ``wisebreak`` package.

    Works both from a source checkout and an installed wheel.
    """
    pkg = resources.files("wisebreak")
    target = pkg.joinpath(relative)
    # ``resources.files`` returns a Traversable; for the filesystem-backed
    # cases we care about, ``str()`` yields a usable path.
    return Path(str(target))
