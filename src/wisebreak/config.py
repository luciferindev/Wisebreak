"""Configuration loading for WISEBREAK.

Reads a nano-friendly TOML file and merges it over built-in defaults. A
missing config file is fine — defaults are used and the app still runs.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import paths

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - fallback for <3.11
    import tomli as tomllib


DEFAULTS: dict[str, Any] = {
    "general": {
        "data_dir": "/home/$USER/Downloads/wisebreak",
        "read_only": True,
    },
    "privacy": {"redact_identifiers": True},
    "usb": {"poll_interval": 2.0},
    "vuln": {
        "nvd_api_base": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "nvd_api_key": "",
        "cache_ttl": 604800,
        "timeout": 30.0,
    },
    "diagnostics": {
        "default_baud": 115200,
        "read_timeout": 3.0,
        "max_capture_bytes": 65536,
    },
    "firmware": {"max_entry_bytes": 8589934592},
    "reporting": {"formats": ["markdown", "json", "html"]},
}


@dataclass(frozen=True)
class Config:
    """Resolved, read-only configuration."""

    data_dir: Path
    read_only: bool
    redact_identifiers: bool
    usb_poll_interval: float
    nvd_api_base: str
    nvd_api_key: str
    vuln_cache_ttl: int
    vuln_timeout: float
    serial_default_baud: int
    serial_read_timeout: float
    serial_max_capture_bytes: int
    firmware_max_entry_bytes: int
    report_formats: list[str] = field(default_factory=lambda: ["markdown", "json", "html"])
    source_file: Path | None = None

    # ---- derived locations -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "wisebreak.db"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def firmware_cache_dir(self) -> Path:
        return self.data_dir / "firmware"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.cache_dir, self.reports_dir, self.firmware_cache_dir):
            paths.ensure_dir(d)

    def with_data_dir(self, new_dir: Path) -> "Config":
        return replace(self, data_dir=new_dir)


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = {k: (v.copy() if isinstance(v, dict) else v) for k, v in base.items()}
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load(config_file: Path | None = None) -> Config:
    """Load configuration, merging a TOML file over defaults.

    Parameters
    ----------
    config_file:
        Explicit path. If ``None``, the default user config path is tried.
    """
    merged = {k: v.copy() for k, v in DEFAULTS.items()}
    source: Path | None = None

    candidate = config_file or paths.default_config_file()
    if candidate.is_file():
        try:
            with candidate.open("rb") as fh:
                user_cfg = tomllib.load(fh)
            merged = _deep_merge(merged, user_cfg)
            source = candidate
        except (OSError, tomllib.TOMLDecodeError) as exc:  # pragma: no cover
            # A broken config must never crash the app; fall back to defaults.
            print(f"wisebreak: ignoring invalid config {candidate}: {exc}", file=sys.stderr)

    g = merged["general"]
    v = merged["vuln"]
    d = merged["diagnostics"]
    data_dir = paths.expand(g["data_dir"])

    return Config(
        data_dir=data_dir,
        read_only=bool(g.get("read_only", True)),
        redact_identifiers=bool(merged["privacy"].get("redact_identifiers", True)),
        usb_poll_interval=float(merged["usb"].get("poll_interval", 2.0)),
        nvd_api_base=str(v["nvd_api_base"]),
        nvd_api_key=str(v.get("nvd_api_key", "")),
        vuln_cache_ttl=int(v.get("cache_ttl", 604800)),
        vuln_timeout=float(v.get("timeout", 30.0)),
        serial_default_baud=int(d.get("default_baud", 115200)),
        serial_read_timeout=float(d.get("read_timeout", 3.0)),
        serial_max_capture_bytes=int(d.get("max_capture_bytes", 65536)),
        firmware_max_entry_bytes=int(merged["firmware"].get("max_entry_bytes", 8589934592)),
        report_formats=list(merged["reporting"].get("formats", ["markdown", "json", "html"])),
        source_file=source,
    )
