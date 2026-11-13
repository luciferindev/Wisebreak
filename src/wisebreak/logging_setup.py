"""Central logging for WISEBREAK.

A ring buffer handler feeds the TUI "Live operation logs" panel while a
rotating file handler persists logs to the data directory.
"""

from __future__ import annotations

import logging
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

LOGGER_NAME = "wisebreak"


class RingBufferHandler(logging.Handler):
    """Keep the most recent N formatted records and notify a listener."""

    def __init__(self, capacity: int = 2000) -> None:
        super().__init__()
        self.buffer: deque[str] = deque(maxlen=capacity)
        self._listener: Callable[[str], None] | None = None

    def set_listener(self, listener: Callable[[str], None] | None) -> None:
        self._listener = listener

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:  # pragma: no cover - never let logging crash the app
            return
        self.buffer.append(line)
        if self._listener is not None:
            try:
                self._listener(line)
            except Exception:  # pragma: no cover
                pass


_ring = RingBufferHandler()


def get_ring_handler() -> RingBufferHandler:
    return _ring


def setup(log_file: Path | None = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:  # already configured
        return logger

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")

    _ring.setFormatter(fmt)
    _ring.setLevel(level)
    logger.addHandler(_ring)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
            fh.setFormatter(fmt)
            fh.setLevel(level)
            logger.addHandler(fh)
        except OSError:  # pragma: no cover - logging to file is best-effort
            pass

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
