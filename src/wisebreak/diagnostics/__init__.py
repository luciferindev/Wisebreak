"""Diagnostic interface inspector (passive, read-only)."""

from .serial_inspect import (
    SerialInspector,
    SerialInterface,
    hexdump,
    list_serial_interfaces,
)

__all__ = ["SerialInspector", "SerialInterface", "hexdump", "list_serial_interfaces"]
