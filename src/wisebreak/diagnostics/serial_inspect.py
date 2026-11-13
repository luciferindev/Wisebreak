"""Passive diagnostic-interface inspector for /dev/ttyACM* and friends.

STRICTLY READ-ONLY AND PASSIVE. This module:
  * Lists exposed serial interfaces and their sysfs/USB metadata.
  * Identifies the bound kernel driver.
  * Performs a *passive* read (capture) with a configurable timeout.
  * Renders captured bytes as a hex dump and exports them.

It never writes bytes to the port, never sends AT/modem/diagnostic commands,
and never issues arbitrary binary payloads. There is no code path that
transmits to the device.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger

log = get_logger()

SYS_TTY = Path("/sys/class/tty")


@dataclass(slots=True)
class SerialInterface:
    device: str                    # /dev/ttyACM0
    driver: str = ""
    usb_vid: str = ""
    usb_pid: str = ""
    manufacturer: str = ""
    product: str = ""
    interface_desc: str = ""
    present: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "driver": self.driver,
            "usb_vid": self.usb_vid,
            "usb_pid": self.usb_pid,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "interface_desc": self.interface_desc,
            "present": self.present,
        }


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def list_serial_interfaces() -> list[SerialInterface]:
    """Enumerate /dev/ttyACM* and /dev/ttyUSB* with sysfs metadata."""
    out: list[SerialInterface] = []
    if not SYS_TTY.is_dir():
        return out
    for tty in sorted(SYS_TTY.iterdir()):
        name = tty.name
        if not (name.startswith("ttyACM") or name.startswith("ttyUSB")):
            continue
        dev_node = f"/dev/{name}"
        iface = SerialInterface(device=dev_node, present=Path(dev_node).exists())
        device_link = tty / "device"
        if device_link.exists():
            try:
                dev_path = device_link.resolve()
            except OSError:
                dev_path = device_link
            # driver
            drv = dev_path / "driver"
            if drv.exists():
                try:
                    iface.driver = drv.resolve().name
                except OSError:
                    pass
            iface.interface_desc = _read(dev_path / "interface")
            # Walk up to the USB device dir (has idVendor).
            usb_dir = dev_path
            for _ in range(6):
                if (usb_dir / "idVendor").exists():
                    break
                usb_dir = usb_dir.parent
            if (usb_dir / "idVendor").exists():
                iface.usb_vid = _read(usb_dir / "idVendor")
                iface.usb_pid = _read(usb_dir / "idProduct")
                iface.manufacturer = _read(usb_dir / "manufacturer")
                iface.product = _read(usb_dir / "product")
        out.append(iface)
    return out


def hexdump(data: bytes, width: int = 16, base_offset: int = 0) -> str:
    """Classic canonical hex+ASCII dump."""
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_offset + i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


@dataclass(slots=True)
class CaptureResult:
    device: str
    bytes_captured: int
    data: bytes = b""
    method: str = ""
    duration: float = 0.0
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def hexdump(self) -> str:
        return hexdump(self.data)


class SerialInspector:
    """Passive capture controller for a single serial interface."""

    def __init__(
        self,
        read_timeout: float = 3.0,
        max_capture_bytes: int = 65536,
        baud: int = 115200,
    ) -> None:
        self.read_timeout = read_timeout
        self.max_capture_bytes = max_capture_bytes
        self.baud = baud

    def backend(self) -> str:
        try:
            import serial  # noqa: F401

            return "pyserial"
        except Exception:
            return "os"

    def capture(self, device: str) -> CaptureResult:
        """Passively read up to ``max_capture_bytes`` for ``read_timeout`` secs.

        Uses pyserial when present (handles line settings cleanly); otherwise a
        non-blocking ``os.read`` fallback. Neither path writes to the port.
        """
        path = Path(device)
        if not path.exists():
            return CaptureResult(device, 0, error=f"{device} does not exist")
        backend = self.backend()
        log.info("passive capture on %s via %s (timeout=%ss)", device, backend, self.read_timeout)
        if backend == "pyserial":
            return self._capture_pyserial(device)
        return self._capture_os(device)

    def _capture_pyserial(self, device: str) -> CaptureResult:
        import serial

        result = CaptureResult(device, 0, method="pyserial")
        start = time.monotonic()
        try:
            # Open read-only intent: we never call write(). timeout bounds read().
            with serial.Serial(
                device, baudrate=self.baud, timeout=self.read_timeout
            ) as ser:
                buf = bytearray()
                deadline = start + self.read_timeout
                while time.monotonic() < deadline and len(buf) < self.max_capture_bytes:
                    waiting = getattr(ser, "in_waiting", 0)
                    to_read = max(1, min(waiting or 1, self.max_capture_bytes - len(buf)))
                    chunk = ser.read(to_read)
                    if not chunk:
                        continue
                    buf.extend(chunk)
                result.data = bytes(buf)
                result.bytes_captured = len(buf)
        except Exception as exc:  # serial.SerialException et al.
            result.error = str(exc)
            if "Permission denied" in str(exc):
                result.warnings.append(
                    "Permission denied. Add your user to the 'uucp' (Arch) or "
                    "'dialout' group, or run with appropriate permissions."
                )
        result.duration = time.monotonic() - start
        return result

    def _capture_os(self, device: str) -> CaptureResult:
        result = CaptureResult(device, 0, method="os")
        result.warnings.append(
            "pyserial not installed; using raw non-blocking read (no line-setting "
            "control). Install the 'serial' extra for robust capture."
        )
        start = time.monotonic()
        fd = -1
        try:
            fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
            buf = bytearray()
            deadline = start + self.read_timeout
            while time.monotonic() < deadline and len(buf) < self.max_capture_bytes:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    time.sleep(0.05)
                    continue
                except OSError as exc:
                    result.error = str(exc)
                    break
                if not chunk:
                    time.sleep(0.05)
                    continue
                buf.extend(chunk)
            result.data = bytes(buf)
            result.bytes_captured = len(buf)
        except PermissionError as exc:
            result.error = str(exc)
            result.warnings.append(
                "Permission denied. Add your user to the 'uucp' group on Arch Linux."
            )
        except OSError as exc:
            result.error = str(exc)
        finally:
            if fd >= 0:
                os.close(fd)
        result.duration = time.monotonic() - start
        return result

    @staticmethod
    def export_capture(result: CaptureResult, out_dir: Path) -> Path:
        """Write the raw captured bytes to a timestamped .bin file."""
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = result.device.replace("/", "_").strip("_")
        ts = time.strftime("%Y%m%d-%H%M%S")
        out = out_dir / f"capture_{safe}_{ts}.bin"
        out.write_bytes(result.data)
        log.info("exported %d bytes to %s", result.bytes_captured, out)
        return out
