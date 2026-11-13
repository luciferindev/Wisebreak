"""USB discovery engine.

Primary backend is **sysfs** (``/sys/bus/usb/devices``): it is always
present on Linux, needs no root, and no third-party packages. When the
optional ``pyudev`` package is installed it is used for richer driver
metadata and live hotplug monitoring; ``pyusb`` (libusb) is used to read
string descriptors when sysfs does not expose them.

Design rules honored here:
  * Read-only. Nothing is ever written to a device.
  * A serial/CDC-ACM interface is reported as a serial interface and nothing
    more. It is never labeled "privileged Android access".
  * ADB is reported as present only when an actual ADB interface
    (class 0xFF / subclass 0x42 / protocol 0x01) is observed.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..logging_setup import get_logger
from ..models import UsbDevice, UsbInterface
from ..paths import resource_path

log = get_logger()

SYSFS_USB = Path("/sys/bus/usb/devices")

# USB base class codes (bDeviceClass / bInterfaceClass).
USB_CLASS_NAMES = {
    0x00: "Per-interface",
    0x01: "Audio",
    0x02: "CDC Communications",
    0x03: "HID",
    0x05: "Physical",
    0x06: "Image (PTP/MTP)",
    0x07: "Printer",
    0x08: "Mass Storage",
    0x09: "Hub",
    0x0A: "CDC Data",
    0x0B: "Smart Card",
    0x0E: "Video",
    0xDC: "Diagnostic",
    0xE0: "Wireless (RNDIS/Bluetooth)",
    0xEF: "Miscellaneous",
    0xFE: "Application Specific",
    0xFF: "Vendor Specific",
}

# Well-known Samsung composite PIDs (documentation/labeling only).
SAMSUNG_VID = "04e8"
SAMSUNG_KNOWN_PIDS = {
    "6860": "Samsung MTP",
    "6863": "Samsung RNDIS / tethering",
    "685d": "Samsung Download Mode (Odin)",
    "685e": "Samsung ADB composite",
    "6864": "Samsung RNDIS+MTP+ADB",
}


def backend_status() -> dict[str, bool]:
    """Report which optional backends are importable."""
    status = {"sysfs": SYSFS_USB.is_dir(), "pyudev": False, "pyusb": False}
    try:
        import pyudev  # noqa: F401

        status["pyudev"] = True
    except Exception:
        pass
    try:
        import usb.core  # noqa: F401

        status["pyusb"] = True
    except Exception:
        pass
    return status


def classify_interface(class_code: int, subclass: int, protocol: int) -> str:
    """Classify a single interface into a WISEBREAK ``kind``.

    This is deliberately conservative. ADB requires the exact
    vendor-specific ADB triple.
    """
    if class_code == 0xFF and subclass == 0x42 and protocol == 0x01:
        return "adb"
    if class_code == 0x06 and subclass == 0x01:
        return "mtp"  # PTP/MTP still-image class
    if class_code == 0xFF and subclass == 0xFF and protocol == 0xFF:
        return "vendor"
    if class_code == 0x02 and subclass in (0x02, 0x06, 0x0E):
        # 0x02 abstract control model (ACM), 0x06 ethernet, 0x0E MBIM
        return "cdc_acm" if subclass == 0x02 else "rndis"
    if class_code == 0xE0 and subclass == 0x01 and protocol == 0x03:
        return "rndis"
    if class_code == 0x0A:
        return "cdc_data"
    if class_code == 0x08:
        return "mass_storage"
    return "unknown"


def _device_kind(dev: UsbDevice) -> str:
    """Summarize a device's role from its interfaces, most privileged last."""
    kinds = {i_kind for i_kind in (classify_from_iface(i) for i in dev.interfaces)}
    if dev.vendor_id == SAMSUNG_VID and dev.product_id.lower() in ("685d",):
        return "download_mode"
    for priority in ("adb", "rndis", "cdc_acm", "mtp", "mass_storage", "vendor"):
        if priority in kinds:
            return priority
    return "unknown"


def classify_from_iface(i: UsbInterface) -> str:
    return classify_interface(i.class_code, i.subclass_code, i.protocol)


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def _read_int(path: Path, base: int = 16) -> int:
    val = _read(path)
    if not val:
        return 0
    try:
        return int(val, base)
    except ValueError:
        return 0


@dataclass(slots=True)
class _ProfileIds:
    labels: dict[str, str]

    @classmethod
    def load(cls) -> "_ProfileIds":
        labels: dict[str, str] = {}
        try:
            profile = resource_path("data/device_profile.toml")
            data = tomllib.loads(Path(profile).read_text())
            for entry in data.get("usb_ids", []):
                key = f"{entry['vid'].lower()}:{entry['pid'].lower()}"
                labels[key] = entry.get("label", "")
        except Exception as exc:  # pragma: no cover - profile is optional
            log.debug("could not load device profile usb_ids: %s", exc)
        return cls(labels)

    def label_for(self, vid: str, pid: str) -> str:
        key = f"{vid.lower()}:{pid.lower()}"
        if key in self.labels:
            return self.labels[key]
        if vid.lower() == SAMSUNG_VID:
            return SAMSUNG_KNOWN_PIDS.get(pid.lower(), "")
        return ""


class UsbDiscovery:
    """Enumerate USB devices and (optionally) monitor hotplug events."""

    def __init__(self) -> None:
        self.status = backend_status()
        self._profile = _ProfileIds.load()
        self._pyudev_context = None
        self._monitor = None
        if self.status["pyudev"]:
            try:
                import pyudev

                self._pyudev_context = pyudev.Context()
            except Exception as exc:  # pragma: no cover
                log.warning("pyudev context init failed: %s", exc)
                self.status["pyudev"] = False

    # ---- enumeration ------------------------------------------------------
    def enumerate(self) -> list[UsbDevice]:
        """Return all currently connected USB devices."""
        if not SYSFS_USB.is_dir():
            log.warning("sysfs USB path %s not present; cannot enumerate", SYSFS_USB)
            return []
        devices = [self._read_sysfs_device(p) for p in self._iter_device_dirs()]
        devices = [d for d in devices if d is not None]
        # Optionally enrich with pyusb string descriptors when sysfs is blank.
        if self.status["pyusb"]:
            self._enrich_with_pyusb(devices)
        devices.sort(key=lambda d: (d.vendor_id != SAMSUNG_VID, d.vid_pid))
        return devices

    def _iter_device_dirs(self) -> Iterator[Path]:
        for entry in sorted(SYSFS_USB.iterdir()):
            name = entry.name
            # Device dirs have idVendor; interface dirs contain ':' ; root hubs
            # start with 'usb'. We want true devices only.
            if ":" in name:
                continue
            if (entry / "idVendor").exists():
                yield entry

    def _read_sysfs_device(self, dev_dir: Path) -> UsbDevice | None:
        vid = _read(dev_dir / "idVendor")
        pid = _read(dev_dir / "idProduct")
        if not vid or not pid:
            return None
        dev = UsbDevice(
            vendor_id=vid.lower(),
            product_id=pid.lower(),
            manufacturer=_read(dev_dir / "manufacturer"),
            product=_read(dev_dir / "product"),
            serial=_read(dev_dir / "serial") or None,
            bus=_read(dev_dir / "busnum"),
            address=_read(dev_dir / "devnum"),
            sys_path=str(dev_dir.resolve()),
            speed=_read(dev_dir / "speed"),
        )
        dev.interfaces = list(self._read_interfaces(dev_dir))
        dev.kind = _device_kind(dev)
        dev.label = self._profile.label_for(vid, pid)
        return dev

    def _read_interfaces(self, dev_dir: Path) -> Iterator[UsbInterface]:
        prefix = dev_dir.name + ":"
        for iface_dir in sorted(dev_dir.parent.glob(prefix + "*")):
            if not iface_dir.is_dir():
                continue
            cls = _read_int(iface_dir / "bInterfaceClass")
            sub = _read_int(iface_dir / "bInterfaceSubClass")
            proto = _read_int(iface_dir / "bInterfaceProtocol")
            num = _read_int(iface_dir / "bInterfaceNumber", base=16)
            driver = None
            drv_link = iface_dir / "driver"
            if drv_link.is_symlink() or drv_link.exists():
                try:
                    driver = drv_link.resolve().name
                except OSError:
                    driver = None
            desc = USB_CLASS_NAMES.get(cls, f"Class 0x{cls:02x}")
            yield UsbInterface(
                class_code=cls,
                subclass_code=sub,
                protocol=proto,
                number=num,
                driver=driver,
                description=desc,
            )

    def _enrich_with_pyusb(self, devices: list[UsbDevice]) -> None:  # pragma: no cover
        try:
            import usb.core
            import usb.util
        except Exception:
            return
        for dev in devices:
            if dev.manufacturer and dev.product:
                continue
            try:
                found = usb.core.find(
                    idVendor=int(dev.vendor_id, 16), idProduct=int(dev.product_id, 16)
                )
                if found is None:
                    continue
                if not dev.manufacturer:
                    dev.manufacturer = usb.util.get_string(found, found.iManufacturer) or ""
                if not dev.product:
                    dev.product = usb.util.get_string(found, found.iProduct) or ""
            except Exception as exc:
                log.debug("pyusb enrich failed for %s: %s", dev.vid_pid, exc)

    # ---- monitoring -------------------------------------------------------
    def monitor(
        self,
        on_event: Callable[[str, UsbDevice | None], None],
        stop_flag: Callable[[], bool],
    ) -> None:  # pragma: no cover - requires live hardware events
        """Blocking monitor loop; call from a worker thread.

        Uses pyudev when available, otherwise polls ``enumerate`` and diffs.
        ``on_event`` is called with (action, device). ``stop_flag`` returning
        True ends the loop.
        """
        if self.status["pyudev"] and self._pyudev_context is not None:
            self._monitor_pyudev(on_event, stop_flag)
        else:
            self._monitor_poll(on_event, stop_flag)

    def _monitor_pyudev(self, on_event, stop_flag) -> None:  # pragma: no cover
        import pyudev

        monitor = pyudev.Monitor.from_netlink(self._pyudev_context)
        monitor.filter_by(subsystem="usb")
        monitor.start()
        for device in iter(lambda: monitor.poll(timeout=1.0), None):
            if stop_flag():
                return
            if device is None:
                continue
            action = device.action or "?"
            vid = device.get("ID_VENDOR_ID", "")
            pid = device.get("ID_MODEL_ID", "")
            dev_obj = None
            if vid and pid:
                dev_obj = UsbDevice(
                    vendor_id=vid.lower(),
                    product_id=pid.lower(),
                    product=device.get("ID_MODEL", ""),
                    manufacturer=device.get("ID_VENDOR", ""),
                    sys_path=device.sys_path,
                    label=self._profile.label_for(vid, pid),
                )
            on_event(action, dev_obj)
            if stop_flag():
                return

    def _monitor_poll(self, on_event, stop_flag, interval: float = 2.0) -> None:  # pragma: no cover
        import time

        previous = {d.vid_pid + d.sys_path: d for d in self.enumerate()}
        while not stop_flag():
            time.sleep(interval)
            current = {d.vid_pid + d.sys_path: d for d in self.enumerate()}
            for key, dev in current.items():
                if key not in previous:
                    on_event("add", dev)
            for key, dev in previous.items():
                if key not in current:
                    on_event("remove", dev)
            previous = current
