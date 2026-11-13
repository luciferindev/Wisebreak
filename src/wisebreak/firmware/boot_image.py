"""Read-only inspection of Android boot images and AVB (vbmeta) metadata.

Parses headers only. Never modifies, re-signs, or repacks images.

References:
  * Android boot image header: https://source.android.com/docs/core/architecture/bootloader/boot-image-header
  * AVB / vbmeta: https://android.googlesource.com/platform/external/avb/+/master/README.md
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BOOT_MAGIC = b"ANDROID!"
VBMETA_MAGIC = b"AVB0"


@dataclass(slots=True)
class BootImageInfo:
    is_boot_image: bool = False
    header_version: int | None = None
    kernel_size: int | None = None
    ramdisk_size: int | None = None
    second_size: int | None = None
    page_size: int | None = None
    os_version: str = ""
    os_patch_level: str = ""
    cmdline: str = ""
    product_name: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_boot_image": self.is_boot_image,
            "header_version": self.header_version,
            "kernel_size": self.kernel_size,
            "ramdisk_size": self.ramdisk_size,
            "second_size": self.second_size,
            "page_size": self.page_size,
            "os_version": self.os_version,
            "os_patch_level": self.os_patch_level,
            "cmdline": self.cmdline,
            "product_name": self.product_name,
            "notes": self.notes,
        }


def _decode_os_version(value: int) -> tuple[str, str]:
    """Decode the packed os_version field (boot header v1+).

    Top 11 bits: a, next 7: b, next 7: c of OS version a.b.c.
    Low 11 bits of the remaining: year-2000, month -> patch level.
    """
    os_ver = value >> 11
    os_patch = value & 0x7FF
    a = (os_ver >> 14) & 0x7F
    b = (os_ver >> 7) & 0x7F
    c = os_ver & 0x7F
    year = (os_patch >> 4) + 2000
    month = os_patch & 0xF
    ver = f"{a}.{b}.{c}" if (a or b or c) else ""
    patch = f"{year:04d}-{month:02d}" if 1 <= month <= 12 else ""
    return ver, patch


def inspect_boot_image(data: bytes) -> BootImageInfo:
    """Inspect the first bytes of a (possibly large) boot image.

    Only the header is read; pass at least the first 4096 bytes.
    """
    info = BootImageInfo()
    if len(data) < 8 or data[:8] != BOOT_MAGIC:
        return info
    info.is_boot_image = True
    try:
        # Common fields across header versions 0-2:
        # magic[8], kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
        # second_size, second_addr, tags_addr, page_size, header_version,
        # os_version
        (
            kernel_size,
            _kernel_addr,
            ramdisk_size,
            _ramdisk_addr,
            second_size,
            _second_addr,
            _tags_addr,
            page_size,
            header_version,
            os_version,
        ) = struct.unpack_from("<10I", data, 8)
        info.kernel_size = kernel_size
        info.ramdisk_size = ramdisk_size
        info.second_size = second_size
        info.page_size = page_size
        info.header_version = header_version
        ver, patch = _decode_os_version(os_version)
        info.os_version = ver
        info.os_patch_level = patch
        # product name (16 bytes) + cmdline (512 bytes) at offset 48
        name = data[48:64].split(b"\x00", 1)[0].decode("ascii", "replace")
        cmdline = data[64:64 + 512].split(b"\x00", 1)[0].decode("ascii", "replace")
        info.product_name = name
        info.cmdline = cmdline
    except struct.error as exc:
        info.notes.append(f"Header parse incomplete: {exc}")
    return info


def inspect_avb(data: bytes) -> dict[str, Any]:
    """Inspect an AVB vbmeta blob header (read-only).

    Returns parsed AVB header fields, or ``{"is_vbmeta": False}``.
    """
    if len(data) < 256 or data[:4] != VBMETA_MAGIC:
        return {"is_vbmeta": False}
    try:
        # AvbVBMetaImageHeader (big-endian):
        # magic[4], required_libavb_version_major(u32), minor(u32),
        # authentication_data_block_size(u64), auxiliary_data_block_size(u64),
        # algorithm_type(u32), ...
        major, minor = struct.unpack_from(">II", data, 4)
        auth_size, aux_size = struct.unpack_from(">QQ", data, 12)
        algorithm_type = struct.unpack_from(">I", data, 28)[0]
        algo_names = {
            0: "NONE (unsigned)",
            1: "SHA256_RSA2048",
            2: "SHA256_RSA4096",
            3: "SHA256_RSA8192",
            4: "SHA512_RSA2048",
            5: "SHA512_RSA4096",
            6: "SHA512_RSA8192",
        }
        return {
            "is_vbmeta": True,
            "libavb_version": f"{major}.{minor}",
            "authentication_block_size": auth_size,
            "auxiliary_block_size": aux_size,
            "algorithm_type": algorithm_type,
            "algorithm_name": algo_names.get(algorithm_type, f"unknown({algorithm_type})"),
            "signed": algorithm_type != 0,
        }
    except struct.error as exc:
        return {"is_vbmeta": True, "error": f"header parse failed: {exc}"}


def inspect_file(path: Path, read_bytes: int = 8192) -> dict[str, Any]:
    """Inspect a file on disk, trying boot-image then AVB detection."""
    try:
        with path.open("rb") as fh:
            head = fh.read(read_bytes)
    except OSError as exc:
        return {"error": str(exc)}
    boot = inspect_boot_image(head)
    if boot.is_boot_image:
        return {"type": "boot_image", **boot.to_dict()}
    avb = inspect_avb(head)
    if avb.get("is_vbmeta"):
        return {"type": "vbmeta", **avb}
    return {"type": "unknown", "magic": head[:8].hex()}
