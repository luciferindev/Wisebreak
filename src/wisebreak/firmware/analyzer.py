"""Offline Samsung firmware package analyzer.

Supported, all READ-ONLY:
  * ZIP archive inspection (the outer Samsung firmware .zip).
  * Component identification: AP, BL, CP, CSC, HOME_CSC.
  * TAR / tar.md5 archive inspection.
  * LZ4 (frame) peek-decompression of partition images.
  * Partition image identification (boot, recovery, vbmeta, super, ...).
  * Firmware metadata extraction (model, CSC, build, bootloader revision).
  * SHA-256 verification.
  * Android boot image + AVB header inspection (see boot_image.py).

The analyzer never writes to, repacks, or modifies firmware images. It
extracts nothing permanently; peeks are bounded and in-memory.
"""

from __future__ import annotations

import hashlib
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from . import boot_image

log = get_logger()

# Samsung firmware component prefixes.
COMPONENT_PREFIXES = ("AP", "BL", "CP", "CSC", "HOME_CSC", "USERDATA")

# Recognized partition image basenames (without compression suffix).
PARTITION_IMAGES = {
    "boot.img": "Android boot image (kernel + ramdisk)",
    "init_boot.img": "Generic ramdisk (GKI init_boot)",
    "vendor_boot.img": "Vendor boot image",
    "recovery.img": "Recovery image",
    "dtbo.img": "Device Tree Blob Overlay",
    "vbmeta.img": "AVB top-level vbmeta",
    "vbmeta_system.img": "AVB system vbmeta",
    "super.img": "Dynamic partitions super image",
    "system.img": "System partition",
    "vendor.img": "Vendor partition",
    "product.img": "Product partition",
    "odm.img": "ODM partition",
    "sboot.bin": "Secondary bootloader (S-Boot)",
    "cm.bin": "Cortex-M / sensor hub firmware",
    "up_param.bin": "Boot logo / up parameters",
    "modem.bin": "Cellular modem (CP) firmware",
    "param.bin": "Parameter partition",
    "keystorage.bin": "Key storage",
}

LZ4_MAGIC = b"\x04\x22\x4d\x18"


@dataclass(slots=True)
class ArchiveEntry:
    name: str
    size: int
    component: str = ""        # AP/BL/CP/CSC/HOME_CSC if recognized
    image_kind: str = ""       # description if a known partition image
    compressed: str = ""       # 'lz4' | 'gz' | ''

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "component": self.component,
            "image_kind": self.image_kind,
            "compressed": self.compressed,
        }


@dataclass(slots=True)
class FirmwareReport:
    path: str
    filename: str
    size_bytes: int
    sha256: str = ""
    archive_type: str = ""           # zip | tar | tar.md5 | unknown
    components: list[str] = field(default_factory=list)
    entries: list[ArchiveEntry] = field(default_factory=list)
    model: str = ""
    csc: str = ""
    build: str = ""
    bootloader_revision: str = ""
    date_code: str = ""
    boot_image: dict[str, Any] = field(default_factory=dict)
    avb: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "archive_type": self.archive_type,
            "components": self.components,
            "entries": [e.to_dict() for e in self.entries],
            "model": self.model,
            "csc": self.csc,
            "build": self.build,
            "bootloader_revision": self.bootloader_revision,
            "date_code": self.date_code,
            "boot_image": self.boot_image,
            "avb": self.avb,
            "warnings": self.warnings,
        }

    def db_metadata(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "model": self.model,
            "csc": self.csc,
            "build": self.build,
            "bootloader": self.bootloader_revision,
            "components": self.components,
            "metadata": self.to_dict(),
        }


_VERSION_RE = re.compile(
    r"(?P<model>[A-Z]\d{3}[A-Z]{0,2}\d?)"  # e.g. A176U1
    r"(?P<carrier>[A-Z]{3})"               # 3-letter bootloader/carrier block, e.g. UEU
    r"(?P<boot>\d)"                        # single bootloader revision digit, e.g. 8
    r"(?P<date>[A-Z0-9]{4})"               # 4-char date/build code, e.g. CZJA
)


def parse_samsung_version(version: str) -> dict[str, str]:
    """Best-effort parse of a Samsung firmware/build version string.

    Example: ``A176U1UEU8CZJA`` ->
        model='A176U1', carrier='UEU', bootloader_revision='8',
        date_code='CZJA'.

    NOTE: Samsung's encoding is only partially public; this is heuristic and
    is reported as such. The bootloader revision digit and date code are the
    reliably interpretable parts.
    """
    out = {
        "model": "",
        "carrier": "",
        "bootloader_revision": "",
        "date_code": "",
        "parsed": "false",
    }
    m = _VERSION_RE.search(version or "")
    if not m:
        return out
    out.update(
        model=m.group("model"),
        carrier=m.group("carrier"),
        bootloader_revision=m.group("boot"),
        date_code=m.group("date"),
        parsed="true",
    )
    return out


class FirmwareAnalyzer:
    def __init__(self, max_entry_bytes: int = 8 * 1024**3) -> None:
        self.max_entry_bytes = max_entry_bytes

    # ---- hashing ----------------------------------------------------------
    @staticmethod
    def sha256(path: Path, chunk: int = 1 << 20) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(chunk), b""):
                h.update(block)
        return h.hexdigest()

    # ---- top-level --------------------------------------------------------
    def analyze(self, path: Path, compute_hash: bool = True) -> FirmwareReport:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        report = FirmwareReport(
            path=str(path),
            filename=path.name,
            size_bytes=path.stat().st_size,
        )
        if compute_hash:
            log.info("hashing %s", path.name)
            report.sha256 = self.sha256(path)

        name_lower = path.name.lower()
        if zipfile.is_zipfile(path):
            report.archive_type = "zip"
            self._analyze_zip(path, report)
        elif name_lower.endswith((".tar", ".tar.md5", ".md5")) or tarfile.is_tarfile(path):
            report.archive_type = "tar.md5" if name_lower.endswith(".md5") else "tar"
            self._analyze_tar(path, report)
        else:
            report.archive_type = "unknown"
            report.warnings.append("Unrecognized archive type; only metadata extracted.")

        self._extract_version_metadata(report)
        return report

    # ---- ZIP (outer package) ---------------------------------------------
    def _analyze_zip(self, path: Path, report: FirmwareReport) -> None:
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > self.max_entry_bytes:
                        report.warnings.append(
                            f"Skipping oversize entry {info.filename} "
                            f"({info.file_size} bytes > guard)."
                        )
                        continue
                    comp = self._component_of(info.filename)
                    entry = ArchiveEntry(
                        name=info.filename,
                        size=info.file_size,
                        component=comp,
                    )
                    report.entries.append(entry)
                    if comp and comp not in report.components:
                        report.components.append(comp)
        except zipfile.BadZipFile as exc:
            report.warnings.append(f"Bad ZIP: {exc}")

    # ---- TAR / tar.md5 (component archive) --------------------------------
    def _analyze_tar(self, path: Path, report: FirmwareReport) -> None:
        try:
            # tar.md5 is a tar with an appended md5 text line; tarfile reads
            # the tar portion and ignores the trailer.
            with tarfile.open(path, mode="r:*", ignore_zeros=True) as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    entry = ArchiveEntry(name=member.name, size=member.size)
                    self._classify_image_entry(entry)
                    comp = self._component_of(member.name)
                    if comp:
                        entry.component = comp
                        if comp not in report.components:
                            report.components.append(comp)
                    report.entries.append(entry)
                    # Peek boot image / vbmeta headers for the small, relevant ones.
                    self._maybe_peek_header(tf, member, entry, report)
        except tarfile.TarError as exc:
            report.warnings.append(f"TAR read error: {exc}")

    def _maybe_peek_header(
        self,
        tf: tarfile.TarFile,
        member: tarfile.TarInfo,
        entry: ArchiveEntry,
        report: FirmwareReport,
    ) -> None:
        base = entry.name.rsplit("/", 1)[-1]
        stem = base[:-4] if base.endswith(".lz4") else base
        want = stem in ("boot.img", "init_boot.img", "vbmeta.img", "vbmeta_system.img")
        if not want:
            return
        try:
            fh = tf.extractfile(member)
            if fh is None:
                return
            raw = fh.read(1 << 20)  # read up to 1 MiB of the (possibly lz4) stream
        except (tarfile.TarError, OSError) as exc:
            report.warnings.append(f"Could not read {entry.name}: {exc}")
            return
        head = raw
        if entry.compressed == "lz4" or raw[:4] == LZ4_MAGIC:
            head = _lz4_peek(raw, want_bytes=8192)
            if head is None:
                report.warnings.append(
                    f"{entry.name} is LZ4-compressed; install the 'lz4' extra to "
                    "inspect its header."
                )
                return
        if stem in ("boot.img", "init_boot.img"):
            info = boot_image.inspect_boot_image(head)
            if info.is_boot_image and not report.boot_image:
                report.boot_image = {"source": entry.name, **info.to_dict()}
        else:
            avb = boot_image.inspect_avb(head)
            if avb.get("is_vbmeta") and not report.avb:
                report.avb = {"source": entry.name, **avb}

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    def _component_of(name: str) -> str:
        base = name.rsplit("/", 1)[-1]
        for prefix in sorted(COMPONENT_PREFIXES, key=len, reverse=True):
            if base.startswith(prefix + "_"):
                return prefix
        return ""

    @staticmethod
    def _classify_image_entry(entry: ArchiveEntry) -> None:
        base = entry.name.rsplit("/", 1)[-1]
        if base.endswith(".lz4"):
            entry.compressed = "lz4"
            base = base[:-4]
        elif base.endswith(".gz"):
            entry.compressed = "gz"
            base = base[:-3]
        if base in PARTITION_IMAGES:
            entry.image_kind = PARTITION_IMAGES[base]

    def _extract_version_metadata(self, report: FirmwareReport) -> None:
        # Pull a version string from component filenames (AP_<model>..._<build>).
        candidates = [e.name for e in report.entries] + [report.filename]
        for name in candidates:
            parsed = parse_samsung_version(name.rsplit("/", 1)[-1])
            if parsed["parsed"] == "true":
                report.model = report.model or parsed["model"]
                report.bootloader_revision = (
                    report.bootloader_revision or parsed["bootloader_revision"]
                )
                report.date_code = report.date_code or parsed["date_code"]
                report.build = report.build or name.rsplit("/", 1)[-1]
                break
        # CSC code often appears as a 3-letter token in CSC_<CODE>_... filenames.
        for e in report.entries:
            base = e.name.rsplit("/", 1)[-1]
            m = re.match(r"(?:HOME_)?CSC_([A-Z0-9]{3,4})_", base)
            if m:
                report.csc = report.csc or m.group(1)
                break


def _lz4_peek(data: bytes, want_bytes: int = 8192) -> bytes | None:
    """Incrementally decompress an LZ4 *frame* until ``want_bytes`` of output.

    Returns ``None`` if the ``lz4`` package is unavailable or the data is not
    a valid LZ4 frame.
    """
    try:
        import lz4.frame
    except Exception:
        return None
    try:
        ctx = lz4.frame.LZ4FrameDecompressor()
        out = ctx.decompress(data, max_length=want_bytes)
        return out or None
    except Exception as exc:  # pragma: no cover - corrupt/partial frame
        log.debug("lz4 peek failed: %s", exc)
        return None
