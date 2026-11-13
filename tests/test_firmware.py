from __future__ import annotations

import struct
import tarfile
import zipfile
from pathlib import Path

from wisebreak.firmware import (
    FirmwareAnalyzer,
    inspect_avb,
    inspect_boot_image,
    parse_samsung_version,
)
from wisebreak.firmware.boot_image import BOOT_MAGIC, VBMETA_MAGIC


def test_parse_samsung_version():
    parsed = parse_samsung_version("A176U1UEU8CZJA")
    assert parsed["parsed"] == "true"
    assert parsed["model"] == "A176U1"
    assert parsed["bootloader_revision"] == "8"
    assert parsed["date_code"] == "CZJA"


def test_parse_samsung_version_bad():
    assert parse_samsung_version("not-a-version")["parsed"] == "false"


def _make_boot_image() -> bytes:
    buf = bytearray(2048)
    buf[0:8] = BOOT_MAGIC
    # kernel_size, kaddr, ramdisk_size, raddr, second_size, saddr, tags,
    # page_size, header_version, os_version
    struct.pack_into(
        "<10I", buf, 8,
        1024, 0x8000, 512, 0x1000000, 0, 0, 0x100, 2048, 2, 0,
    )
    name = b"wisephone\x00"
    buf[48:48 + len(name)] = name
    cmd = b"console=ttyS0\x00"
    buf[64:64 + len(cmd)] = cmd
    return bytes(buf)


def test_inspect_boot_image():
    info = inspect_boot_image(_make_boot_image())
    assert info.is_boot_image
    assert info.kernel_size == 1024
    assert info.ramdisk_size == 512
    assert info.page_size == 2048
    assert info.header_version == 2
    assert info.product_name == "wisephone"


def test_inspect_boot_image_rejects_non_boot():
    assert inspect_boot_image(b"not a boot image at all 1234567890").is_boot_image is False


def test_inspect_avb_unsigned():
    blob = bytearray(256)
    blob[0:4] = VBMETA_MAGIC
    struct.pack_into(">II", blob, 4, 1, 0)       # version 1.0
    struct.pack_into(">QQ", blob, 12, 0, 0)      # auth/aux block sizes
    struct.pack_into(">I", blob, 28, 0)          # algorithm NONE
    res = inspect_avb(bytes(blob))
    assert res["is_vbmeta"] is True
    assert res["signed"] is False


def test_sha256(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello world")
    # sha256 of "hello world"
    assert FirmwareAnalyzer.sha256(f) == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_analyze_zip_components(tmp_path: Path):
    zip_path = tmp_path / "SM-A176U1_firmware.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("AP_A176U1UEU8CZJA_file.tar.md5", b"x" * 10)
        zf.writestr("BL_A176U1UEU8CZJA_file.tar.md5", b"x" * 10)
        zf.writestr("CP_A176U1UEU8CZJA_file.tar.md5", b"x" * 10)
        zf.writestr("CSC_OXM_A176U1_file.tar.md5", b"x" * 10)
        zf.writestr("HOME_CSC_OXM_A176U1_file.tar.md5", b"x" * 10)
    analyzer = FirmwareAnalyzer()
    report = analyzer.analyze(zip_path)
    assert report.archive_type == "zip"
    assert set(report.components) == {"AP", "BL", "CP", "CSC", "HOME_CSC"}
    assert report.model == "A176U1"
    assert report.bootloader_revision == "8"
    assert report.sha256


def test_analyze_tar_with_boot_image(tmp_path: Path):
    tar_path = tmp_path / "AP_A176U1UEU8CZJA_test.tar"
    boot = _make_boot_image()
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("boot.img")
        info.size = len(boot)
        import io

        tf.addfile(info, io.BytesIO(boot))
    report = FirmwareAnalyzer().analyze(tar_path)
    assert report.archive_type == "tar"
    names = [e.name for e in report.entries]
    assert "boot.img" in names
    assert report.boot_image.get("is_boot_image") is True


def test_oversize_guard(tmp_path: Path):
    zip_path = tmp_path / "big.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("AP_A176U1UEU8CZJA.tar.md5", b"x" * 100)
    analyzer = FirmwareAnalyzer(max_entry_bytes=10)  # tiny guard
    report = analyzer.analyze(zip_path)
    assert any("oversize" in w.lower() for w in report.warnings)
