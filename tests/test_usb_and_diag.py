from __future__ import annotations

from wisebreak.diagnostics import hexdump
from wisebreak.usbscan import classify_interface
from wisebreak.usbscan.discovery import _ProfileIds


def test_classify_adb_requires_exact_triple():
    # The exact Android ADB vendor triple.
    assert classify_interface(0xFF, 0x42, 0x01) == "adb"
    # Vendor-specific but NOT adb must not be classified as adb.
    assert classify_interface(0xFF, 0x42, 0x02) != "adb"
    assert classify_interface(0xFF, 0xFF, 0xFF) == "vendor"


def test_classify_mtp():
    assert classify_interface(0x06, 0x01, 0x01) == "mtp"


def test_classify_cdc_acm_is_just_serial():
    # A CDC-ACM serial interface is 'cdc_acm' and nothing privileged.
    assert classify_interface(0x02, 0x02, 0x01) == "cdc_acm"


def test_classify_rndis():
    assert classify_interface(0xE0, 0x01, 0x03) == "rndis"


def test_profile_ids_label_samsung_mtp():
    ids = _ProfileIds.load()
    # Samsung MTP should be labeled from the bundled device profile or fallback.
    label = ids.label_for("04e8", "6860")
    assert "MTP" in label


def test_hexdump_format():
    dump = hexdump(b"ABCD\x00\xff")
    assert "41 42 43 44" in dump  # ABCD
    assert "|ABCD..|" in dump
    assert dump.startswith("00000000")
