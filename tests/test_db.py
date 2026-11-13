from __future__ import annotations

from wisebreak.models import (
    Classification,
    Confidence,
    CveRecord,
    Finding,
    UsbDevice,
    UsbInterface,
)


def test_session_lifecycle(db):
    sid = db.create_session("test")
    assert sid > 0
    assert db.get_session(sid)["name"] == "test"
    db.end_session(sid)
    assert db.get_session(sid)["ended_at"] is not None


def test_add_and_read_device(db):
    sid = db.create_session("s")
    dev = UsbDevice(
        vendor_id="04e8",
        product_id="6860",
        product="Galaxy",
        kind="mtp",
        interfaces=[UsbInterface(6, 1, 1, 0, driver="usb", description="Image")],
    )
    db.add_device(sid, dev)
    rows = db.devices_for_session(sid)
    assert len(rows) == 1
    assert rows[0]["vendor_id"] == "04e8"


def test_findings_roundtrip(db):
    sid = db.create_session("s")
    f = Finding(
        title="t",
        classification=Classification.INSUFFICIENT_EVIDENCE,
        confidence=Confidence.LOW,
        summary="sum",
        evidence=["e1"],
        source_urls=["https://x"],
        cve_id="CVE-2026-1",
    )
    db.add_finding(sid, f)
    got = db.findings_for_session(sid)
    assert len(got) == 1
    assert got[0].classification == Classification.INSUFFICIENT_EVIDENCE
    assert got[0].source_urls == ["https://x"]


def test_advisory_upsert(db):
    cve = CveRecord(
        cve_id="CVE-2026-9",
        description="desc",
        published="2026-01-01",
        last_modified="2026-01-02",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-9",
    )
    db.upsert_advisory(cve)
    db.upsert_advisory(cve)  # upsert should not duplicate
    rows = db.search_advisories("CVE-2026-9")
    assert len(rows) == 1


def test_compare_sessions(db):
    a = db.create_session("a")
    b = db.create_session("b")
    db.add_finding(a, Finding("only-a", Classification.PATCHED, Confidence.LOW, ""))
    db.add_finding(a, Finding("shared", Classification.PATCHED, Confidence.LOW, ""))
    db.add_finding(b, Finding("shared", Classification.PATCHED, Confidence.LOW, ""))
    diff = db.compare_sessions(a, b)
    assert ("only-a", "patched") in diff["findings_only_in_a"]
    assert ("shared", "patched") in diff["findings_common"]


def test_counts(db):
    sid = db.create_session("s")
    db.add_note(sid, "note")
    c = db.counts(sid)
    assert c["notes"] == 1
    assert c["findings"] == 0
