from __future__ import annotations

from wisebreak.models import Classification, CveRecord
from wisebreak.vuln.matcher import (
    PatchLevel,
    classify_cve_relevance,
    compare_patch_levels,
)


def test_patchlevel_parse():
    assert PatchLevel.parse("2026-06-05").as_tuple() == (2026, 6, 5)
    assert PatchLevel.parse("2026-06").as_tuple() == (2026, 6, 1)
    assert PatchLevel.parse("not-a-date") is None
    assert PatchLevel.parse("2026-13-01") is None  # invalid month


def test_compare_patch_levels_patched():
    res = compare_patch_levels("2026-06-05", "2026-05-01")
    assert res["status"] == "patched"


def test_compare_patch_levels_vulnerable_window():
    res = compare_patch_levels("2026-01-01", "2026-06-01")
    assert res["status"] == "vulnerable_window"


def test_compare_patch_levels_unknown():
    assert compare_patch_levels("garbage", "also garbage")["status"] == "unknown"


def _cve(desc: str, published: str = "2026-06-01T00:00:00") -> CveRecord:
    return CveRecord(
        cve_id="CVE-2026-00000",
        description=desc,
        published=published,
        last_modified=published,
        cvss_score=7.5,
        cvss_severity="HIGH",
        cvss_version="3.1",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-00000",
    )


def test_generic_android_mention_is_not_confirmed():
    """A bare 'Android' mention must never be confirmed-vulnerable."""
    cve = _cve("A flaw in some Android component allows denial of service.")
    finding = classify_cve_relevance(cve, "17", "A176U1UEU8CZJA", "SM-A176U1")
    assert finding.classification != Classification.CONFIRMED_VULNERABLE
    assert finding.classification in (
        Classification.INSUFFICIENT_EVIDENCE,
        Classification.POTENTIALLY_AFFECTED,
        Classification.PATCHED,
    )
    # Must carry a source URL.
    assert finding.source_urls
    assert finding.source_urls[0].startswith("https://")


def test_model_hit_is_potentially_affected():
    cve = _cve("Issue affecting SM-A176U1 under specific conditions.",
               published="2027-01-01T00:00:00")
    finding = classify_cve_relevance(cve, "17", "A176U1UEU8CZJA", "SM-A176U1")
    assert finding.classification == Classification.POTENTIALLY_AFFECTED


def test_patched_when_device_newer():
    # device build date code implies a later patch level than the CVE date
    cve = _cve("Samsung Android Knox related issue.", published="2025-01-01T00:00:00")
    finding = classify_cve_relevance(cve, "17", "2026-06-05", "SM-A176U1")
    assert finding.classification == Classification.PATCHED


def test_never_confirmed_without_manual_evidence():
    cve = _cve("Samsung Galaxy Knox Android 17 critical remote code execution.")
    finding = classify_cve_relevance(cve, "17", "A176U1UEU8CZJA", "SM-A176U1")
    assert finding.classification != Classification.CONFIRMED_VULNERABLE
