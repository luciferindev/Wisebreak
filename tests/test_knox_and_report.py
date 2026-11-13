from __future__ import annotations

from wisebreak.knox import KnoxKnowledge
from wisebreak.models import Classification, Confidence, Finding
from wisebreak.reporting import ReportBuilder, redact


def test_knox_loads_and_explains():
    knox = KnoxKnowledge.load()
    assert knox.disclaimer
    techs = {t["id"] for t in knox.technologies()}
    assert "knox_manage" in techs
    assert "knox_mobile_enrollment" in techs

    analysis = knox.analyze_observed(
        {"apk_installation": "blocked", "usb_debugging": "blocked", "wifi": "allowed"}
    )
    keys = {a["restriction"] for a in analysis}
    assert "apk_installation" in keys
    assert "usb_debugging" in keys
    assert "wifi" not in keys  # only active restrictions explained
    for a in analysis:
        assert a["not_an_exploit"] is True


def test_knox_compare():
    knox = KnoxKnowledge.load()
    cmp = knox.compare("knox_manage", "knox_guard")
    assert "Knox Manage" in cmp["a"]
    assert "Knox Guard" in cmp["b"]


def test_redact():
    assert redact("ABCDEF123456", True).endswith("REDACTED")
    assert redact("ABCDEF123456", False) == "ABCDEF123456"
    assert redact("", True) == ""
    assert redact(None, True) == ""


def test_report_builder_markdown(db):
    sid = db.create_session("report-test")
    db.add_finding(
        sid,
        Finding(
            title="CVE-2026-1: relevance assessment",
            classification=Classification.POTENTIALLY_AFFECTED,
            confidence=Confidence.LOW,
            summary="Something about Samsung.",
            evidence=["generic match"],
            source_urls=["https://nvd.nist.gov/vuln/detail/CVE-2026-1"],
            cve_id="CVE-2026-1",
        ),
    )
    builder = ReportBuilder(db, redact_identifiers=True)
    profile = {
        "device": {"marketing_name": "Wisephone II", "model": "SM-A176U1"},
        "restrictions": {"apk_installation": "blocked"},
    }
    data = builder.gather(sid, profile)
    md = builder.render_markdown(data)
    assert "WISEBREAK Research Report" in md
    assert "Potentially affected" in md
    assert "CVE-2026-1" in md
    assert "nvd.nist.gov" in md
    # HTML render should not raise and should be a full document.
    html_doc = builder.render_html(data)
    assert html_doc.startswith("<!doctype html>")


def test_report_separates_confirmed_from_speculative(db):
    sid = db.create_session("sep")
    db.add_finding(sid, Finding("patched-item", Classification.PATCHED, Confidence.HIGH, "x"))
    db.add_finding(
        sid, Finding("maybe", Classification.INSUFFICIENT_EVIDENCE, Confidence.LOW, "y")
    )
    builder = ReportBuilder(db, redact_identifiers=True)
    data = builder.gather(sid, {"device": {}, "restrictions": {}})
    md = builder.render_markdown(data)
    assert "Patched (1)" in md
    assert "Insufficient evidence (1)" in md
