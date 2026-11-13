"""Patch-level comparison and conservative CVE relevance classification.

The matcher's job is to AVOID overclaiming. Two hard rules:

1. A CVE is never "confirmed vulnerable" just because its description text
   mentions "Android" or "Samsung". Keyword hits yield at most
   "potentially affected" and usually "insufficient evidence".

2. Patch-level math decides *plausibility of patch status*, not
   exploitability. A device patched after a CVE's bulletin date is
   classified "patched"; otherwise the result is "potentially affected"
   pending confirmation that the specific component is present and reachable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Classification, Confidence, CveRecord, Finding

# Public advisory sources, each with its canonical URL. Used for references
# and for the "Security advisory explorer" source list.
KNOWN_SOURCES = {
    "NVD": {
        "name": "NIST National Vulnerability Database",
        "url": "https://nvd.nist.gov/vuln/search",
        "note": "Authoritative CVE records with CVSS and references.",
    },
    "AndroidBulletin": {
        "name": "Android Security Bulletins",
        "url": "https://source.android.com/docs/security/bulletin",
        "note": "Monthly bulletins keyed by security patch level (YYYY-MM-01/05).",
    },
    "SamsungSMR": {
        "name": "Samsung Mobile Security Updates (SMR)",
        "url": "https://security.samsungmobile.com/securityUpdate.smsb",
        "note": "Samsung's monthly Security Maintenance Release notes (SVE items).",
    },
    "GHSA": {
        "name": "GitHub Security Advisories",
        "url": "https://github.com/advisories",
        "note": "Advisories for open-source components; map to CVEs where present.",
    },
    "KnoxDocs": {
        "name": "Samsung Knox Documentation",
        "url": "https://docs.samsungknox.com/",
        "note": "Authoritative Knox/EMM behavior and policy references.",
    },
}

_PATCH_RE = re.compile(r"(\d{4})-(\d{2})(?:-(\d{2}))?")


@dataclass(frozen=True, slots=True)
class PatchLevel:
    """An Android security patch level, e.g. 2026-06-05."""

    year: int
    month: int
    day: int = 1

    @classmethod
    def parse(cls, text: str) -> "PatchLevel | None":
        m = _PATCH_RE.search(text or "")
        if not m:
            return None
        year, month = int(m.group(1)), int(m.group(2))
        day = int(m.group(3)) if m.group(3) else 1
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return None
        return cls(year, month, day)

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.year, self.month, self.day)

    def __str__(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"


def compare_patch_levels(device: str, advisory: str) -> dict[str, object]:
    """Compare a device patch level to an advisory/bulletin date.

    Returns a dict describing the relationship. ``status`` is one of
    ``patched`` (device >= advisory), ``vulnerable_window`` (device <
    advisory), or ``unknown`` (unparseable).
    """
    dev = PatchLevel.parse(device)
    adv = PatchLevel.parse(advisory)
    if dev is None or adv is None:
        return {
            "status": "unknown",
            "device": str(dev) if dev else device,
            "advisory": str(adv) if adv else advisory,
            "explanation": "Could not parse one or both patch levels.",
        }
    if dev.as_tuple() >= adv.as_tuple():
        return {
            "status": "patched",
            "device": str(dev),
            "advisory": str(adv),
            "explanation": (
                f"Device patch level {dev} is at or after the advisory date {adv}; "
                "the fix is expected to be present (verify the specific SVE/CVE is "
                "listed in that month's bulletin)."
            ),
        }
    return {
        "status": "vulnerable_window",
        "device": str(dev),
        "advisory": str(adv),
        "explanation": (
            f"Device patch level {dev} predates the advisory {adv}. The device "
            "is within the vulnerable time window, but this alone does NOT prove "
            "the specific component is present or exploitable."
        ),
    }


# Terms that, alone, are far too generic to establish relevance.
_GENERIC_TERMS = {"android", "samsung", "mobile", "phone", "google"}


def classify_cve_relevance(
    cve: CveRecord,
    device_android_version: str,
    device_patch_level: str,
    device_model: str = "",
) -> Finding:
    """Produce a conservative :class:`Finding` for one CVE vs the device.

    This never returns ``CONFIRMED_VULNERABLE`` — confirmation requires
    corroborating evidence (a matching SVE in Samsung's bulletin for the
    device, or a reproduced condition) that the analyst must add manually.
    """
    desc_lower = cve.description.lower()
    evidence: list[str] = []
    sources = [cve.source_url] + [u for u in cve.references if u]

    mentions_android = "android" in desc_lower
    mentions_samsung = "samsung" in desc_lower or "galaxy" in desc_lower or "knox" in desc_lower
    mentions_version = device_android_version and (
        f"android {device_android_version}" in desc_lower
        or f"android version {device_android_version}" in desc_lower
    )
    model_hit = bool(device_model) and device_model.lower() in desc_lower

    # Try to find a bulletin/patch date in the CVE or references.
    patch_cmp = compare_patch_levels(device_patch_level, cve.published)

    # Decide classification conservatively.
    classification = Classification.INSUFFICIENT_EVIDENCE
    confidence = Confidence.LOW
    limitations = (
        "Classification is based on public metadata only. Presence of the "
        "affected component on this specific device/firmware has not been "
        "confirmed, and description keyword matches are not proof of "
        "exploitability."
    )

    if model_hit:
        evidence.append(f"CVE description references the device model '{device_model}'.")
        classification = Classification.POTENTIALLY_AFFECTED
        confidence = Confidence.MEDIUM
    elif mentions_samsung and (mentions_android or mentions_version):
        evidence.append("CVE references Samsung/Knox and Android together.")
        classification = Classification.POTENTIALLY_AFFECTED
        confidence = Confidence.LOW
    elif mentions_android or mentions_samsung:
        matched = {t for t in _GENERIC_TERMS if t in desc_lower}
        evidence.append(
            f"CVE matched only generic term(s): {', '.join(sorted(matched))}. "
            "This is insufficient to establish relevance."
        )
        classification = Classification.INSUFFICIENT_EVIDENCE
        confidence = Confidence.LOW

    if mentions_version:
        evidence.append(
            f"CVE text explicitly mentions Android {device_android_version}."
        )

    # Patch-level reasoning can downgrade to 'patched'.
    if patch_cmp["status"] == "patched" and classification in (
        Classification.POTENTIALLY_AFFECTED,
        Classification.INSUFFICIENT_EVIDENCE,
    ):
        evidence.append(str(patch_cmp["explanation"]))
        classification = Classification.PATCHED
        confidence = Confidence.MEDIUM
    elif patch_cmp["status"] == "vulnerable_window":
        evidence.append(str(patch_cmp["explanation"]))

    if cve.cvss_score is not None:
        evidence.append(
            f"CVSS {cve.cvss_version or '?'} base score {cve.cvss_score} "
            f"({cve.cvss_severity or 'n/a'})."
        )

    recommended = (
        "Confirm whether the affected component/package exists on firmware "
        f"'{device_patch_level}' and whether it is reachable given Knox "
        "restrictions. Cross-reference the matching Samsung SMR/SVE entry."
    )

    return Finding(
        title=f"{cve.cve_id}: relevance assessment",
        classification=classification,
        confidence=confidence,
        summary=cve.description[:400],
        evidence=evidence or ["No specific device indicators found in CVE metadata."],
        source_urls=[u for u in sources if u],
        cve_id=cve.cve_id,
        limitations=limitations,
        recommended_next=recommended,
    )
