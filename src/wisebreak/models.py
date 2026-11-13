"""Shared data models and the finding classification taxonomy."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Classification(enum.Enum):
    """Evidence-based classification for every research finding.

    The whole point of WISEBREAK is to NOT overclaim. A CVE whose text
    mentions Android or Samsung is *not* automatically relevant, and a
    vulnerable version string is *not* proof of exploitability.
    """

    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    POTENTIALLY_AFFECTED = "potentially_affected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    PATCHED = "patched"
    NOT_APPLICABLE = "not_applicable"

    @property
    def label(self) -> str:
        return {
            Classification.CONFIRMED_VULNERABLE: "Confirmed vulnerable",
            Classification.POTENTIALLY_AFFECTED: "Potentially affected",
            Classification.INSUFFICIENT_EVIDENCE: "Insufficient evidence",
            Classification.PATCHED: "Patched",
            Classification.NOT_APPLICABLE: "Not applicable",
        }[self]


class Confidence(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class UsbInterface:
    class_code: int
    subclass_code: int
    protocol: int
    number: int
    driver: str | None = None
    description: str = ""


@dataclass(slots=True)
class UsbDevice:
    vendor_id: str
    product_id: str
    manufacturer: str = ""
    product: str = ""
    serial: str | None = None
    bus: str = ""
    address: str = ""
    sys_path: str = ""
    speed: str = ""
    kind: str = "unknown"          # mtp | rndis | cdc_acm | adb | download_mode | ...
    label: str = ""               # friendly label from the device profile
    interfaces: list[UsbInterface] = field(default_factory=list)
    observed_at: str = field(default_factory=utcnow)

    @property
    def vid_pid(self) -> str:
        return f"{self.vendor_id}:{self.product_id}"


@dataclass(slots=True)
class CveRecord:
    cve_id: str
    description: str
    published: str
    last_modified: str
    cvss_version: str = ""
    cvss_score: float | None = None
    cvss_severity: str = ""
    source_url: str = ""
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    """A single research finding with explicit evidence and classification."""

    title: str
    classification: Classification
    confidence: Confidence
    summary: str
    evidence: list[str] = field(default_factory=list)
    source_urls: list[str] = field(default_factory=list)
    cve_id: str | None = None
    limitations: str = ""
    recommended_next: str = ""
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "classification": self.classification.value,
            "classification_label": self.classification.label,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "source_urls": self.source_urls,
            "cve_id": self.cve_id,
            "limitations": self.limitations,
            "recommended_next": self.recommended_next,
            "created_at": self.created_at,
        }
