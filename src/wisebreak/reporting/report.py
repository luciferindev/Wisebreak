"""Build Markdown / JSON / HTML research reports from a session.

Reports redact serial numbers and other unique identifiers by default and
clearly separate confirmed findings from speculative attack surfaces.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..db import Database
from ..models import Classification, Finding
from .. import __version__

# Patterns for unique identifiers we redact by default.
_SERIAL_RE = re.compile(r"\b([A-Z0-9]{8,})\b")
_IMEI_RE = re.compile(r"\b\d{15,16}\b")


def redact(value: str | None, enabled: bool = True) -> str:
    """Redact a likely-unique identifier, keeping a short prefix for context."""
    if not value:
        return ""
    if not enabled:
        return value
    v = value.strip()
    if len(v) <= 4:
        return "REDACTED"
    return v[:2] + "…REDACTED"


def _redact_text(text: str, enabled: bool) -> str:
    if not enabled or not text:
        return text
    text = _IMEI_RE.sub("[REDACTED-IMEI]", text)
    return text


ORDER = [
    Classification.CONFIRMED_VULNERABLE,
    Classification.POTENTIALLY_AFFECTED,
    Classification.INSUFFICIENT_EVIDENCE,
    Classification.PATCHED,
    Classification.NOT_APPLICABLE,
]


@dataclass(slots=True)
class ReportContext:
    session_id: int
    session_name: str
    generated_at: str
    device_profile: dict[str, Any]
    observed_restrictions: dict[str, str]
    knox_analysis: list[dict[str, Any]]
    ownership_guidance: dict[str, Any]
    redact_identifiers: bool


class ReportBuilder:
    def __init__(self, db: Database, redact_identifiers: bool = True) -> None:
        self.db = db
        self.redact = redact_identifiers

    # ---- data gathering ---------------------------------------------------
    def gather(
        self,
        session_id: int,
        device_profile: dict[str, Any],
        knox_analysis: list[dict[str, Any]] | None = None,
        ownership_guidance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self.db.get_session(session_id)
        name = session["name"] if session else f"session-{session_id}"
        devices = [dict(r) for r in self.db.devices_for_session(session_id)]
        firmware = [dict(r) for r in self.db.firmware_for_session(session_id)]
        findings = self.db.findings_for_session(session_id)
        notes = [dict(r) for r in self.db.notes_for_session(session_id)]
        evidence = [dict(r) for r in self.db.evidence_for_session(session_id)]
        restrictions = device_profile.get("restrictions", {})

        return {
            "meta": {
                "tool": "WISEBREAK",
                "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "session_id": session_id,
                "session_name": name,
                "redacted": self.redact,
            },
            "device": self._device_block(device_profile),
            "observed_restrictions": restrictions,
            "knox_analysis": knox_analysis or [],
            "ownership_guidance": ownership_guidance or {},
            "usb_inventory": [self._device_row(d) for d in devices],
            "firmware": [self._firmware_row(f) for f in firmware],
            "findings": [self._finding_block(f) for f in findings],
            "notes": [{"created_at": n["created_at"], "body": n["body"]} for n in notes],
            "evidence": [
                {
                    "kind": e["kind"],
                    "label": e["label"],
                    "sha256": e["sha256"],
                    "size_bytes": e["size_bytes"],
                    "created_at": e["created_at"],
                }
                for e in evidence
            ],
            "limitations": self._global_limitations(),
        }

    def _device_block(self, profile: dict[str, Any]) -> dict[str, Any]:
        dev = profile.get("device", {})
        return {
            "marketing_name": dev.get("marketing_name", ""),
            "hardware_basis": dev.get("hardware_basis", ""),
            "model": dev.get("model", ""),
            "csc": dev.get("csc", ""),
            "android_version": dev.get("android_version", ""),
            "firmware": dev.get("firmware", ""),
            "build": dev.get("build", ""),
            "knox_version": dev.get("knox_version", ""),
            "knox_api_level": dev.get("knox_api_level", ""),
            "device_management": dev.get("device_management", ""),
        }

    def _device_row(self, d: dict[str, Any]) -> dict[str, Any]:
        return {
            "vid_pid": f"{d['vendor_id']}:{d['product_id']}",
            "manufacturer": d.get("manufacturer", ""),
            "product": d.get("product", ""),
            "kind": d.get("kind", ""),
            "label": d.get("label", ""),
            "serial": redact(d.get("serial"), self.redact),
            "observed_at": d.get("observed_at", ""),
        }

    def _firmware_row(self, f: dict[str, Any]) -> dict[str, Any]:
        return {
            "filename": f.get("filename", ""),
            "size_bytes": f.get("size_bytes", 0),
            "sha256": f.get("sha256", ""),
            "model": f.get("model", ""),
            "csc": f.get("csc", ""),
            "build": f.get("build", ""),
            "bootloader": f.get("bootloader", ""),
            "components": f.get("components", ""),
        }

    def _finding_block(self, f: Finding) -> dict[str, Any]:
        d = f.to_dict()
        d["summary"] = _redact_text(d["summary"], self.redact)
        return d

    @staticmethod
    def _global_limitations() -> list[str]:
        return [
            "WISEBREAK operates read-only; no device state was modified.",
            "A vulnerable software version is not proof of an exploitable "
            "vulnerability. Findings marked 'potentially affected' or "
            "'insufficient evidence' require corroboration.",
            "ADB-dependent inspection is unavailable while USB debugging is "
            "disabled by policy; related conclusions are limited accordingly.",
            "Knox/EMM analysis is documentation-based. No management API was "
            "contacted and no management control was bypassed.",
        ]

    # ---- rendering --------------------------------------------------------
    def build(
        self,
        data: dict[str, Any],
        out_dir: Path,
        formats: list[str],
        basename: str | None = None,
    ) -> dict[str, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = basename or f"wisebreak_report_session{data['meta']['session_id']}"
        written: dict[str, Path] = {}
        if "json" in formats:
            p = out_dir / f"{stem}.json"
            p.write_text(json.dumps(data, indent=2))
            written["json"] = p
        if "markdown" in formats:
            p = out_dir / f"{stem}.md"
            p.write_text(self.render_markdown(data))
            written["markdown"] = p
        if "html" in formats:
            p = out_dir / f"{stem}.html"
            p.write_text(self.render_html(data))
            written["html"] = p
        return written

    # ---- Markdown ---------------------------------------------------------
    def render_markdown(self, data: dict[str, Any]) -> str:
        m = data["meta"]
        dev = data["device"]
        lines: list[str] = []
        a = lines.append
        a(f"# WISEBREAK Research Report — {m['session_name']}")
        a("")
        a(f"*Generated {m['generated_at']} by WISEBREAK v{m['version']}.*  ")
        a(f"*Identifiers redacted: {m['redacted']}.*")
        a("")
        a("> **Scope & ethics.** Owner-authorized, read-only security research "
          "on hardware owned by the operator. No device was modified, flashed, "
          "or reset. No management control was bypassed.")
        a("")

        a("## 1. Device identification")
        a("")
        a("| Field | Value |")
        a("|---|---|")
        for label, key in [
            ("Marketing name", "marketing_name"),
            ("Hardware basis", "hardware_basis"),
            ("Model", "model"),
            ("CSC", "csc"),
            ("Android version", "android_version"),
            ("Firmware", "firmware"),
            ("Build", "build"),
            ("Knox version", "knox_version"),
            ("Knox API level", "knox_api_level"),
            ("Device management", "device_management"),
        ]:
            a(f"| {label} | {dev.get(key, '')} |")
        a("")

        a("## 2. Observed restrictions")
        a("")
        if data["observed_restrictions"]:
            a("| Restriction | Status |")
            a("|---|---|")
            for k, v in data["observed_restrictions"].items():
                a(f"| {k.replace('_', ' ')} | {v} |")
        else:
            a("_None recorded._")
        a("")

        a("## 3. Management / Knox architecture analysis")
        a("")
        if data["knox_analysis"]:
            for item in data["knox_analysis"]:
                a(f"### {item.get('restriction', '').replace('_', ' ').title()} "
                  f"— {item.get('status', '')}")
                a("")
                if item.get("observed"):
                    a(f"- **Observed:** {item['observed']}")
                for pol in item.get("likely_policies", []):
                    a(f"- **Likely policy:** {pol}")
                if item.get("legitimate_control"):
                    a(f"- **Legitimate control:** {item['legitimate_control']}")
                a(f"- **Exploit?** {'No — administrative control, not a vulnerability.' if item.get('not_an_exploit', True) else 'See finding.'}")
                a("")
        else:
            a("_No Knox analysis attached._")
        a("")

        a("## 4. USB interface inventory")
        a("")
        if data["usb_inventory"]:
            a("| VID:PID | Manufacturer | Product | Kind | Label | Serial |")
            a("|---|---|---|---|---|---|")
            for d in data["usb_inventory"]:
                a(f"| {d['vid_pid']} | {d['manufacturer']} | {d['product']} | "
                  f"{d['kind']} | {d['label']} | {d['serial']} |")
        else:
            a("_No USB devices captured in this session._")
        a("")

        a("## 5. Firmware analysis")
        a("")
        if data["firmware"]:
            for f in data["firmware"]:
                a(f"### {f['filename']}")
                a("")
                a(f"- SHA-256: `{f['sha256']}`")
                a(f"- Size: {f['size_bytes']} bytes")
                a(f"- Model/CSC/Build: {f['model']} / {f['csc']} / {f['build']}")
                a(f"- Bootloader revision: {f['bootloader']}")
                a(f"- Components: {f['components']}")
                a("")
        else:
            a("_No firmware analyzed in this session._")
        a("")

        a("## 6. Findings")
        a("")
        findings = data["findings"]
        by_class: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            by_class.setdefault(f["classification"], []).append(f)
        if not findings:
            a("_No findings recorded._")
        for cls in ORDER:
            group = by_class.get(cls.value, [])
            if not group:
                continue
            a(f"### {cls.label} ({len(group)})")
            a("")
            for f in group:
                a(f"#### {f['title']}")
                a("")
                a(f"- **Confidence:** {f['confidence']}")
                if f.get("cve_id"):
                    a(f"- **CVE:** {f['cve_id']}")
                a(f"- **Summary:** {f['summary']}")
                if f.get("evidence"):
                    a("- **Evidence:**")
                    for e in f["evidence"]:
                        a(f"    - {e}")
                if f.get("source_urls"):
                    a("- **Sources:**")
                    for u in f["source_urls"]:
                        a(f"    - {u}")
                if f.get("limitations"):
                    a(f"- **Limitations:** {f['limitations']}")
                if f.get("recommended_next"):
                    a(f"- **Recommended next:** {f['recommended_next']}")
                a("")

        if data.get("ownership_guidance"):
            og = data["ownership_guidance"]
            a("## 7. Owner-authorized restoration guidance")
            a("")
            if og.get("summary"):
                a(og["summary"])
                a("")
            for opt in og.get("options", []):
                a(f"- {opt}")
            if og.get("cautions"):
                a("")
                a("**Cautions:**")
                for c in og["cautions"]:
                    a(f"- {c}")
            a("")

        a("## 8. Evidence")
        a("")
        if data["evidence"]:
            a("| Kind | Label | SHA-256 | Bytes | Captured |")
            a("|---|---|---|---|---|")
            for e in data["evidence"]:
                a(f"| {e['kind']} | {e['label']} | `{e['sha256'][:16]}…` | "
                  f"{e['size_bytes']} | {e['created_at']} |")
        else:
            a("_No evidence artifacts._")
        a("")

        a("## 9. Limitations")
        a("")
        for lim in data["limitations"]:
            a(f"- {lim}")
        a("")
        return "\n".join(lines)

    # ---- HTML -------------------------------------------------------------
    def render_html(self, data: dict[str, Any]) -> str:
        # Render markdown-ish content into a styled standalone HTML document.
        md = self.render_markdown(data)
        body = html.escape(md)
        css = (
            "body{background:#0b0f14;color:#cfe8ef;font-family:ui-monospace,"
            "SFMono-Regular,Menlo,monospace;max-width:960px;margin:2rem auto;"
            "padding:0 1rem;line-height:1.5}"
            "pre{white-space:pre-wrap;word-wrap:break-word}"
            "h1{color:#38bdf8;border-bottom:1px solid #164e63;padding-bottom:.3rem}"
            "a{color:#5eead4}"
        )
        return (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>WISEBREAK Report — {html.escape(data['meta']['session_name'])}</title>"
            f"<style>{css}</style></head><body><pre>{body}</pre></body></html>"
        )
