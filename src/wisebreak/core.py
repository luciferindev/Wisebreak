"""High-level orchestration tying subsystems to the research workspace.

Both the CLI and the TUI drive this class so behavior stays identical.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .config import Config
from .db import Database
from .diagnostics import SerialInspector, list_serial_interfaces
from .firmware import FirmwareAnalyzer
from .knox import KnoxKnowledge
from .logging_setup import get_logger
from .models import Finding, UsbDevice
from .paths import resource_path
from .reporting import ReportBuilder
from .usbscan import UsbDiscovery, backend_status
from .vuln import NvdClient, classify_cve_relevance

log = get_logger()


class Core:
    def __init__(self, config: Config) -> None:
        self.config = config
        config.ensure_dirs()
        self.db = Database(config.db_path)
        self.usb = UsbDiscovery()
        self.firmware = FirmwareAnalyzer(max_entry_bytes=config.firmware_max_entry_bytes)
        self.knox = KnoxKnowledge.load()
        self.device_profile = self._load_profile()
        self._session_id: int | None = None

    # ---- profile ----------------------------------------------------------
    @staticmethod
    def _load_profile() -> dict[str, Any]:
        try:
            path = Path(resource_path("data/device_profile.toml"))
            return tomllib.loads(path.read_text())
        except Exception as exc:  # pragma: no cover
            log.warning("could not load device profile: %s", exc)
            return {}

    # ---- sessions ---------------------------------------------------------
    def start_session(self, name: str) -> int:
        self._session_id = self.db.create_session(name)
        log.info("started research session %s (%s)", self._session_id, name)
        return self._session_id

    @property
    def session_id(self) -> int:
        if self._session_id is None:
            self._session_id = self.db.create_session("auto")
        return self._session_id

    def use_session(self, session_id: int) -> None:
        self._session_id = session_id

    # ---- USB --------------------------------------------------------------
    def scan_usb(self, persist: bool = True) -> list[UsbDevice]:
        devices = self.usb.enumerate()
        if persist:
            for d in devices:
                self.db.add_device(self.session_id, d)
        log.info("USB scan found %d device(s)", len(devices))
        return devices

    def backends(self) -> dict[str, bool]:
        return backend_status()

    # ---- firmware ---------------------------------------------------------
    def analyze_firmware(self, path: str | Path, persist: bool = True):
        report = self.firmware.analyze(Path(path))
        if persist:
            self.db.add_firmware(self.session_id, report.db_metadata())
        # Flag mismatches vs the device profile.
        self._firmware_mismatch_findings(report, persist=persist)
        return report

    def _firmware_mismatch_findings(self, report, persist: bool) -> list[Finding]:
        from .models import Classification, Confidence

        dev = self.device_profile.get("device", {})
        findings: list[Finding] = []
        expected_model = dev.get("model", "")
        if report.model and expected_model and report.model not in expected_model:
            f = Finding(
                title="Firmware model mismatch",
                classification=Classification.NOT_APPLICABLE,
                confidence=Confidence.HIGH,
                summary=(
                    f"Firmware model '{report.model}' does not match the target "
                    f"device model '{expected_model}'. This firmware is for a "
                    "different device and should not be used as a reference."
                ),
                evidence=[f"Firmware: {report.model}", f"Device profile: {expected_model}"],
                source_urls=[],
                limitations="Model inferred heuristically from filenames.",
            )
            findings.append(f)
        expected_csc = dev.get("csc", "")
        if report.csc and expected_csc and report.csc != expected_csc:
            findings.append(
                Finding(
                    title="CSC mismatch",
                    classification=Classification.POTENTIALLY_AFFECTED,
                    confidence=Confidence.MEDIUM,
                    summary=(
                        f"Firmware CSC '{report.csc}' differs from device CSC "
                        f"'{expected_csc}'. Region/carrier configuration differs."
                    ),
                    evidence=[f"Firmware CSC: {report.csc}", f"Device CSC: {expected_csc}"],
                    source_urls=[],
                )
            )
        if persist:
            for f in findings:
                self.db.add_finding(self.session_id, f)
        return findings

    # ---- knox -------------------------------------------------------------
    def knox_analysis(self) -> list[dict[str, Any]]:
        restrictions = self.device_profile.get("restrictions", {})
        return self.knox.analyze_observed(restrictions)

    # ---- vulnerabilities --------------------------------------------------
    def nvd_client(self) -> NvdClient:
        return NvdClient(
            api_base=self.config.nvd_api_base,
            cache_dir=self.config.cache_dir,
            api_key=self.config.nvd_api_key,
            timeout=self.config.vuln_timeout,
            cache_ttl=self.config.vuln_cache_ttl,
        )

    def search_and_classify(
        self, keyword: str, limit: int = 20, persist: bool = True
    ) -> list[Finding]:
        dev = self.device_profile.get("device", {})
        client = self.nvd_client()
        cves = client.search(keyword=keyword, results_per_page=limit)
        findings: list[Finding] = []
        for cve in cves:
            client_db = self.db
            client_db.upsert_advisory(cve, source="NVD", verified=True)
            finding = classify_cve_relevance(
                cve,
                device_android_version=dev.get("android_version", ""),
                device_patch_level=dev.get("build", ""),
                device_model=dev.get("model", ""),
            )
            findings.append(finding)
            if persist:
                self.db.add_finding(self.session_id, finding)
        return findings

    # ---- diagnostics ------------------------------------------------------
    def serial_interfaces(self):
        return list_serial_interfaces()

    def serial_inspector(self) -> SerialInspector:
        return SerialInspector(
            read_timeout=self.config.serial_read_timeout,
            max_capture_bytes=self.config.serial_max_capture_bytes,
            baud=self.config.serial_default_baud,
        )

    def capture_serial(self, device: str, persist: bool = True):
        inspector = self.serial_inspector()
        result = inspector.capture(device)
        if persist and result.bytes_captured:
            out = inspector.export_capture(result, self.config.firmware_cache_dir.parent / "captures")
            import hashlib

            sha = hashlib.sha256(result.data).hexdigest()
            self.db.add_evidence(
                self.session_id,
                kind="serial_capture",
                label=device,
                path=str(out),
                sha256=sha,
                size_bytes=result.bytes_captured,
            )
        return result

    # ---- reporting --------------------------------------------------------
    def build_report(self, formats: list[str] | None = None) -> dict[str, Path]:
        builder = ReportBuilder(self.db, redact_identifiers=self.config.redact_identifiers)
        data = builder.gather(
            self.session_id,
            device_profile=self.device_profile,
            knox_analysis=self.knox_analysis(),
            ownership_guidance=self.knox.ownership_guidance(),
        )
        return builder.build(
            data,
            out_dir=self.config.reports_dir,
            formats=formats or self.config.report_formats,
        )

    def report_data(self) -> dict[str, Any]:
        builder = ReportBuilder(self.db, redact_identifiers=self.config.redact_identifiers)
        return builder.gather(
            self.session_id,
            device_profile=self.device_profile,
            knox_analysis=self.knox_analysis(),
            ownership_guidance=self.knox.ownership_guidance(),
        )

    # ---- lifecycle --------------------------------------------------------
    def close(self) -> None:
        if self._session_id is not None:
            self.db.end_session(self._session_id)
        self.db.close()
