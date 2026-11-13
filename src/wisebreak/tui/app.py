"""WISEBREAK Textual application.

A keyboard-driven, dark-cyan security research console. Every long-running
operation runs in a worker thread so the UI stays responsive; results are
marshaled back with ``call_from_thread``.
"""

from __future__ import annotations

from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Grid, Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from ..config import Config
from ..core import Core
from ..diagnostics import hexdump
from ..logging_setup import get_ring_handler, get_logger
from ..models import Classification
from ..vuln import KNOWN_SOURCES

log = get_logger()


class WisebreakApp(App):
    CSS_PATH = "app.tcss"
    TITLE = "WISEBREAK"
    SUB_TITLE = "owner-authorized Android security research — read-only"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan_usb", "Scan USB"),
        ("d", "scan_serial", "Diagnostics"),
        ("r", "export_report", "Export report"),
        ("k", "refresh_knox", "Knox"),
        ("f1", "show_tab('dashboard')", "Dashboard"),
        ("ctrl+l", "clear_log", "Clear log"),
    ]

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self.core = Core(config)
        self.core.start_session("tui-session")
        self._usb_cache: list = []

    # ---- layout -----------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield from self._compose_dashboard()
            with TabPane("USB Explorer", id="usb"):
                yield from self._compose_usb()
            with TabPane("Firmware", id="firmware"):
                yield from self._compose_firmware()
            with TabPane("Advisories", id="advisories"):
                yield from self._compose_advisories()
            with TabPane("Knox", id="knox"):
                yield from self._compose_knox()
            with TabPane("Diagnostics", id="diagnostics"):
                yield from self._compose_diagnostics()
            with TabPane("Findings", id="findings"):
                yield from self._compose_findings()
            with TabPane("Reports", id="reports"):
                yield from self._compose_reports()
            with TabPane("Logs", id="logs"):
                yield from self._compose_logs()
            with TabPane("Config", id="config"):
                yield from self._compose_config()
        yield Footer()

    # ---- dashboard --------------------------------------------------------
    def _compose_dashboard(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Device under investigation", classes="panel-title")
            yield Static(id="device-info")
            yield Static("Backend status", classes="panel-title")
            yield Static(id="backend-info")
            yield Static(
                "All operations are read-only. WISEBREAK never flashes, resets, "
                "or bypasses device management.",
                classes="hint",
            )

    # ---- usb --------------------------------------------------------------
    def _compose_usb(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("USB device explorer", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Button("Scan (s)", id="btn-usb-scan", classes="-primary")
            table = DataTable(id="usb-table", cursor_type="row")
            table.add_columns("VID:PID", "Kind", "Label", "Manufacturer", "Product", "Serial")
            yield table
            yield Static("Select a row for interface detail.", classes="hint")
            yield Static(id="usb-detail")

    # ---- firmware ---------------------------------------------------------
    def _compose_firmware(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Firmware analysis dashboard (offline, read-only)", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Input(
                    placeholder="/home/$USER/Downloads/wisebreak/SM-A176U1_firmware.zip",
                    id="firmware-path",
                )
                yield Button("Analyze", id="btn-firmware", classes="-primary")
            yield Markdown("_No firmware analyzed yet._", id="firmware-result")

    # ---- advisories -------------------------------------------------------
    def _compose_advisories(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Security advisory explorer", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="keyword, e.g. 'Samsung Knox' or 'Android 17'", id="cve-kw")
                yield Button("Search NVD", id="btn-cve", classes="-primary")
            table = DataTable(id="cve-table", cursor_type="row")
            table.add_columns("CVE", "Classification", "Confidence", "Summary")
            yield table
            yield Static(self._sources_text(), classes="hint")

    def _sources_text(self) -> str:
        lines = ["Sources: "]
        lines += [f"{v['name']} ({v['url']})" for v in KNOWN_SOURCES.values()]
        return "  •  ".join([lines[0]] + lines[1:])

    # ---- knox -------------------------------------------------------------
    def _compose_knox(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Knox management diagnostics (documentation-based)", classes="panel-title")
            yield Markdown(id="knox-md")

    # ---- diagnostics ------------------------------------------------------
    def _compose_diagnostics(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Diagnostic interface inspector (passive)", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Button("Refresh (d)", id="btn-serial-refresh", classes="-primary")
                yield Button("Passive capture", id="btn-serial-capture")
            table = DataTable(id="serial-table", cursor_type="row")
            table.add_columns("Device", "Driver", "VID:PID", "Product", "Present")
            yield table
            yield Static(
                "Capture is READ-ONLY: no bytes are ever written to the port.",
                classes="hint",
            )
            yield RichLog(id="serial-hex", highlight=False, markup=False)

    # ---- findings ---------------------------------------------------------
    def _compose_findings(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Research findings database", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Button("Refresh", id="btn-findings", classes="-primary")
            table = DataTable(id="findings-table", cursor_type="row")
            table.add_columns("Title", "Classification", "Confidence", "CVE")
            yield table
            yield Static(id="findings-detail")

    # ---- reports ----------------------------------------------------------
    def _compose_reports(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Exportable reports", classes="panel-title")
            with Horizontal(classes="toolbar"):
                yield Button("Export (r)", id="btn-report", classes="-primary")
            yield Static(id="report-result")
            yield Markdown(id="report-preview")

    # ---- logs -------------------------------------------------------------
    def _compose_logs(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Live operation logs / command history", classes="panel-title")
            yield RichLog(id="op-log", highlight=False, markup=False, max_lines=5000)

    # ---- config -----------------------------------------------------------
    def _compose_config(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("Configuration manager", classes="panel-title")
            yield Static(id="config-info")

    # ---- lifecycle --------------------------------------------------------
    def on_mount(self) -> None:
        get_ring_handler().set_listener(self._on_log_line)
        self._refresh_dashboard()
        self._refresh_knox()
        self._refresh_config()
        log.info("WISEBREAK TUI ready. Session %s.", self.core.session_id)

    def on_unmount(self) -> None:
        get_ring_handler().set_listener(None)
        self.core.close()

    def _on_log_line(self, line: str) -> None:
        try:
            self.call_from_thread(self._append_log, line)
        except Exception:
            pass

    def _append_log(self, line: str) -> None:
        try:
            self.query_one("#op-log", RichLog).write(line)
        except Exception:
            pass

    # ---- dashboard rendering ---------------------------------------------
    def _refresh_dashboard(self) -> None:
        dev = self.core.device_profile.get("device", {})
        info = "\n".join(
            f"[b]{k.replace('_', ' ').title()}[/]: {v}"
            for k, v in dev.items()
        )
        self.query_one("#device-info", Static).update(info or "No device profile loaded.")
        b = self.core.backends()
        parts = []
        for name, present in b.items():
            mark = "[#4ade80]available[/]" if present else "[#f87171]missing[/]"
            parts.append(f"{name}: {mark}")
        self.query_one("#backend-info", Static).update("   ".join(parts))

    def _refresh_config(self) -> None:
        c = self.config
        src = c.source_file or "built-in defaults"
        text = (
            f"[b]Config source[/]: {src}\n"
            f"[b]Data dir[/]: {c.data_dir}\n"
            f"[b]Database[/]: {c.db_path}\n"
            f"[b]Reports dir[/]: {c.reports_dir}\n"
            f"[b]Read-only[/]: {c.read_only}\n"
            f"[b]Redact identifiers[/]: {c.redact_identifiers}\n"
            f"[b]NVD API base[/]: {c.nvd_api_base}\n"
            f"[b]NVD API key set[/]: {bool(c.nvd_api_key)}\n"
            f"[b]Serial read timeout[/]: {c.serial_read_timeout}s\n"
            f"[b]Report formats[/]: {', '.join(c.report_formats)}\n"
        )
        self.query_one("#config-info", Static).update(text)

    # ---- actions ----------------------------------------------------------
    def action_scan_usb(self) -> None:
        self._scan_usb()

    def action_scan_serial(self) -> None:
        self._refresh_serial()

    def action_refresh_knox(self) -> None:
        self._refresh_knox()

    def action_export_report(self) -> None:
        self._export_report()

    def action_clear_log(self) -> None:
        self.query_one("#op-log", RichLog).clear()

    def action_show_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    # ---- buttons ----------------------------------------------------------
    @on(Button.Pressed, "#btn-usb-scan")
    def _btn_usb(self) -> None:
        self._scan_usb()

    @on(Button.Pressed, "#btn-firmware")
    def _btn_firmware(self) -> None:
        path = self.query_one("#firmware-path", Input).value.strip()
        if not path:
            self.notify("Enter a firmware path first.", severity="warning")
            return
        self._analyze_firmware(path)

    @on(Button.Pressed, "#btn-cve")
    def _btn_cve(self) -> None:
        kw = self.query_one("#cve-kw", Input).value.strip()
        if not kw:
            self.notify("Enter a search keyword.", severity="warning")
            return
        self._search_cve(kw)

    @on(Button.Pressed, "#btn-serial-refresh")
    def _btn_serial(self) -> None:
        self._refresh_serial()

    @on(Button.Pressed, "#btn-serial-capture")
    def _btn_capture(self) -> None:
        table = self.query_one("#serial-table", DataTable)
        if table.row_count == 0:
            self.notify("No serial interfaces listed. Refresh first.", severity="warning")
            return
        try:
            row = table.get_row_at(table.cursor_row)
        except Exception:
            self.notify("Select a serial interface row first.", severity="warning")
            return
        self._capture_serial(str(row[0]))

    @on(Button.Pressed, "#btn-findings")
    def _btn_findings(self) -> None:
        self._refresh_findings()

    @on(Button.Pressed, "#btn-report")
    def _btn_report(self) -> None:
        self._export_report()

    # ---- USB worker -------------------------------------------------------
    @work(thread=True, exclusive=True)
    def _scan_usb(self) -> None:
        log.info("scanning USB bus…")
        devices = self.core.scan_usb()
        self._usb_cache = devices
        self.call_from_thread(self._render_usb, devices)

    def _render_usb(self, devices) -> None:
        table = self.query_one("#usb-table", DataTable)
        table.clear()
        for d in devices:
            serial = "redacted" if (d.serial and self.config.redact_identifiers) else (d.serial or "")
            table.add_row(d.vid_pid, d.kind, d.label or "", d.manufacturer, d.product, serial)
        self.notify(f"USB scan complete: {len(devices)} device(s).")
        self._refresh_dashboard()

    @on(DataTable.RowHighlighted, "#usb-table")
    def _usb_row(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is None or event.cursor_row >= len(self._usb_cache):
            return
        dev = self._usb_cache[event.cursor_row]
        lines = [f"[b]{dev.vid_pid}[/]  bus {dev.bus} addr {dev.address}  speed {dev.speed}"]
        for i in dev.interfaces:
            drv = i.driver or "—"
            lines.append(
                f"  iface {i.number}: class 0x{i.class_code:02x}/{i.subclass_code:02x}/"
                f"{i.protocol:02x}  {i.description}  driver={drv}"
            )
        self.query_one("#usb-detail", Static).update("\n".join(lines))

    # ---- firmware worker --------------------------------------------------
    @work(thread=True, exclusive=True)
    def _analyze_firmware(self, path: str) -> None:
        try:
            report = self.core.analyze_firmware(path)
        except FileNotFoundError:
            self.call_from_thread(self.notify, f"File not found: {path}", severity="error")
            return
        except Exception as exc:  # pragma: no cover
            self.call_from_thread(self.notify, f"Analysis failed: {exc}", severity="error")
            return
        self.call_from_thread(self._render_firmware, report)

    def _render_firmware(self, report) -> None:
        md = [f"### {report.filename}", ""]
        md.append(f"- **SHA-256:** `{report.sha256}`")
        md.append(f"- **Archive type:** {report.archive_type}")
        md.append(f"- **Model / CSC / Build:** {report.model} / {report.csc} / {report.build}")
        md.append(f"- **Bootloader revision:** {report.bootloader_revision or '—'}  "
                  f"(date code {report.date_code or '—'})")
        md.append(f"- **Components:** {', '.join(report.components) or '—'}")
        if report.boot_image:
            bi = report.boot_image
            md.append(f"- **Boot image:** v{bi.get('header_version')} "
                      f"os={bi.get('os_version')} patch={bi.get('os_patch_level')}")
        if report.avb:
            md.append(f"- **AVB:** {report.avb.get('algorithm_name')} "
                      f"(signed={report.avb.get('signed')})")
        if report.entries:
            md.append(f"- **Entries:** {len(report.entries)}")
            md.append("")
            md.append("| Entry | Size | Component | Image | Comp |")
            md.append("|---|---|---|---|---|")
            for e in report.entries[:40]:
                md.append(f"| {e.name} | {e.size} | {e.component} | {e.image_kind} | {e.compressed} |")
        if report.warnings:
            md.append("")
            md.append("**Warnings:**")
            for w in report.warnings:
                md.append(f"- {w}")
        self.query_one("#firmware-result", Markdown).update("\n".join(md))
        self.notify("Firmware analysis complete.")

    # ---- CVE worker -------------------------------------------------------
    @work(thread=True, exclusive=True)
    def _search_cve(self, keyword: str) -> None:
        try:
            findings = self.core.search_and_classify(keyword, limit=20)
        except Exception as exc:
            self.call_from_thread(self.notify, f"NVD search failed: {exc}", severity="error")
            return
        self.call_from_thread(self._render_cve, findings)

    def _render_cve(self, findings) -> None:
        table = self.query_one("#cve-table", DataTable)
        table.clear()
        for f in findings:
            table.add_row(
                f.cve_id or "—",
                f.classification.label,
                f.confidence.value,
                f.summary[:80],
            )
        self.notify(f"Classified {len(findings)} advisory record(s).")

    # ---- serial -----------------------------------------------------------
    def _refresh_serial(self) -> None:
        interfaces = self.core.serial_interfaces()
        table = self.query_one("#serial-table", DataTable)
        table.clear()
        for s in interfaces:
            table.add_row(
                s.device,
                s.driver or "—",
                f"{s.usb_vid}:{s.usb_pid}" if s.usb_vid else "—",
                s.product or "—",
                "yes" if s.present else "no",
            )
        if not interfaces:
            self.notify("No /dev/ttyACM* or /dev/ttyUSB* interfaces found.", severity="information")
        else:
            self.notify(f"Found {len(interfaces)} serial interface(s).")

    @work(thread=True, exclusive=True)
    def _capture_serial(self, device: str) -> None:
        log.info("passive capture requested on %s", device)
        result = self.core.capture_serial(device)
        self.call_from_thread(self._render_capture, result)

    def _render_capture(self, result) -> None:
        widget = self.query_one("#serial-hex", RichLog)
        widget.clear()
        widget.write(f"Device: {result.device}  bytes: {result.bytes_captured}  "
                     f"method: {result.method}  {result.duration:.1f}s")
        for w in result.warnings:
            widget.write(f"! {w}")
        if result.error:
            widget.write(f"ERROR: {result.error}")
        if result.data:
            widget.write(hexdump(result.data[:2048]))
        else:
            widget.write("(no data captured — the interface may be idle or require a trigger)")
        self.notify(f"Capture done: {result.bytes_captured} bytes.")

    # ---- knox -------------------------------------------------------------
    def _refresh_knox(self) -> None:
        knox = self.core.knox
        md = ["## Observed restrictions → likely mechanisms", ""]
        md.append(f"> {knox.disclaimer}")
        md.append("")
        for item in self.core.knox_analysis():
            md.append(f"### {item['restriction'].replace('_', ' ').title()} — `{item['status']}`")
            if item.get("observed"):
                md.append(f"- **Observed:** {item['observed']}")
            for p in item.get("likely_policies", []):
                md.append(f"- **Likely policy:** {p}")
            if item.get("legitimate_control"):
                md.append(f"- **Legitimate control:** {item['legitimate_control']}")
            md.append(f"- **Exploit?** {'No — administrative control.' if item.get('not_an_exploit', True) else 'See findings.'}")
            md.append("")
        md.append("## Management technologies")
        md.append("")
        for tech in knox.technologies():
            md.append(f"### {tech['name']} — _{tech['category']}_")
            md.append(tech["summary"])
            md.append(f"- **Removal:** {tech['removal']}")
            md.append(f"- **Refs:** {', '.join(tech['references'])}")
            md.append("")
        og = knox.ownership_guidance()
        if og:
            md.append("## Owner-authorized restoration guidance")
            md.append(og.get("summary", ""))
            for opt in og.get("options", []):
                md.append(f"- {opt}")
            for c in og.get("cautions", []):
                md.append(f"- ⚠ {c}")
        self.query_one("#knox-md", Markdown).update("\n".join(md))

    # ---- findings ---------------------------------------------------------
    def _refresh_findings(self) -> None:
        findings = self.core.db.findings_for_session(self.core.session_id)
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for f in findings:
            table.add_row(f.title, f.classification.label, f.confidence.value, f.cve_id or "—")
        counts = {c.label: 0 for c in Classification}
        for f in findings:
            counts[f.classification.label] += 1
        summary = "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
        self.query_one("#findings-detail", Static).update(summary or "No findings yet.")

    # ---- report -----------------------------------------------------------
    @work(thread=True, exclusive=True)
    def _export_report(self) -> None:
        written = self.core.build_report()
        data = self.core.report_data()
        self.call_from_thread(self._render_report, written, data)

    def _render_report(self, written: dict[str, Path], data: dict) -> None:
        lines = ["[b]Reports written:[/]"]
        for fmt, path in written.items():
            lines.append(f"  {fmt}: {path}")
        self.query_one("#report-result", Static).update("\n".join(lines))
        from ..reporting import ReportBuilder

        builder = ReportBuilder(self.core.db, self.config.redact_identifiers)
        preview = builder.render_markdown(data)
        self.query_one("#report-preview", Markdown).update(preview[:6000])
        self.notify(f"Exported {len(written)} report file(s).")


def run(config: Config) -> None:
    WisebreakApp(config).run()
