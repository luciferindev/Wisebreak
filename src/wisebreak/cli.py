"""Command-line entry point for WISEBREAK.

Default (no subcommand) launches the TUI. Headless subcommands are provided
for scripting, CI, and quick checks without a terminal UI.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__, config as config_mod
from .logging_setup import setup


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wisebreak",
        description="Owner-authorized, read-only Android security research toolkit.",
    )
    p.add_argument("--version", action="version", version=f"wisebreak {__version__}")
    p.add_argument("--config", type=Path, help="Path to a wisebreak.toml config file.")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("tui", help="Launch the terminal UI (default).")

    s_usb = sub.add_parser("usb", help="Enumerate connected USB devices and exit.")
    s_usb.add_argument("--json", action="store_true", help="Emit JSON.")

    s_fw = sub.add_parser("firmware", help="Analyze a firmware archive offline.")
    s_fw.add_argument("path", type=Path, help="Firmware .zip / .tar / .tar.md5")
    s_fw.add_argument("--json", action="store_true", help="Emit JSON.")
    s_fw.add_argument("--no-hash", action="store_true", help="Skip SHA-256 (faster).")

    s_cve = sub.add_parser("cve", help="Search NVD and classify results vs the device.")
    s_cve.add_argument("keyword", help="Search keyword, e.g. 'Samsung Knox'.")
    s_cve.add_argument("--limit", type=int, default=10)
    s_cve.add_argument("--json", action="store_true")

    sub.add_parser("knox", help="Print the Knox restriction analysis and exit.")

    s_serial = sub.add_parser("serial", help="List diagnostic serial interfaces.")
    s_serial.add_argument("--json", action="store_true")

    s_rep = sub.add_parser("report", help="Generate a report for the latest session.")
    s_rep.add_argument("--session", type=int, help="Session id (default: latest).")
    s_rep.add_argument(
        "--format",
        action="append",
        choices=["markdown", "json", "html"],
        help="Repeatable. Defaults to config formats.",
    )

    return p


def _load_config(args: argparse.Namespace) -> config_mod.Config:
    cfg = config_mod.load(args.config)
    cfg.ensure_dirs()
    level = logging.DEBUG if args.verbose else logging.INFO
    setup(log_file=cfg.data_dir / "wisebreak.log", level=level)
    return cfg


def _cmd_usb(cfg, args) -> int:
    from .core import Core

    core = Core(cfg)
    try:
        devices = core.scan_usb(persist=False)
        if args.json:
            print(json.dumps([_usb_to_dict(d) for d in devices], indent=2))
        else:
            if not devices:
                print("No USB devices found (is /sys/bus/usb present?).")
            for d in devices:
                print(f"{d.vid_pid}  {d.kind:<12} {d.label:<28} {d.manufacturer} {d.product}")
                for i in d.interfaces:
                    print(f"    iface {i.number}: {i.description} "
                          f"(0x{i.class_code:02x}/{i.subclass_code:02x}/{i.protocol:02x}) "
                          f"driver={i.driver or '—'}")
        return 0
    finally:
        core.close()


def _usb_to_dict(d) -> dict:
    return {
        "vid_pid": d.vid_pid,
        "kind": d.kind,
        "label": d.label,
        "manufacturer": d.manufacturer,
        "product": d.product,
        "interfaces": [
            {
                "number": i.number,
                "class": i.class_code,
                "subclass": i.subclass_code,
                "protocol": i.protocol,
                "driver": i.driver,
                "description": i.description,
            }
            for i in d.interfaces
        ],
    }


def _cmd_firmware(cfg, args) -> int:
    from .core import Core

    core = Core(cfg)
    try:
        report = core.firmware.analyze(args.path, compute_hash=not args.no_hash)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"File:        {report.filename}")
            print(f"Size:        {report.size_bytes} bytes")
            print(f"SHA-256:     {report.sha256 or '(skipped)'}")
            print(f"Archive:     {report.archive_type}")
            print(f"Model/CSC:   {report.model} / {report.csc}")
            print(f"Build:       {report.build}")
            print(f"Bootloader:  rev {report.bootloader_revision or '—'} "
                  f"(date {report.date_code or '—'})")
            print(f"Components:  {', '.join(report.components) or '—'}")
            if report.boot_image:
                print(f"Boot image:  {report.boot_image}")
            if report.avb:
                print(f"AVB:         {report.avb}")
            print(f"Entries:     {len(report.entries)}")
            for w in report.warnings:
                print(f"  ! {w}")
        return 0
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    finally:
        core.close()


def _cmd_cve(cfg, args) -> int:
    from .core import Core
    from .vuln import NvdError

    core = Core(cfg)
    try:
        try:
            findings = core.search_and_classify(args.keyword, limit=args.limit, persist=True)
        except NvdError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            for f in findings:
                print(f"{f.cve_id}: {f.classification.label} ({f.confidence.value})")
                print(f"    {f.summary[:100]}")
                for u in f.source_urls[:1]:
                    print(f"    source: {u}")
        return 0
    finally:
        core.close()


def _cmd_knox(cfg, args) -> int:
    from .core import Core

    core = Core(cfg)
    try:
        print(core.knox.disclaimer)
        print()
        for item in core.knox_analysis():
            print(f"[{item['status']}] {item['restriction']}")
            print(f"    observed: {item.get('observed', '')}")
            for p in item.get("likely_policies", []):
                print(f"    policy:   {p}")
            print(f"    control:  {item.get('legitimate_control', '')}")
            print()
        return 0
    finally:
        core.close()


def _cmd_serial(cfg, args) -> int:
    from .core import Core

    core = Core(cfg)
    try:
        interfaces = core.serial_interfaces()
        if args.json:
            print(json.dumps([s.to_dict() for s in interfaces], indent=2))
        else:
            if not interfaces:
                print("No serial interfaces (/dev/ttyACM*, /dev/ttyUSB*) present.")
            for s in interfaces:
                print(f"{s.device}  driver={s.driver or '—'}  "
                      f"{s.usb_vid}:{s.usb_pid}  {s.product}")
        return 0
    finally:
        core.close()


def _cmd_report(cfg, args) -> int:
    from .core import Core

    core = Core(cfg)
    try:
        sessions = core.db.list_sessions()
        if not sessions:
            print("No sessions in the workspace yet. Run a scan first.", file=sys.stderr)
            return 4
        sid = args.session or sessions[0]["id"]
        core.use_session(sid)
        written = core.build_report(formats=args.format)
        for fmt, path in written.items():
            print(f"{fmt}: {path}")
        return 0
    finally:
        core.close()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = _load_config(args)

    command = args.command or "tui"
    if command == "tui":
        from .tui import run as run_tui

        try:
            run_tui(cfg)
        except KeyboardInterrupt:  # pragma: no cover
            pass
        return 0

    dispatch = {
        "usb": _cmd_usb,
        "firmware": _cmd_firmware,
        "cve": _cmd_cve,
        "knox": _cmd_knox,
        "serial": _cmd_serial,
        "report": _cmd_report,
    }
    return dispatch[command](cfg, args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
