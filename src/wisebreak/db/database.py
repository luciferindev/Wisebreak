"""SQLite persistence layer for the research workspace.

Thin, synchronous wrapper around :mod:`sqlite3`. All public methods are
safe to call from worker threads (the connection uses
``check_same_thread=False`` guarded by a lock), which suits Textual's
``run_worker`` thread pool.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .. import paths
from ..models import (
    Classification,
    Confidence,
    CveRecord,
    Finding,
    UsbDevice,
    utcnow,
)

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


class Database:
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        paths.ensure_dir(db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # ---- lifecycle --------------------------------------------------------
    def _init_schema(self) -> None:
        sql = SCHEMA_FILE.read_text(encoding="utf-8")
        with self._lock, self._conn:
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- sessions ---------------------------------------------------------
    def create_session(self, name: str) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO sessions(name, started_at) VALUES(?, ?)",
                (name, utcnow()),
            )
            return int(cur.lastrowid)

    def end_session(self, session_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE sessions SET ended_at=? WHERE id=?", (utcnow(), session_id)
            )

    def list_sessions(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute("SELECT * FROM sessions ORDER BY id DESC").fetchall()
            )

    def get_session(self, session_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()

    def set_session_notes(self, session_id: int, notes: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE sessions SET notes=? WHERE id=?", (notes, session_id)
            )

    # ---- devices ----------------------------------------------------------
    def add_device(self, session_id: int, dev: UsbDevice) -> int:
        details = {
            "bus": dev.bus,
            "address": dev.address,
            "speed": dev.speed,
            "manufacturer": dev.manufacturer,
            "interfaces": [
                {
                    "number": i.number,
                    "class": i.class_code,
                    "subclass": i.subclass_code,
                    "protocol": i.protocol,
                    "driver": i.driver,
                    "description": i.description,
                }
                for i in dev.interfaces
            ],
        }
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO devices(session_id, vendor_id, product_id, manufacturer,
                        product, serial, kind, label, sys_path, details_json, observed_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    dev.vendor_id,
                    dev.product_id,
                    dev.manufacturer,
                    dev.product,
                    dev.serial,
                    dev.kind,
                    dev.label,
                    dev.sys_path,
                    json.dumps(details),
                    dev.observed_at,
                ),
            )
            return int(cur.lastrowid)

    def devices_for_session(self, session_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM devices WHERE session_id=? ORDER BY id", (session_id,)
                ).fetchall()
            )

    # ---- firmware ---------------------------------------------------------
    def add_firmware(self, session_id: int, meta: dict[str, Any]) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO firmware(session_id, path, filename, size_bytes, sha256,
                        model, csc, build, bootloader, components, metadata_json, analyzed_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    meta.get("path", ""),
                    meta.get("filename", ""),
                    int(meta.get("size_bytes", 0)),
                    meta.get("sha256"),
                    meta.get("model", ""),
                    meta.get("csc", ""),
                    meta.get("build", ""),
                    meta.get("bootloader", ""),
                    ",".join(meta.get("components", [])),
                    json.dumps(meta.get("metadata", {})),
                    utcnow(),
                ),
            )
            return int(cur.lastrowid)

    def firmware_for_session(self, session_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM firmware WHERE session_id=? ORDER BY id", (session_id,)
                ).fetchall()
            )

    # ---- advisories -------------------------------------------------------
    def upsert_advisory(
        self, cve: CveRecord, source: str = "NVD", verified: bool = True
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO advisories(cve_id, source, title, description, published,
                        last_modified, cvss_version, cvss_score, cvss_severity, source_url,
                        references_json, verified, fetched_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id, source) DO UPDATE SET
                        description=excluded.description,
                        last_modified=excluded.last_modified,
                        cvss_version=excluded.cvss_version,
                        cvss_score=excluded.cvss_score,
                        cvss_severity=excluded.cvss_severity,
                        source_url=excluded.source_url,
                        references_json=excluded.references_json,
                        verified=excluded.verified,
                        fetched_at=excluded.fetched_at""",
                (
                    cve.cve_id,
                    source,
                    cve.cve_id,
                    cve.description,
                    cve.published,
                    cve.last_modified,
                    cve.cvss_version,
                    cve.cvss_score,
                    cve.cvss_severity,
                    cve.source_url,
                    json.dumps(cve.references),
                    1 if verified else 0,
                    utcnow(),
                ),
            )

    def search_advisories(self, text: str = "", limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            if text:
                like = f"%{text}%"
                return list(
                    self._conn.execute(
                        """SELECT * FROM advisories
                           WHERE cve_id LIKE ? OR description LIKE ?
                           ORDER BY cvss_score DESC NULLS LAST LIMIT ?""",
                        (like, like, limit),
                    ).fetchall()
                )
            return list(
                self._conn.execute(
                    "SELECT * FROM advisories ORDER BY fetched_at DESC LIMIT ?", (limit,)
                ).fetchall()
            )

    # ---- findings ---------------------------------------------------------
    def add_finding(self, session_id: int, finding: Finding) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO findings(session_id, title, classification, confidence,
                        summary, evidence_json, source_urls_json, cve_id, limitations,
                        recommended_next, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    finding.title,
                    finding.classification.value,
                    finding.confidence.value,
                    finding.summary,
                    json.dumps(finding.evidence),
                    json.dumps(finding.source_urls),
                    finding.cve_id,
                    finding.limitations,
                    finding.recommended_next,
                    finding.created_at,
                ),
            )
            return int(cur.lastrowid)

    def findings_for_session(self, session_id: int) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY id", (session_id,)
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            title=row["title"],
            classification=Classification(row["classification"]),
            confidence=Confidence(row["confidence"]),
            summary=row["summary"],
            evidence=json.loads(row["evidence_json"]),
            source_urls=json.loads(row["source_urls_json"]),
            cve_id=row["cve_id"],
            limitations=row["limitations"],
            recommended_next=row["recommended_next"],
            created_at=row["created_at"],
        )

    # ---- notes & evidence -------------------------------------------------
    def add_note(self, session_id: int, body: str) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO notes(session_id, body, created_at) VALUES(?,?,?)",
                (session_id, body, utcnow()),
            )
            return int(cur.lastrowid)

    def notes_for_session(self, session_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM notes WHERE session_id=? ORDER BY id", (session_id,)
                ).fetchall()
            )

    def add_evidence(
        self,
        session_id: int,
        kind: str,
        label: str = "",
        path: str = "",
        sha256: str = "",
        size_bytes: int = 0,
    ) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO evidence(session_id, kind, label, path, sha256, size_bytes, created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (session_id, kind, label, path, sha256, size_bytes, utcnow()),
            )
            return int(cur.lastrowid)

    def evidence_for_session(self, session_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT * FROM evidence WHERE session_id=? ORDER BY id", (session_id,)
                ).fetchall()
            )

    # ---- comparison -------------------------------------------------------
    def compare_sessions(self, a: int, b: int) -> dict[str, Any]:
        """Compare findings/devices between two sessions."""

        def finding_keys(sid: int) -> set[tuple[str, str]]:
            return {(f.title, f.classification.value) for f in self.findings_for_session(sid)}

        def device_keys(sid: int) -> set[str]:
            return {
                f"{r['vendor_id']}:{r['product_id']}" for r in self.devices_for_session(sid)
            }

        fa, fb = finding_keys(a), finding_keys(b)
        da, db = device_keys(a), device_keys(b)
        return {
            "session_a": a,
            "session_b": b,
            "findings_only_in_a": sorted(fa - fb),
            "findings_only_in_b": sorted(fb - fa),
            "findings_common": sorted(fa & fb),
            "devices_only_in_a": sorted(da - db),
            "devices_only_in_b": sorted(db - da),
            "devices_common": sorted(da & db),
        }

    # ---- generic ----------------------------------------------------------
    def counts(self, session_id: int) -> dict[str, int]:
        with self._lock:
            def one(sql: str) -> int:
                return int(self._conn.execute(sql, (session_id,)).fetchone()[0])

            return {
                "devices": one("SELECT COUNT(*) FROM devices WHERE session_id=?"),
                "firmware": one("SELECT COUNT(*) FROM firmware WHERE session_id=?"),
                "findings": one("SELECT COUNT(*) FROM findings WHERE session_id=?"),
                "notes": one("SELECT COUNT(*) FROM notes WHERE session_id=?"),
                "evidence": one("SELECT COUNT(*) FROM evidence WHERE session_id=?"),
            }

    def executescript_values(self, rows: Iterable[tuple[str, str]]) -> None:  # pragma: no cover
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", list(rows)
            )
