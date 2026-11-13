-- WISEBREAK research workspace schema (SQLite).
-- All timestamps are ISO-8601 UTC strings.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A research session groups together the scans/findings of one investigation.
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    notes       TEXT DEFAULT ''
);

-- Connected devices observed during scans.
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    vendor_id     TEXT NOT NULL,
    product_id    TEXT NOT NULL,
    manufacturer  TEXT DEFAULT '',
    product       TEXT DEFAULT '',
    serial        TEXT,            -- stored raw; redacted at report time
    kind          TEXT DEFAULT 'unknown',
    label         TEXT DEFAULT '',
    sys_path      TEXT DEFAULT '',
    details_json  TEXT DEFAULT '{}',
    observed_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_session ON devices(session_id);

-- Firmware packages analyzed offline.
CREATE TABLE IF NOT EXISTS firmware (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    filename      TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT,
    model         TEXT DEFAULT '',
    csc           TEXT DEFAULT '',
    build         TEXT DEFAULT '',
    bootloader    TEXT DEFAULT '',
    components    TEXT DEFAULT '',  -- comma list: AP,BL,CP,CSC,HOME_CSC
    metadata_json TEXT DEFAULT '{}',
    analyzed_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_firmware_session ON firmware(session_id);

-- Security advisories (NVD CVEs, bulletins) fetched/cached.
CREATE TABLE IF NOT EXISTS advisories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id         TEXT,
    source         TEXT NOT NULL,   -- NVD | AndroidBulletin | SamsungSMR | GHSA | manual
    title          TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    published       TEXT DEFAULT '',
    last_modified   TEXT DEFAULT '',
    cvss_version    TEXT DEFAULT '',
    cvss_score      REAL,
    cvss_severity   TEXT DEFAULT '',
    source_url      TEXT DEFAULT '',
    references_json TEXT DEFAULT '[]',
    verified        INTEGER DEFAULT 0,  -- 0 = unverified, 1 = source-confirmed
    fetched_at      TEXT NOT NULL,
    UNIQUE(cve_id, source)
);
CREATE INDEX IF NOT EXISTS idx_advisories_cve ON advisories(cve_id);

-- Findings: the analytical output, each tied to evidence and a classification.
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    title            TEXT NOT NULL,
    classification   TEXT NOT NULL,   -- see models.Classification
    confidence       TEXT NOT NULL,   -- low | medium | high
    summary          TEXT DEFAULT '',
    evidence_json    TEXT DEFAULT '[]',
    source_urls_json TEXT DEFAULT '[]',
    cve_id           TEXT,
    limitations      TEXT DEFAULT '',
    recommended_next TEXT DEFAULT '',
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(classification);

-- Free-form research notes.
CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Evidence blobs captured (e.g. serial captures), referenced by findings.
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,       -- serial_capture | usb_snapshot | firmware_meta
    label       TEXT DEFAULT '',
    path        TEXT DEFAULT '',     -- on-disk artifact, if any
    sha256      TEXT DEFAULT '',
    size_bytes  INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL
);
