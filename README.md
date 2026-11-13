# WISEBREAK

**A read-only, owner-authorized Android security *research* console for managed Samsung devices.**

WISEBREAK is a modular terminal application (Textual + Rich) for investigating
the security architecture of a device you own. It enumerates USB interfaces,
analyzes stock Samsung firmware offline, matches publicly documented
vulnerabilities, documents Knox / device-management architecture, passively
inspects exposed diagnostic interfaces, and produces rigorous, source-cited
reports.

It was built for investigating a **Wisephone II** (a managed Samsung Galaxy
A17 5G, `SM-A176U1`) from an **Arch Linux** host, but works with any Samsung
device.

---

## What WISEBREAK does — and does *not* — do

WISEBREAK is a **defensive / research** tool. It is deliberately conservative.

It **does**:

- Discover USB devices and enumerate their interfaces (MTP, RNDIS, CDC-ACM,
  ADB-when-present, Samsung Download Mode identifiers) from `sysfs`, with
  optional `pyudev`/`pyusb` enrichment.
- Analyze Samsung firmware archives **offline** (ZIP, TAR, `tar.md5`, LZ4),
  identify `AP/BL/CP/CSC/HOME_CSC` components and partition images, verify
  SHA-256, and inspect Android boot-image and AVB (`vbmeta`) headers.
- Match public advisories (NIST NVD, Android Security Bulletins, Samsung SMR,
  GitHub Security Advisories) and **classify** each finding with evidence and a
  **source URL**.
- Document how Knox Manage, Knox Mobile Enrollment, Knox Guard, Android Device
  Owner, Android Enterprise, Managed Google Play, and Samsung KPE enforce the
  restrictions you observe — and which *legitimate administrative* mechanisms
  control them.
- Passively capture bytes from `/dev/ttyACM*` (read-only) with hex
  visualization and export.
- Persist everything to a SQLite research workspace and generate
  Markdown/JSON/HTML reports with serial numbers redacted by default.

It **never**:

- Flashes firmware, factory-resets, or writes to a connected device.
- Unlocks a bootloader or sends undocumented/destructive serial commands.
- Bypasses, removes, or claims to bypass Knox / EMM management. Removing
  enterprise management is controlled by the **enrolling organization**, and
  WISEBREAK documents that administrative path rather than attacking it.
- Treats an exposed USB interface as an exploit, or a vulnerable version
  string as proof of exploitability.

Every finding is classified as **Confirmed vulnerable**, **Potentially
affected**, **Insufficient evidence**, **Patched**, or **Not applicable** —
and the code will not mark anything "confirmed vulnerable" from public metadata
alone.

---

## Install (Arch Linux)

```bash
# 1. System packages (recommended for the optional USB/serial backends)
sudo pacman -S --needed python python-pip usbutils

# 2. Get the project (explicit path, per convention)
mkdir -p /home/$USER/Downloads/wisebreak
cd /home/$USER/Downloads/wisebreak
# copy/clone the wisebreak/ project tree here

# 3. Create an isolated environment
python -m venv .venv
source .venv/bin/activate

# 4. Install. Use the 'full' extra for live USB + serial + LZ4 support.
pip install -e ".[full]"
```

Optional backends and the groups that provide them:

| Extra       | Packages                 | Enables                                  |
|-------------|--------------------------|------------------------------------------|
| `usb`       | `pyudev`, `pyusb`        | Hotplug monitoring, richer descriptors   |
| `serial`    | `pyserial`               | Robust passive serial capture            |
| `firmware`  | `lz4`                    | LZ4 peek of `boot.img.lz4` / `vbmeta.lz4`|
| `full`      | all of the above         | Everything                               |
| `dev`       | `pytest`, `ruff`, …      | Tests and linting                        |

WISEBREAK runs **without** any extra — subsystems that need a missing package
report themselves as unavailable instead of failing.

### Permissions for serial capture

Reading `/dev/ttyACM0` needs group membership. On Arch:

```bash
sudo usermod -aG uucp $USER   # log out/in afterwards
```

(No elevated privileges are needed for USB enumeration or firmware analysis.)

---

## Usage

Launch the TUI:

```bash
wisebreak
```

Development entry point (equivalent):

```bash
python -m wisebreak
```

### Keyboard shortcuts (TUI)

| Key      | Action              |
|----------|---------------------|
| `s`      | Scan USB            |
| `d`      | Diagnostics refresh |
| `k`      | Knox analysis       |
| `r`      | Export report       |
| `Ctrl+L` | Clear log           |
| `q`      | Quit                |

Use the tab bar (or mouse) to move between Dashboard, USB Explorer, Firmware,
Advisories, Knox, Diagnostics, Findings, Reports, Logs, and Config.

### Headless commands (scripting / CI)

```bash
wisebreak usb --json                     # enumerate USB devices
wisebreak firmware /path/to/SM-A176U1_firmware.zip
wisebreak cve "Samsung Knox" --limit 10  # NVD search + classification
wisebreak knox                           # restriction → mechanism analysis
wisebreak serial --json                  # list /dev/ttyACM* interfaces
wisebreak report --format markdown       # report for the latest session
```

---

## Configuration

Copy the sample config and edit it (it is plain, `nano`-friendly TOML):

```bash
mkdir -p ~/.config/wisebreak
cp config/wisebreak.toml ~/.config/wisebreak/wisebreak.toml
nano ~/.config/wisebreak/wisebreak.toml
```

Key settings: `data_dir`, `redact_identifiers`, `nvd_api_key` (optional, raises
NVD rate limits), serial `read_timeout`/`max_capture_bytes`, and report
`formats`. The data directory holds the SQLite workspace, the advisory cache,
captures, and generated reports.

---

## Project layout

```
wisebreak/
├── pyproject.toml
├── README.md
├── config/wisebreak.toml          # sample, nano-friendly config
├── reports/sample_report.md       # example output
├── src/wisebreak/
│   ├── cli.py  __main__.py  app entry points
│   ├── config.py  paths.py  logging_setup.py  models.py  core.py
│   ├── db/            SQLite workspace (schema.sql + database.py)
│   ├── usbscan/       USB discovery engine (sysfs + pyudev/pyusb)
│   ├── vuln/          NVD client + conservative CVE matcher
│   ├── knox/          Knox/EMM knowledge base + analyzer
│   ├── firmware/      offline firmware + boot-image/AVB analysis
│   ├── diagnostics/   passive /dev/ttyACM* inspector
│   ├── reporting/     Markdown/JSON/HTML report builder
│   ├── tui/           Textual UI (app.py + app.tcss)
│   └── data/          device_profile.toml, knox_kb.json
└── tests/             pytest suite
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Legal & ethics

Use WISEBREAK only on devices you own or are explicitly authorized to test.
It performs read-only research and does not provide any means to bypass device
management. If you wish to remove enterprise management from a device you own,
the documented path is to contact the organization that enrolled it; see the
Knox panel's "Owner-authorized restoration guidance".

## License

Apache-2.0.
