# CIPHER — Autonomous Post-Quantum Cryptographic Vulnerability Detection System

CIPHER analyzes IoT network traffic for cryptographic configurations and
protocols that may be vulnerable in a post-quantum security context. It
combines a deterministic rule-based risk engine with an optional statistical
anomaly detector, then reports and (in software) acts on the result.

Implemented capabilities:

- Deterministic **Quantum Risk Score (QRS)** — a rule-based 0–10 cryptographic
  risk score
- **TLS / RSA / protocol fingerprinting** from raw captured traffic (no
  PyShark; parsing is Scapy + hand-rolled TLS record/handshake parsing)
- **Shannon entropy** analysis of packet payloads
- Optional **Isolation Forest** anomaly detection, fused with QRS
- **Risk fusion** — Isolation Forest may escalate a device's reported category
  by one level; it never independently decides isolation
- **High-risk enforcement decision logic**, with a `NoOp` backend on Windows
  (decisions are recorded, never physically enforced yet)
- **ML-DSA-44 (FIPS 204)** signed, 3-page PDF security reports
- A frozen **REST API** and an **integrated React dashboard**, served from one
  Flask process
- A **controlled evaluation harness** with measured, reproducible results

CIPHER does **not** currently perform real Raspberry Pi / Linux firewall
enforcement — see [Enforcement](#enforcement) and
[Raspberry Pi Deployment Status](#raspberry-pi-deployment-status).

## Current Status

| | |
|---|---|
| Software implementation | Complete |
| Current verified deployment | Windows 11, offline `.pcap` analysis |
| Raspberry Pi integration | Next stage (not yet started) |
| Python baseline | 3.12 |
| Test suite | **605 passing** (`pytest -q`) |

Raspberry Pi hardware integration — live packet capture, monitor-mode Wi-Fi,
the SSD1306 OLED, GPIO status LEDs, and real Linux `iptables` isolation — is
not yet implemented. Everything above runs and is tested on Windows today
against offline `.pcap` input.

## Architecture

```
Capture (offline .pcap)
    -> Protocol/TLS Fingerprinting + Shannon Entropy
    -> Device Features
    -> Quantum Risk Score (QRS)  +  optional Isolation Forest
    -> Risk Fusion
    -> DeviceAssessment
    -> Enforcement Decision (should_isolate)
    -> Signed PDF Report  /  REST API  /  React Dashboard
```

Each stage is an independent, unit-tested module (`entropy/`, `fingerprint/`,
`risk/`, `ml/`, `fusion/`, `enforcement/`, `signing/`, `reports/`) composed by
`pipeline/runner.py`. No stage imports ahead of itself in this chain, and the
per-packet path never touches the disk, the REST layer, or PDF generation.

## Quantum Risk Score (QRS)

QRS is CIPHER's primary, deterministic, explainable risk engine — a rule-based
score from 0–10 combining TLS version, RSA key size, forward secrecy, payload
entropy, and protocol/port exposure (`risk/scoring.py`).

| Score | Category |
|---|---|
| 0–2 | LOW |
| 3–6 | MEDIUM |
| 7–10 | HIGH |

**Isolation eligibility is `raw QRS >= 7`** (`enforcement/decision.py`) — the
raw score, not the fused category. Isolation Forest may raise a device's
*reported* `final_category` by one level (e.g. MEDIUM → HIGH) when it flags an
anomaly, but that escalation alone can never make an otherwise-ineligible
device isolation-eligible: a ML-only signal never triggers a high-consequence
enforcement action the deterministic QRS score doesn't itself support.

## Isolation Forest (Optional)

Isolation Forest anomaly detection is optional and secondary to QRS. If a
trained model exists at:

```
ml/artifacts/anomaly_detector.joblib
```

it is loaded once at startup and used to flag statistical outliers. **No
trained model is committed to this repository** (`ml/artifacts/` is empty by
default) — with no model present, CIPHER continues in **QRS-only mode**;
anomaly detection is simply unavailable, and QRS risk scoring is entirely
unaffected. Any anomaly-detection output reflects this project's own
synthetically-trained model only, never a research-grade or real-world
accuracy claim.

## Enforcement

Current (Windows) behavior, exactly as implemented:

```
raw QRS >= 7
    -> isolation decision requested (should_isolate() == True)
    -> NoOpIsolationBackend.isolate(...)
    -> IsolationOutcome(requested=True, enforced=False)
```

`NoOpIsolationBackend` deliberately records the decision (with a logged
`WARNING`) and does **not** modify the Windows Firewall or any network state.
A HIGH-risk device is flagged, reported, and logged — **it is not currently
physically blocked**. Real Raspberry Pi / Linux `iptables` enforcement is
deferred to hardware integration, in part because the source specification
doesn't define enough of the firewall policy (chain, rule direction,
`DROP` vs. `REJECT`, restoration semantics) to implement responsibly yet.

## PDF Security Reports

Each flagged device gets a professional, 3-page, ML-DSA-44-signed PDF report
(`reports/pdf_generator.py`) containing:

- Device information and assessment timestamps
- QRS score and risk category
- Findings and remediation guidance
- Applicable NIST guidance references
- Anomaly status (if Isolation Forest ran)
- A SHA-256 integrity hash of the report's canonical content
- The ML-DSA-44 digital signature and its verification status

**LOW-category devices are not report-eligible.** A report is generated only
for a device whose final category is MEDIUM or HIGH
(`is_flagged_device()` — `final_category != LOW`).

## Web Application

CIPHER is self-contained: the compiled React production build lives in this
repository, under:

```
web/
```

`run_demo.py` serves both the React UI and the `/api/*` REST API from a
single Flask process, on one origin. **Running CIPHER requires none of:**
Node.js, npm, Vite, the separate `cipher-frontend` repository, or a second
terminal.

React **source** is maintained separately, in the `cipher-frontend` repository
— only the compiled production artifact (`web/`) is committed here. See
`docs/SDD.md`'s Phase 15 addenda for the release-artifact boundary and the
update procedure for when the frontend changes.

## Quick Start (Windows)

```
git clone https://github.com/chandini-narayana/cipher-pqc.git
cd cipher-pqc
python -m venv .venv
```

Activate the environment (PowerShell):

```
.\.venv\Scripts\Activate.ps1
```

Install and run:

```
python -m pip install --upgrade pip
pip install -r requirements.txt
python preflight.py
python run_demo.py
```

Dashboard: **http://127.0.0.1:5000**

`preflight.py` checks every runtime precondition (web build, demo fixture,
signing keys, port availability, ML model presence) before you start CIPHER —
run it any time to confirm the environment is ready.

## Windows Presentation Launcher

```
Start CIPHER.bat
```

Double-click to launch CIPHER end to end. It:

- Resolves the project directory and selects a project virtual environment
  (`.venv/` or `venv/`) if one exists, otherwise the system `python`
- Runs the same preflight check as `python preflight.py`
- Starts CIPHER (`run_demo.py`)
- Waits for a real `HTTP 200` from `/api/health`
- Opens your default browser only once the server is actually ready

Press **Ctrl+C** in the console window to stop. See
[`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the full presentation walkthrough
and troubleshooting table.

## Entry Points

| Command | Behavior |
|---|---|
| `python main.py` | Offline batch processing: one capture pass, then exits. No server. |
| `python run_api.py` | API-only development server (REST API, no web UI). |
| `python run_demo.py` | Integrated, self-contained application: React UI + REST API from one process. |

`main.py` and `run_api.py` are unaffected by `run_demo.py`'s presentation
behavior (its default demo fixture, web UI serving, etc.) — all three remain
independent composition roots.

## REST API

| Method & Path | Description |
|---|---|
| `GET /api/health` | Service status and summary counts |
| `GET /api/devices` | List of assessed devices |
| `GET /api/devices/<ip>` | Full detail for one device |
| `GET /api/devices/<ip>/report` | Report metadata for one device |
| `GET /api/devices/<ip>/report/download` | The signed PDF report itself |

## Capture Modes

| Mode | Status |
|---|---|
| `offline` (default) | Implemented and verified — deterministic replay from a `.pcap` file |
| `live` | Interface/scaffold exists (`capture/live_source.py`); real NIC/live capture is **not implemented** — it raises immediately and clearly rather than doing nothing silently |
| `mock` | Reserved; current code exits gracefully with no runtime pipeline (no mock data source is implemented yet) |

## Controlled Evaluation

```
python evaluate_demo.py
```

Runs five core controlled scenarios through the real, unmodified CIPHER
pipeline:

1. Secure modern TLS (TLS 1.3)
2. Legacy TLS (TLS 1.0)
3. Weak RSA key size
4. Plaintext protocol exposure (HTTP)
5. High-risk enforcement (Telnet)

MQTT protocol detection is reported separately, as **additional validation**
closing a fixture-coverage gap — it is never counted toward the five-scenario
result.

Latest measured result on this development machine:

| Target | Measured | Result |
|---|---|---|
| Five controlled scenarios | 5/5 | PASS |
| Controlled false-positive rate (< 10%) | 0.00% | PASS |
| Assessment latency (< 500 ms) | ~0.03 ms mean | PASS |
| TLS 1.0 → QRS (7–9) | 7 | PASS |
| TLS 1.3 → QRS (0–2) | 2 | PASS |
| Encrypted payload entropy (> 7.5) | 7.63 | PASS |
| Plaintext HTTP entropy (< 5.0) | 4.72 | PASS |
| Tamper detection (100%) | 100% | PASS |

These are **controlled, synthetic, offline evaluation results** on fixtures
this project built for itself — they are **not** a real-world network
validation, and the timing figures are Windows-only measurements, not
Raspberry Pi timing (unmeasured until Pi hardware is available).

## Testing

```
pytest -q
```

Current verified result: **605 passed**.

Focused suites:

```
pytest tests/ml/ -v
pytest tests/pipeline/ -v
pytest tests/reports/ -v
pytest tests/dashboard/ -v
pytest tests/enforcement/ -v
```

## Project Structure

```
cipher-pqc/
├── capture/         # Packet capture sources (offline .pcap; live is a scaffold)
├── entropy/         # Shannon entropy calculation
├── fingerprint/     # Protocol / TLS / RSA fingerprinting
├── risk/            # Quantum Risk Score (QRS) engine
├── ml/              # Isolation Forest anomaly detection (optional)
├── fusion/          # QRS + anomaly risk fusion
├── enforcement/      # Isolation eligibility decision + NoOp backend
├── signing/         # ML-DSA-44 (FIPS 204) signing and verification
├── reports/         # Signed PDF report generation
├── pipeline/        # Runtime orchestration (run_capture)
├── dashboard/       # Flask REST API + static/SPA serving
├── models/          # Domain dataclasses
├── config/          # Settings and constants
├── utils/           # Logging setup, shared exceptions
├── web/             # Compiled React production build (served by Flask)
├── tests/           # Test suite (605 passing) and controlled fixtures
├── docs/            # SDD.md, DEMO_GUIDE.md
├── main.py            # Offline batch entry point
├── run_api.py          # API-only development server
├── run_demo.py         # Integrated self-contained application
├── preflight.py        # Pre-start environment/asset check
├── launch_cipher.py     # Presentation launcher (used by Start CIPHER.bat)
├── evaluate_demo.py     # Controlled evaluation harness
├── measure_startup.py   # Startup-time measurement
└── Start CIPHER.bat     # Windows double-click launcher
```

## Raspberry Pi Deployment Status

Target hardware: **Raspberry Pi 4 Model B, 4GB**.

A pre-Pi software efficiency audit and dependency-baseline freeze are
complete (see `docs/SDD.md`'s Pre-Pi addenda) — the Isolation Forest inference
path was optimized, and `requirements.txt` is now pinned to an
independently re-validated, from-scratch-installable Windows baseline.

Not yet started or implemented:

- ARM64 dependency validation (wheel availability, build-from-source risk)
- Raspberry Pi CPU/RAM measurement (all current timing is Windows-only)
- Live packet capture
- Monitor-mode Wi-Fi adapter integration
- SSD1306 I2C OLED display
- GPIO status LEDs
- Real Linux `iptables` isolation enforcement
- Sustained (72-hour) operation validation

## Current Limitations

- No real live network interface capture (offline `.pcap` only)
- No Raspberry Pi GPIO, OLED, or physical LED integration
- No real `iptables` (or any) physical network isolation — enforcement is
  decided and logged only (`NoOpIsolationBackend`)
- No 72-hour sustained-operation validation performed yet
- No real-world (non-synthetic) network false-positive validation
- No production-grade secret-key protection — signing keys are plain files
  with no passphrase encryption or OS keyring integration
- No trained Isolation Forest model is committed; anomaly detection is
  QRS-only unless one is trained and placed manually

## Project Scope

CIPHER is an **academic/research prototype**. It is not a production firewall,
a commercial security appliance, a certified IDS/IPS, or a production-grade
PKI scanner.

## Documentation

- [`docs/SDD.md`](docs/SDD.md) — full software design document and phase-by-phase addenda
- [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) — presentation-day quick reference
