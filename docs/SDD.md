# CIPHER — Software Design Document (Phase 1)

**Status:** APPROVED — four changes incorporated below. This document now reflects the architecture that Step 2 (folder scaffolding, this same turn) and all subsequent module-by-module steps are built against.

**Scope of this document:** Phase 1 only — a Windows-executable, hardware-free version of CIPHER. Raspberry Pi, GPIO, OLED, iptables isolation, and systemd are out of scope for implementation and documentation here. Where a Phase 1 decision was shaped by the fact that Phase 2 will extend this codebase, that reasoning is noted briefly and only to the depth needed to justify the Phase 1 choice — not as Phase 2 design.

---

## 1. Project Overview

CIPHER detects post-quantum-cryptographic vulnerabilities in IoT network traffic: packet inspection, TLS/RSA fingerprinting, Shannon entropy, a per-device Quantum Risk Score, ML-based risk classification, Dilithium2-signed tamper-evident logging, a live dashboard, and per-device PDF remediation reports.

**Phase 1** delivers this entire stack running on Windows 11, with two capture modes behind one interface:

- **Offline `.pcap` replay** — fully implemented in Phase 1. Deterministic, needs no privileges, is the backbone of the test suite.
- **Live capture** — the interface exists and is wired into the factory, but the implementation is a **documented scaffold** in Phase 1 (see Section 4, `capture/live_source.py`). It is not a Phase 2 concern being smuggled in — live capture on a normal NIC is a Windows-executable feature — it is simply not built out yet, to keep Phase 1's actual working, tested surface area to what's needed now.

**Hard constraint carried through every section:** Phase 2 (Raspberry Pi + GPIO + OLED + physical isolation + systemd) must attach through a single narrow seam, without editing any module below. Section 15 defines that seam.

---

## 2. Overall Software Architecture

Five processing layers plus cross-cutting concerns, now with two additions from the approved changes:

| Layer | Package(s) | Responsibility |
|---|---|---|
| 0 — Domain | `models/` | Shared dataclasses and enums — the vocabulary every other layer speaks |
| 1 — Ingestion | `capture/` | Abstracts *where packets come from* (file, fully implemented; NIC, scaffolded) |
| 2 — Analysis | `entropy/`, `fingerprint/` | Pure, stateless functions on packet data |
| 3 — Intelligence | `risk/`, `ml/` | Score, category, remediation — with a rule-based fallback when no model is trained |
| 4 — Assurance | `signing/` | Tamper-evidence for every detection event |
| 5 — Presentation | `dashboard/`, `reports/` | Live web view and on-demand PDF |
| Orchestration | `pipeline/` | The actual per-packet sequence — kept out of `main.py` |
| Cross-cutting | `config/`, `utils/` | Settings, logging, exceptions, the shared in-memory registry |

### Approved Design Decisions

**D1 — Domain models live in a dedicated `models/` package**, not `utils/models.py`. This makes the dependency graph read cleanly: `models/` has zero outgoing dependencies and is the one package every other package is allowed to import from without it implying any behavioral coupling — `utils/` is now free to mean "logging, exceptions, and the registry" without also being an implicit models package.

**D2 — `capture/` fully implements `OfflinePcapSource` in Phase 1; `LiveCaptureSource` is a documented scaffold.** Both implement the same `CaptureSource` interface, so nothing downstream of capture (analysis, risk, ml, signing, reports, dashboard, pipeline) can tell which one is running, or ever needs to. `LiveCaptureSource.read_packets()` raises `NotImplementedError` with a message pointing at offline/mock mode — a deliberate, loud failure rather than a silent no-op, so a misconfigured `CAPTURE_MODE=live` in Phase 1 is caught immediately rather than producing a dashboard that quietly shows nothing. This keeps the option open (interface, factory wiring, and tests-for-the-interface all exist) without spending Phase 1 effort building and validating live-network handling that Phase 1's own scope doesn't require to be considered done.

**D3 — Orchestration lives in `pipeline/`, not `main.py`.** `pipeline.runner.Pipeline` owns the per-packet sequence (capture → entropy/fingerprint → risk → ml → sign → registry update), the background-thread lifecycle, and the per-packet fault isolation from Section 12. `main.py` becomes a pure composition root: it constructs each component from `Settings` and hands them to `Pipeline` and the Flask app factory — nothing else. Two benefits, one immediate and one forward-looking (noted briefly, not designed further): immediately, `Pipeline` becomes unit-testable end-to-end without `main.py` or Flask in the picture at all; and later, Phase 2's isolation/alerting behavior has one obvious extension point — a hook on `Pipeline` — rather than requiring changes scattered through a monolithic `main.py`.

**D4 (superseded — see Section 21) — ML fail-open.** The draft's original wording described a `MLClassifier` that derived `RiskCategory` directly from `risk_score` thresholds when no model was present; that class no longer exists. Current architecture: `risk/`'s Quantum Risk Score is the primary, always-on assessment — it never depends on ML being available. `ml/`'s `AnomalyDetector` (Isolation Forest) is a secondary, optional anomaly signal. When no trained model artifact is present, `ml.loading.load_anomaly_detector()` logs one warning and returns `None`; `fusion.fuse_assessments()` already defines `anomaly_assessment=None` → the QRS category passes through unchanged (Section 19). A missing model is never a startup failure.

---

## 3. Module Responsibilities

| # | Module | Responsibility | Depends on | Consumed by |
|---|---|---|---|---|
| 1 | `models/` | `Device`, `DetectionEvent`, `RiskEvent`, enums, validation | — | everything |
| 2 | `config/` | Settings, env loading, constants | — | everything |
| 3 | `utils/` | Logging setup, `CipherError` hierarchy, `DeviceRegistry` | `config/` | `pipeline/`, `dashboard/` |
| 4 | `capture/` | `PacketRecord`s from a `.pcap` file (implemented) or a live NIC (scaffolded) | `models/`, `config/` | `pipeline/` |
| 5 | `entropy/` | Shannon entropy of a payload | — | `pipeline/` |
| 6 | `fingerprint/` | TLS version, key size, cipher suite, protocol exposure | `models/` | `pipeline/` |
| 7 | `risk/` | Quantum Risk Score formula, NIST mapping, remediation text, score→category thresholds | `models/` | `ml/`, `pipeline/` |
| 8 | `ml/` | Dataset, features, training, prediction, persistence, rule-based fallback | `models/`, `risk/` | `pipeline/` |
| 9 | `signing/` | Dilithium2 keygen, sign/verify | `models/` | `pipeline/` |
| 10 | `reports/` | Per-device PDF | `models/`, `risk/` | `pipeline/`, `dashboard/` |
| 11 | `pipeline/` | The runtime sequence: wires 4–10 together, owns the background thread, fault isolation | 4–10, `utils/` (registry) | `main.py` |
| 12 | `dashboard/` | Flask app, REST API, HTML, mock-data mode | `models/`, `utils/` (registry) | end user |
| 13 | `main.py` | Composition root: build components, hand off to `pipeline/` and `dashboard/` | all of the above | — |

---

## 4. Folder Structure

```
cipher/
├── models/
│   ├── __init__.py
│   ├── device.py            # Device
│   ├── events.py              # DetectionEvent, RiskEvent
│   └── enums.py                # ProtocolType, RiskCategory, CaptureMode
│
├── capture/
│   ├── __init__.py
│   ├── base.py                # CaptureSource — abstract interface
│   ├── offline_source.py       # OfflinePcapSource — fully implemented
│   ├── live_source.py           # LiveCaptureSource — documented scaffold, raises NotImplementedError
│   └── factory.py                # get_capture_source(settings) -> CaptureSource
│
├── entropy/
│   ├── __init__.py
│   └── engine.py                  # shannon_entropy(data) -> float; compute_entropy_metrics(payload) -> EntropyMetrics
│
├── fingerprint/
│   ├── __init__.py
│   ├── tls.py                      # TLS version / key size / cipher suite
│   └── protocol.py                  # HTTP / MQTT / Telnet exposure flags
│
├── risk/
│   ├── __init__.py
│   ├── scoring.py                    # quantum_risk_score(...); score->category thresholds
│   ├── nist_mapping.py                 # finding -> NIST SP reference + remediation text
│   └── engine.py                        # RiskEngine — orchestrates scoring + mapping
│
├── ml/
│   ├── __init__.py
│   ├── dataset.py                        # sample/synthetic training data loader
│   ├── features.py                        # DetectionEvent -> feature vector
│   ├── train.py                            # CLI entry point: train + serialize
│   ├── classifier.py                        # MLClassifier — predict + rule-based fallback (D4)
│   └── artifacts/
│       └── .gitkeep
│
├── pipeline/
│   ├── __init__.py
│   └── runner.py                            # Pipeline — the runtime sequence (D3)
│
├── dashboard/
│   ├── __init__.py
│   ├── app.py                                # Flask app factory
│   ├── routes.py                              # /api/devices, /api/devices/<ip>/report
│   ├── mock_data.py                            # canned records for CAPTURE_MODE=mock
│   ├── static/
│   │   └── .gitkeep
│   └── templates/
│       └── .gitkeep
│
├── signing/
│   ├── __init__.py
│   └── dilithium_signer.py                     # sign_event / verify_event
│
├── reports/
│   ├── __init__.py
│   └── pdf_generator.py                         # generate(risk_event) -> Path
│
├── config/
│   ├── __init__.py
│   ├── settings.py                               # Settings dataclass + env/.env loading
│   └── constants.py                               # thresholds, NIST doc IDs, default paths
│
├── utils/
│   ├── __init__.py
│   ├── registry.py                                 # DeviceRegistry — thread-safe in-memory store
│   ├── logging_setup.py
│   └── exceptions.py                                 # CipherError hierarchy
│
├── tests/
│   ├── __init__.py
│   ├── models/
│   ├── capture/
│   ├── entropy/
│   ├── fingerprint/
│   ├── risk/
│   ├── ml/
│   ├── pipeline/
│   ├── dashboard/
│   ├── signing/
│   ├── reports/
│   └── fixtures/
│       └── .gitkeep
│
├── docs/
│   └── SDD.md
│
├── data/
│   └── .gitkeep
├── logs/
│   └── .gitkeep
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 5. Data Flow

```
   [.pcap file]  (Phase 1: implemented)      [live NIC]  (Phase 1: scaffold only)
          │                                         │
          └───────────────┬─────────────────────────┘
                           ▼
                CaptureSource.read_packets()
                  yields PacketRecord
                           │
             ┌─────────────┴──────────────┐
             ▼                             ▼
      shannon_entropy()      fingerprint_packet()
             │                             │
             └─────────────┬───────────────┘
                            ▼
                    DetectionEvent (models/)
                            │
                            ▼
                  evaluate_risk(features, port_risk)
               → risk_score + remediation text
                            │
                            ▼
                MLClassifier.predict(features)
       (falls back to score-derived category if no model — D4)
                            │
                            ▼
                     RiskEvent (models/)
                            │
             ┌──────────────┼───────────────┐
             ▼               ▼               ▼
     DilithiumSigner   DeviceRegistry    ReportGenerator
     .sign(event)       (utils/)          (on demand,
       → signed log          │             not in this loop)
                              ▼
                     Dashboard (Flask)
                     reads registry only
```

All of the above, from `CaptureSource.read_packets()` through the `DeviceRegistry` update, is owned by `pipeline.runner.Pipeline` — not scattered across `main.py`.

---

## 6. Runtime Sequence

**`main.py` (composition root — this is now the entirety of its job):**
1. Load `Settings`.
2. Configure logging.
3. Build: `CaptureSource` (via `capture.factory`), `RiskEngine`, `MLClassifier` (loads model or logs the D4 fallback warning), `DilithiumSigner`, `ReportGenerator`, `DeviceRegistry`.
4. Construct `Pipeline(capture_source, risk_engine, ml_classifier, signer, registry)` and call `pipeline.start()` — this spawns the background thread.
5. Build the Flask app via `dashboard.app.create_app(registry, settings)` and call `app.run(...)` on the main thread.

**`pipeline.runner.Pipeline` (owns everything that used to be described as "main.py's per-packet loop" in the draft):**
- `start()` spawns a background thread running `_loop()`.
- `_loop()` iterates `capture_source.read_packets()`; for each packet, calls `_process_packet()` inside a `try/except CipherError` (plus a broad `except Exception` logged at `ERROR`) so one bad packet never kills the thread.
- `_process_packet()` runs entropy → fingerprint → build `DetectionEvent` → `risk_engine.evaluate()` → `ml_classifier.predict()` → build `RiskEvent` → `signer.sign_event()` → append to the day's signed log under `data/` → `registry.update()`.
- If `CAPTURE_MODE=live` and `LiveCaptureSource` raises its documented `NotImplementedError`, `Pipeline.start()` catches this once at startup, logs a clear error naming the unimplemented mode, and exits cleanly rather than spinning up a broken background thread — this is deliberately a startup-time failure, not a silent no-op discovered later via an empty dashboard.

**Dashboard request handling (independent, main thread):**
- `/api/devices` reads `registry.snapshot()`.
- `/api/devices/<ip>/report` calls `ReportGenerator.generate()` on demand.
- `CAPTURE_MODE=mock` routes read `dashboard/mock_data.py` instead — no dependency on `Pipeline` ever running.

**Offline mode:** `Pipeline` processes the entire `.pcap` file once, populates the registry, then the background thread exits naturally — a deterministic final state, well suited to tests and to demoing without a live network.

---

## 7. Dependency Graph

```
                          models/
                             ▲
        ┌──────────┬─────────┼─────────┬──────────┬──────────┐
        │          │         │         │          │          │
    capture/   entropy/  fingerprint/  risk/     ml/      signing/
        │          │         │         │          │          │
        └────┬─────┴─────────┘         │          │          │
             │                         │          │          │
             └────────────┬────────────┴────┬─────┘          │
                           ▼                 ▼                │
                       pipeline/  ◄──────────┘                │
                           │                                  │
                           └──────────────────────────────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
        reports/     utils/(registry)  dashboard/
             ▲             ▲             │
             └─────────────┴─────────────┘
                           │
                        main.py
              (constructs everything, orchestrates nothing)
```

`config/` and `utils/` (logging, exceptions) sit beside `models/` as dependency-free foundations available to every package; omitted above for readability.

---

## 8. Class Diagram (text)

```
# --- models/ ---
class Device:
    ip: str
    first_seen: datetime
    last_seen: datetime

class DetectionEvent:
    device: Device
    tls_version: float | None
    key_size: int | None
    pfs: bool
    entropy: float
    port_risk: int
    protocol_flag: ProtocolType
    timestamp: datetime

class RiskEvent:
    detection: DetectionEvent
    risk_score: int              # 0–10
    category: RiskCategory
    remediation: str
    nist_reference: str

enum ProtocolType:  HTTPS, HTTP, MQTT, TELNET, OTHER
enum RiskCategory:  LOW, MEDIUM, HIGH
enum CaptureMode:   OFFLINE, LIVE, MOCK

# --- capture/ ---
abstract class CaptureSource:
    + read_packets() -> Iterator[PacketRecord]

class OfflinePcapSource(CaptureSource):        # fully implemented
    - path: Path
    + read_packets() -> Iterator[PacketRecord]   # scapy PcapReader, streamed

class LiveCaptureSource(CaptureSource):         # documented scaffold (D2)
    - interface: str
    + read_packets() -> Iterator[PacketRecord]   # raises NotImplementedError

# --- entropy/, fingerprint/ ---
# entropy/ is plain functions, not a class (Step 6) — see Section 18.
def shannon_entropy(data: bytes) -> float: ...            # pure
def compute_entropy_metrics(payload: bytes) -> EntropyMetrics: ...

# fingerprint/ is plain functions, not a class (Step 7) — see Section 19.
    +def detect_protocol_type(payload: bytes) -> ProtocolType: ...
    +def detect_tls_version(payload: bytes) -> Optional[TLSVersion]: ...
    +def extract_rsa_key_size(payload: bytes) -> Optional[int]: ...
    +def fingerprint_packet(payload: bytes) -> ProtocolFingerprint: ...

# --- risk/, ml/ ---
# risk/ is plain functions, not a class (Step 8) — see Section 20.
+def quantum_risk_score(tls_version, key_size, pfs, entropy, port_risk) -> int: ...
+def category_for_score(score: int) -> RiskCategory: ...
+def evaluate_risk(features: DeviceFeatures, port_risk: int) -> RiskAssessment: ...

# ml/ Step 9: Isolation Forest, not Decision Tree. AnomalyDetector
# remains a class (unlike entropy/, fingerprint/, risk/) since it is
# genuinely stateful — see Section 21.
class AnomalyDetector:
    - model: IsolationForest
    - score_std: float
    + fit(feature_matrix: np.ndarray) -> None
    + predict_one(features: DeviceFeatures) -> AnomalyAssessment
    + save(path) / load(path)

# --- signing/ ---
class DilithiumSigner:
    - public_key: bytes
    - secret_key: bytes
    + sign_event(event: RiskEvent) -> SignedRecord
    + verify_event(record: SignedRecord) -> bool

# --- reports/, dashboard/ ---
class ReportGenerator:
    + generate(event: RiskEvent) -> Path

class DashboardApp:
    + create_app(registry: DeviceRegistry, settings: Settings) -> Flask

# --- pipeline/ (D3) ---
class Pipeline:
    - capture_source: CaptureSource
    - risk_engine: RiskEngine
    - ml_classifier: MLClassifier
    - signer: DilithiumSigner
    - registry: DeviceRegistry
    + start() -> None       # spawns background thread
    + stop() -> None
    - _loop() -> None
    - _process_packet(packet: PacketRecord) -> None

# --- utils/ ---
class DeviceRegistry:
    - _store: dict[str, RiskEvent]
    - _lock: threading.Lock
    + update(event: RiskEvent) -> None
    + snapshot() -> list[RiskEvent]
```

---

## 9. Package Diagram (text)

```
┌─────────────┐
│   models    │   (zero outgoing deps — the shared vocabulary)
└──────┬──────┘
       │
   ┌───┼──────────────┬─────────┬─────────┐
   ▼   ▼               ▼         ▼         ▼
┌─────────┐  ┌──────────────┐  ┌──────┐  ┌────────┐
│ capture │  │entropy/fprint│  │ risk │  │   ml   │  ┌─────────┐
└────┬────┘  └──────┬───────┘  └──┬───┘  └───┬────┘  │ signing │
     │              │             │          │        └────┬────┘
     └──────┬───────┴─────────────┴────┬─────┘             │
            │                          │                    │
            ▼                          ▼                    ▼
                        pipeline/  ◄───────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         reports/   utils/(registry)  dashboard/
              │             ▲             │
              └─────────────┴─────────────┘
                            │
                         main.py
```

**Not allowed:** `dashboard → capture`, `dashboard → pipeline`, `reports → capture`, `signing → dashboard`, any cross-import between `entropy` and `fingerprint`, anything importing `main`. `dashboard` and `reports` only ever see `models/` and `utils.registry` — never the packages that produced the data.

---

## 10. Configuration Strategy

Unchanged from the draft: a single `Settings` dataclass in `config/settings.py`, precedence env var → `.env` → default, no module reads `os.environ` outside `config/`.

| Setting | Default | Purpose |
|---|---|---|
| `CAPTURE_MODE` | `offline` | `offline` (implemented) \| `live` (scaffold — raises at startup) \| `mock` |
| `PCAP_PATH` | `tests/fixtures/sample.pcap` | used when `CAPTURE_MODE=offline` |
| `LIVE_INTERFACE` | `None` | reserved for when `live_source.py` is implemented |
| `RISK_ISOLATION_THRESHOLD` | `7` | defined now so Phase 2 doesn't invent a second source of truth; unused by any logic in Phase 1 |
| `MODEL_PATH` | `ml/artifacts/anomaly_detector.joblib` | trained Isolation Forest (`AnomalyDetector`) artifact location — see Section 21 |
| `SIGNING_KEY_PATH` | `data/keys/` | Dilithium2 keypair persistence |
| `FLASK_HOST` / `FLASK_PORT` | `127.0.0.1` / `5000` | dashboard bind address |
| `LOG_LEVEL` | `INFO` | root log level |
| `LOG_DIR` / `DATA_DIR` | `logs/` / `data/` | output locations |

---

## 11. Logging Strategy

Standard-library `logging`, configured once in `utils/logging_setup.py`, one logger per module via `__name__`. Console handler + `RotatingFileHandler`. Log lines carry device IP and event ID.

**Resource-awareness note (ties to the performance constraint below):** per-packet detail is logged at `DEBUG`, not `INFO` — on a resource-constrained deployment target, `INFO`-level logging should reflect state transitions (a device's category changing, a new device appearing), not every packet processed. This costs nothing on Windows and avoids an easy source of unnecessary I/O later.

---

## 12. Error Handling Strategy

```
CipherError (base)
├── CaptureError            # bad .pcap file, interface not found
├── LiveCaptureNotImplementedError(CaptureError)   # D2 — raised by LiveCaptureSource
├── ParsingError
├── RiskEngineError
├── ModelNotFoundError        # triggers D4 fallback, not a crash
├── SigningError
└── ReportGenerationError
```

Fault isolation lives in `Pipeline._loop()` (D3): each packet's processing is wrapped in `try/except CipherError` plus a broad `except Exception` logged with a stack trace — one bad packet is skipped, never fatal. `LiveCaptureNotImplementedError` is the one exception that's intentionally *not* swallowed per-packet — it's raised once when `Pipeline.start()` first calls `read_packets()` on a `LiveCaptureSource`, caught at that single point, logged clearly, and the pipeline stops rather than looping on a scaffold. Flask converts any `CipherError` raised inside a route into a JSON error body with an appropriate status code.

---

## 13. Testing Strategy

`pytest`, `tests/` mirrors the package structure, now including `tests/models/` and `tests/pipeline/`.

- **Fixtures:** `tests/fixtures/sample.pcap` (2 TCP + 1 UDP payload-bearing packets, plus a filtered empty-payload TCP packet and a filtered non-IP ARP packet — see `generate_fixtures.py`; not "clean TLS 1.3, forced TLS 1.0, plaintext HTTP, MQTT" as an earlier draft of this section claimed — none of its packets are a real parseable TLS or MQTT handshake). The controlled TLS 1.3/TLS 1.0/weak-key/HTTP/Telnet/MQTT scenarios that section once described now exist as the separate, purpose-built Phase 15 evaluation fixtures — see Section 29.
- **`OfflinePcapSource`** gets full functional tests against those fixtures.
- **`LiveCaptureSource`** gets exactly one test: confirms it satisfies the `CaptureSource` interface and that calling `read_packets()` raises `LiveCaptureNotImplementedError` with a clear message — this is what "documented scaffold" means in test form, not a skipped/ignored file.
- **`Pipeline`** gets an end-to-end test using `OfflinePcapSource` plus real (not mocked) `RiskEngine`/`MLClassifier`-with-fallback/`DilithiumSigner`, asserting the final `DeviceRegistry` snapshot matches expected risk scores for the fixture devices — this is the test that would have been awkward to write against a monolithic `main.py` and is the concrete payoff of D3.
- Dashboard/report tests still use mocked `RiskEvent` data, independent of whether `Pipeline` has ever run.
- CI runs `pytest -m "not live"` — though with D2 in place there's now nothing marked `live` that does real network I/O; the marker is kept for when Phase 2 revisits `live_source.py`.

---

## 14. Deployment Strategy

Windows 11: venv, `pip install -r requirements.txt`. Three separate entrypoints exist, not one — see Section 28 for the full current picture: `python main.py` (offline batch run, no server, no dashboard — despite this section's earlier wording, `main.py` has never served a dashboard); `python run_api.py` (API-only dev server, `127.0.0.1:5000`, no UI); `python run_demo.py` (the integrated self-contained application — React UI + REST API together, `127.0.0.1:5000`, no `cipher-frontend`/Node/npm/Vite required at runtime). Offline mode needs nothing beyond the pip install; live mode (once implemented) will need Npcap — not relevant to Phase 1's actual test/run path today since `live_source.py` is a scaffold. GitHub Actions runs `pytest -m "not live"` on push using committed fixtures only.

---

## 15. Future Raspberry Pi Integration Strategy

Unchanged in substance from the draft, tightened given D3: Phase 2 adds a `hardware/` package with a `HardwareInterface` (`set_led`, `update_display`, `isolate_device`) — not built now. The natural hook is on `Pipeline`, not `main.py`: wherever `RiskEvent.risk_score >= settings.RISK_ISOLATION_THRESHOLD` is eventually checked, it's a call out from `Pipeline._process_packet()` to a `NullHardware` stub (Phase 1) or `RaspberryPiHardware` (Phase 2) — a swap at the composition root, not a rewrite of `Pipeline`. `live_source.py` going from scaffold to implemented is itself a Phase 2-adjacent task, but note it is not GPIO/OLED/systemd work — it's the same `CaptureSource` interface, just with a real `scapy.sniff()` body, and can in principle be done on Windows too before any Pi is involved. No further Phase 2 detail is given here per your instructions.

---

## 16. Resource-Awareness Notes (Phase 1, Written with Pi 4 in Mind)

No Raspberry Pi-specific code exists in Phase 1. The following Phase 1 choices were made because they're free on Windows and meaningfully better on constrained hardware later — each is a normal good practice, not a hardware-specific optimization:

- **Streaming, not bulk, pcap reads:** `OfflinePcapSource` uses scapy's `PcapReader` as an iterator, not `rdpcap()`, which loads the entire file into memory. Cost on Windows: none. Benefit later: memory use stays flat regardless of capture length.
- **Lazy, one-time model loading:** `MLClassifier` loads its `.pkl` file once at construction, not per prediction.
- **Deliberately small model:** a decision tree (already the plan, not a Phase 1 change) rather than anything requiring a heavier runtime.
- **Bounded registry, not a growing log:** `DeviceRegistry` keeps one current `RiskEvent` per device IP, not full history — memory footprint is proportional to device count, not to packets processed. Full history, if ever wanted, belongs in the signed log files on disk, not in memory.
- **On-demand PDF generation:** reports are generated when requested via the dashboard route, not proactively for every device on every update.
- **Event-driven capture, not polling:** both `OfflinePcapSource` and (once implemented) `LiveCaptureSource` are iterator/callback-driven via scapy, not a sleep-and-poll loop.

None of this changes Phase 1's Windows behavior or adds complexity — it's simply choosing the version of "normal good Python" that also happens to travel well.

---

## 17. Step 6 Addendum — Entropy Module

**Status:** Steps 5 (capture/) and 6 (entropy/) complete and verified.

`entropy/engine.py` is plain module-level functions (`shannon_entropy(data: bytes) -> float`, `compute_entropy_metrics(payload: bytes) -> EntropyMetrics`), not the `EntropyEngine` class the original Section 4/5/8 diagrams sketched. The calculation is pure and stateless — no configuration, nothing to hold between calls — so a class wrapper would be an abstraction with nothing to abstract. Sections 4, 5, and 8 above have been corrected to match; this is the only change those sections needed.

**Model decision (no change made):** `models.EntropyMetrics` (Step 4) already rejects `sample_size <= 0`. This is correct, not a gap — `capture.RawPacket` (Step 5) already guarantees a non-empty payload before entropy/ ever sees one, so an empty-payload `EntropyMetrics` should never legitimately be constructed. The "empty payload → 0.0" requirement belongs to `shannon_entropy()` itself (a pure calculation, independent of the domain model), not to `EntropyMetrics`. `compute_entropy_metrics(b"")` correctly raises `ValueError`, propagated from the unmodified Step 4 model.

**New capture-layer type used, not modified:** `entropy/` consumes `capture.RawPacket.payload` (added in Step 5 specifically so `models.PacketMetadata` could stay payload-free) — no changes to either was needed for this step.

---


## 18. Step 9 Addendum — Isolation Forest Anomaly Detection

**Status:** Step 9 (ml/) complete and verified.

`ml/classifier.py`'s `AnomalyDetector` replaces the draft's `MLClassifier`/`DecisionTreeClassifier` sketch (Section 8). Unlike entropy/, fingerprint/, and risk/ (all plain functions per Sections 18-20), this is a class: Isolation Forest is genuinely stateful, and a fitted model's learned structure must persist across `fit()` and `predict_one()` calls and be saved/loaded as a unit.

**Feature schema:** 12 columns, fixed order in `ml.features.FEATURE_NAMES` — raw entropy, packet size, TLS version (reusing `TLSVersion`'s own numeric value) with an observed-indicator, key size with an observed-indicator, forward secrecy, and one-hot protocol type. No Quantum Risk Score or risk/ output is ever used as a feature (enforced by a static-analysis test) — Isolation Forest and the rule engine consume the same raw inputs independently, per the approved "no risk-score leakage" requirement.

**Contamination = 0.05**, chosen after testing: sklearn's `"auto"` mode flagged ~46% of representative synthetic data as anomalous on inspection — clearly unsuitable. `0.05` caught all 10 injected synthetic outliers with zero false positives on the same data. This is a starting engineering default, not a value validated against real traffic.

**`random_state = 42`**, fixed for reproducibility, exposed as a constructor parameter.

**Anomaly score is sign-flipped from sklearn's native convention** (`decision_function` returns high=normal, low=anomalous; `AnomalyAssessment.anomaly_score` is negated so high=anomalous, matching the field's name). **`confidence` is a sigmoid of `anomaly_score`, scaled by the training-time score standard deviation** (adaptive, not a fixed constant) — explicitly not a calibrated probability.

**Persistence:** minimal `joblib.dump`/`load` of the whole `AnomalyDetector`, no registry or versioning.

**Not implemented at the time of this step:** Risk Fusion (now implemented — see Section 19), pipeline integration, REST API, frontend, any ML algorithm besides Isolation Forest.

---

## 19. Step 10 Addendum — Risk Fusion

**Status:** Step 10 (fusion/) complete and verified.

`fusion/risk_fusion.py`'s `fuse_assessments()` combines an already-produced `RiskAssessment` (risk/) and an optional `AnomalyAssessment` (ml/) into the `DeviceAssessment` that dashboard/, reports/, and the REST API are meant to consume. Like entropy/, fingerprint/, and risk/, this is a plain function, not a class — fusion is a pure, stateless rule with nothing to hold between calls.

**Frozen rule: Category-Floor with One-Level Escalation.**

```
final_category = risk_assessment.category

if anomaly_assessment is not None and anomaly_assessment.is_anomaly:
    escalate exactly one level:
        LOW -> MEDIUM
        MEDIUM -> HIGH
        HIGH -> HIGH
```

- **QRS category is the floor.** The rule-based Quantum Risk Score (risk/) always sets the starting category; Isolation Forest never lowers it and never sets it independently.
- **The anomaly flag may raise the category by one level only.** There is no direct `LOW -> HIGH` jump, regardless of how confident or extreme the anomaly signal is.
- **`confidence` does not gate or scale fusion.** Only the boolean `is_anomaly` flag is consulted; `anomaly_assessment.confidence` plays no role in the escalation decision.
- **`anomaly_assessment=None` is a valid input and passes through unchanged.** ML not having run (or being unavailable) is not itself an anomaly signal — the rule-based category is used as-is.
- **No weighted fusion, and no numeric combined score.** This is a discrete category-bucket rule, not an arithmetic blend of `risk_score` and `anomaly_score`; no new numeric "fused score" field exists anywhere in the output.
- **`DeviceAssessment` is the final, fused, API-facing per-device result** (models/device_assessment.py, Step 4) — the only assessment object downstream consumers (dashboard/, reports/, the REST API) are meant to see. `DeviceAssessment.anomaly_assessment` is `Optional[AnomalyAssessment]` to accommodate the `None` case above; `to_dict()`/`from_dict()` serialize it as JSON `null` symmetrically.

**Dependency boundary:** fusion/ imports only `models.*` — never `risk/` or `ml/` directly (enforced by a static-analysis test, same precedent as ml/features.py's "no risk-score leakage" check). It fuses already-computed outputs; it does not invoke either engine.

**Not implemented:** pipeline integration, REST API, frontend, report generation, signing.

---

## 20. Step 11 Addendum — Single-Observation Assessment Pipeline

**Status:** Step 11 (pipeline/assessment_pipeline.py) complete and verified.

`pipeline/assessment_pipeline.py`'s `assess_packet()` composes the already-implemented per-stage modules (entropy/, fingerprint/, risk/, ml/, fusion/) into one deterministic sequence for a single captured packet. It is a small, stateless, plain function — no thread, no loop, no registry — and contains no entropy, fingerprinting, scoring, ML, or fusion logic of its own; it only wires their existing public entry points together.

**Exact orchestration sequence:**

```
RawPacket.payload  -> compute_entropy_metrics()  -> EntropyMetrics
RawPacket.payload  -> fingerprint_packet()        -> ProtocolFingerprint
RawPacket.to_metadata()                           -> PacketMetadata
Device + PacketMetadata + ProtocolFingerprint + EntropyMetrics
                                                   -> DeviceFeatures
DeviceFeatures + port_risk  -> evaluate_risk()    -> RiskAssessment
DeviceFeatures  -> anomaly_detector.predict_one()  -> AnomalyAssessment | None
RiskAssessment + AnomalyAssessment(?) + Device + assessed_at
                                    -> fuse_assessments() -> DeviceAssessment
```

Exactly one `DeviceFeatures` instance is built per call and reused for both `evaluate_risk()` and `anomaly_detector.predict_one()` — it is never reconstructed between stages, and its schema (`device`, `packet`, `fingerprint`, `entropy`) carries no risk-score-derived field, so there is no channel for QRS output to leak into the ML feature vector (same "no risk-score leakage" property ml/features.py already guarantees at the vectorization level — see Section 18).

**`Device` and `port_risk` remain external, deliberately.** Neither is derived inside this step:
- **Device identity** — nothing in the codebase defines whether a packet's `src_ip` or `dst_ip` identifies "the device," and `DeviceRegistry` (utils/registry.py) — the component that would own device lifecycle/identity across observations — is not implemented yet. `assess_packet()` takes an already-identified `Device` as a required argument rather than guessing.
- **`port_risk`** — at the time of this step, no approved HTTP/MQTT/Telnet-to-port-risk mapping existed (see risk/scoring.py's own docstring on `quantum_risk_score()`); Step 12B (Section 22) has since frozen one as `risk.port_risk_for_protocol()`. `assess_packet()` still takes `port_risk` as a required external argument, exactly as `risk.evaluate_risk()` already does — Step 12B deliberately did not wire the new mapping function into `assess_packet()`; that wiring belongs to the future runtime runner, not to this pipeline's contract.

**The anomaly detector is dependency-injected and optional, never acquired internally.** `assess_packet(..., anomaly_detector=None)` skips the ML stage entirely and passes `anomaly_assessment=None` straight to `fuse_assessments()`, which already defines that exact pass-through behavior (Section 19). This step does not instantiate, fit, load, or save an `AnomalyDetector`, and never calls `ml/dataset.py`'s synthetic data generator — there is no fallback ML behavior of any kind. A caller who has a fitted detector supplies it; a caller who doesn't, doesn't, and ML is simply unavailable for that observation.

**Known open runtime/model-loading issue (not resolved in this step):** `config/constants.py`'s `DEFAULT_MODEL_PATH` (`ml/artifacts/risk_classifier.pkl`) does not match what `ml/train.py` actually produces (`ml/artifacts/anomaly_detector.joblib`, via `joblib`, not a `.pkl`). No trained model artifact is currently committed to the repository. Because `assess_packet()` never loads a model itself, this mismatch has no effect on Step 11 — but it means there is still no working configuration path from `Settings.model_path` to a real, loadable `AnomalyDetector`. Resolving this (config, format, and an acquisition policy) is left to a later, explicitly-scoped step.

**No aggregation or registry.** `assess_packet()` handles exactly one packet observation for exactly one already-identified device per call; it holds no state across calls and introduces no per-device or per-packet accumulation. `pipeline.runner.Pipeline` (still an unimplemented stub) remains reserved for the later runtime driver that will iterate a `CaptureSource` in a loop, own `DeviceRegistry`, and call `assess_packet()` once per packet.

**`assessed_at` is assessment execution time, not packet observation time.** The packet's own capture time is already represented by `PacketMetadata.timestamp` (via `DeviceFeatures.timestamp`). `assess_packet()` passes `assessed_at` straight through to `fuse_assessments()` unchanged — defaulting to the current UTC time when omitted (Section 19's existing default) — and never substitutes `RawPacket.timestamp` for it. An explicit `assessed_at` argument exists for deterministic tests and replay scenarios.

**Not implemented:** `pipeline.runner.Pipeline` (the background-thread capture loop), `DeviceRegistry`, REST API, frontend, report generation, signing, model acquisition policy.

---

## 21. Step 12A Addendum — Anomaly Model Loading and Configuration Alignment

**Status:** Step 12A (ml/loading.py, config path fix) complete and verified.

**Canonical model artifact:** `ml/artifacts/anomaly_detector.joblib` — this is what `ml/train.py` actually produces via `AnomalyDetector.save()` (joblib, not pickle). `config/constants.py`'s `DEFAULT_MODEL_PATH` previously named a stale, superseded artifact (`ml/artifacts/risk_classifier.pkl`, left over from the original Decision Tree/`MLClassifier` draft — see the corrected D4 note in Section 2) that `ml/train.py` never produced; it now matches the real filename and format. `Settings.model_path` (config/settings.py) is unchanged — it already reads the `MODEL_PATH` environment variable with this corrected default as its fallback, so `MODEL_PATH=<custom path>` continues to override it exactly as before.

**Runtime loading contract:** `ml.loading.load_anomaly_detector(model_path)`:
- **Artifact present** → calls `AnomalyDetector.load(model_path)` and returns the loaded, usable detector.
- **Artifact missing** → logs one `WARNING` naming the path and returns `None`. This is not a startup failure: QRS (`risk/`) is CIPHER's primary, always-on assessment engine and never depends on ML being available; Isolation Forest is a secondary, optional anomaly signal. `None` integrates directly with the already-approved Step 10 fusion rule (Section 19): `fuse_assessments(..., anomaly_assessment=None, ...)` passes the QRS category through unchanged.
- **Artifact present but corrupt or incompatible** (fails to deserialize, or deserializes to something other than an `AnomalyDetector`) → the genuine underlying error propagates unmodified. This is deliberately *not* treated the same as "missing": a broken configured artifact is a real configuration problem the caller must be able to see and distinguish from ordinary "no model configured yet" operation.
- **Never**, under any of the above: fits a model, calls `ml.train`, calls `ml.dataset.generate_synthetic_feature_matrix`, constructs a fallback `AnomalyDetector`, or saves anything. Loading and training remain fully separate — `ml/train.py`'s CLI is the only place a model is ever produced, run explicitly and separately from ordinary runtime.

**Not implemented:** wiring this loader into `main.py` or `pipeline.runner` (both remain later, explicitly-scoped steps), `port_risk` policy (resolved separately — see Section 22), `DeviceRegistry`, device identity.

---

## 22. Step 12B Addendum — port_risk Policy

**Status:** Step 12B (risk/port_risk.py) complete and verified.

**The gap this resolves:** `risk/scoring.py`'s `quantum_risk_score()` has always required `port_risk` as an external `int` argument, because the approved execution report specifies only that plaintext/insecure protocols such as HTTP, Telnet, and MQTT contribute "+1 to +2" risk — a range, not an exact per-protocol value (flagged as an open decision since Step 8; see Section 20's Step 11 addendum for how `assess_packet()` handled this by keeping `port_risk` external rather than guessing).

**Frozen mapping — an explicit ENGINEERING POLICY, not a value taken verbatim from the execution report:**

```
ProtocolType.HTTPS  -> 0
ProtocolType.OTHER  -> 0
ProtocolType.HTTP   -> 1
ProtocolType.MQTT   -> 1
ProtocolType.TELNET -> 2
```

HTTPS and OTHER contribute 0 (encrypted, or no confident protocol evidence). HTTP and MQTT — plaintext/lightweight, commonly unauthenticated — sit at the bottom of the report's approved range. TELNET — plaintext remote shell access — sits at the top of that range, reflecting materially higher exposure than a plaintext web or IoT-messaging request. These exact numbers were chosen to operationalize the report's stated range; they should not be cited as if the report itself specified them.

**`risk.port_risk_for_protocol(protocol: ProtocolType) -> int`** ([risk/port_risk.py](../risk/port_risk.py)) implements this mapping. It is keyed strictly on the already-classified `models.ProtocolType` enum (`fingerprint/protocol.py`'s own output) — never on transport port numbers (`src_port`/`dst_port` are not inspected), and never by string-matching a protocol name. An input that isn't a `ProtocolType` member raises `TypeError` rather than being silently treated as `OTHER`.

**The QRS formula itself is unchanged.** `risk/scoring.py`'s `quantum_risk_score()` and `risk/engine.py`'s `evaluate_risk()` still take `port_risk` as a plain externally-supplied `int`, exactly as before this step — `port_risk_for_protocol()` is a separate, optional helper a caller may use to produce that argument; it is not called from inside `evaluate_risk()`.

**Not wired into `assess_packet()` yet, deliberately.** `pipeline.assessment_pipeline.assess_packet()` continues to accept `port_risk` as a required external argument (Section 20). The intended future wiring — `fingerprint_packet(...).protocol -> port_risk_for_protocol(...) -> assess_packet(..., port_risk=...)` — belongs to the runtime runner step, not to this policy step.

**Not implemented:** wiring `port_risk_for_protocol()` into `assess_packet()` or `pipeline.runner`, `DeviceRegistry`, device identity.

---

## 23. Phase 9 Addendum — Cryptographic Signing & Verification

**Status:** Phase 9 (signing/dilithium_signer.py, signing/key_store.py) complete and verified.

**Implementation uses ML-DSA-44 under FIPS 204, not the legacy pre-standardization `Dilithium2` object.** ML-DSA is NIST's finalized post-quantum digital-signature standard (FIPS 204), standardizing the CRYSTALS-Dilithium algorithm family; ML-DSA-44 is the NIST security level 2 parameter set — the finalized descendant of the original pre-standardization "Dilithium2" parameter set (identical core parameters: k=4, l=4, eta=2, tau=39). The installed `dilithium-py` library ships both objects; this codebase deliberately calls `dilithium_py.ml_dsa.ML_DSA_44`, never `dilithium_py.dilithium.Dilithium2`.

**Canonical human-readable algorithm label:**

```
ALGORITHM_NAME = "ML-DSA-44 (FIPS 204; derived from CRYSTALS-Dilithium)"
```

This is the value `signing.dilithium_signer.sign_assessment()` writes into every `SignedEvent.algorithm`, and the value `verify_signed_event()` requires an exact match against before attempting cryptographic verification (any other value fails verification immediately, without even inspecting the signature). Earlier scaffolding (Step 4-era test fixtures) used the placeholder string `"FIPS-204-Dilithium2"` — that has been replaced with this canonical label wherever it appeared; it was never the finalized name and is not preserved for backward compatibility.

**Signing target: the canonical DeviceAssessment JSON, signed directly.** `canonicalize_assessment(assessment)` produces:

```python
json.dumps(assessment.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
```

`sign_assessment()` signs these bytes directly — never a Python `repr()`, never pickle/joblib bytes, never a bare risk score, and never a pre-hash of the assessment. ML-DSA signs arbitrary-length messages natively; a `DeviceAssessment`'s JSON is small enough that no intermediate hash adds value here (contrast with report-level signing below, where the message being signed — rendered PDF bytes — genuinely warrants hashing first).

**`SignedEvent` carries `assessment` + `signature_hex` + `algorithm` + `signed_at`** (models/signed_event.py, Step 4) — unchanged by this phase. `sign_assessment(assessment, secret_key, signed_at=None)` canonicalizes, signs, and wraps the result; `signed_at` is preserved if supplied, else set to the current UTC time.

**Verification failure modes — all return `False`, none raise:** a tampered `assessment` (canonicalizes to different bytes than what was signed), a tampered `signature_hex`, the wrong `public_key`, and an `algorithm` label that doesn't equal `ALGORITHM_NAME`. Only malformed argument *types* (e.g., a non-`SignedEvent`, non-bytes key material) raise `TypeError` — verified end-to-end, including a full `SignedEvent.to_dict()`/`from_dict()` round-trip remaining verifiable.

**Phase-1 key lifecycle** (`signing/key_store.py`, `load_or_create_keypair(key_dir)`): frozen filenames `ml_dsa_44_public.key` and `ml_dsa_44_secret.key` under the directory the caller supplies (in practice, `Settings.signing_key_path`, unchanged — still `SIGNING_KEY_PATH`, default `data/keys/`, env-overridable, not wired into `main.py` in this phase). Both files present → load and return them. Neither present → generate one keypair, create the directory if needed, persist both files, return them. **Exactly one present is treated as a failure, not a partial success** — `load_or_create_keypair` raises `RuntimeError` naming which file is missing, and never regenerates or overwrites the surviving key. Existing key files are never overwritten under any lifecycle branch. No passphrase encryption, no OS keyring integration, and no file-permission hardening are implemented — production-grade secret-key protection is explicitly future hardening, not attempted in Phase 1.

**Report/PDF signing remains Phase 10.** `models.ReportMetadata` (Step 4) already has separate `report_hash` and `signature_hex` fields — a genuinely different signing target from `SignedEvent`'s direct-assessment-JSON signing. Phase 10 is expected to reuse this phase's generic `sign()`/`verify()` primitives on a report hash — **not a hash of the rendered PDF's own bytes** (see Section 24: hashing the final PDF file would be self-referential once that hash is displayed on the PDF itself; Phase 10 hashes a canonical report-*data* payload instead, following the same pattern as `canonicalize_assessment()` above). This phase does not implement or assume anything about PDF rendering, `ReportGenerator`, `reports/`, REST, the frontend, `pipeline.runner`, or `DeviceRegistry`.

**Not implemented:** PDF/report generation and signing, wiring `load_or_create_keypair`/`sign_assessment` into `main.py` or a future runtime runner.

---

## 24. Phase 10 Addendum — Device-Specific PDF Security Reports

**Status:** Phase 10 (reports/pdf_generator.py) complete and verified.

**One concise, 3-page PDF per flagged device**, rendering only fields already available on an already-produced `DeviceAssessment` (Step 4/10) — no risk scoring, NIST mapping, or signing logic is duplicated inside `reports/`; it reuses `risk_assessment.remediation`/`.nist_reference` verbatim and delegates all cryptography to the unmodified `signing.sign()`/`signing.verify()`.

**Flagged-device rule (frozen):** `is_flagged_device(assessment) -> bool` returns `assessment.final_category != RiskCategory.LOW` — LOW is not flagged, MEDIUM and HIGH both are. No QRS/fusion threshold is changed.

**Report ID (frozen, deterministic, no registry):** `generate_report_id(device_ip, generated_at)` produces `CIPHER-<device-ip-with-separators-as-hyphens>-<UTC timestamp as YYYYMMDDTHHMMSSZ>` (e.g. `CIPHER-192-168-1-10-20260907T154500Z`) — a pure function of its two inputs, no UUID, no counter, no persisted state.

**Output location:** `data/reports/` (module-level default in `reports/pdf_generator.py`, `DEFAULT_REPORT_OUTPUT_DIR`) — no new configuration subsystem; not added to `Settings`/`config/constants.py` in this phase.

**The self-reference problem and its resolution.** The report must display its own integrity hash and signature (Page 3), but hashing the *final* rendered PDF bytes and then writing that hash onto the page would change the bytes the hash was computed from — circular, with no fixed point. Phase 10 resolves this exactly as Phase 9 resolved the equivalent problem for `DeviceAssessment`: hash and sign a **canonical report-content payload**, not any rendered artifact:

```
canonical_content = json.dumps(
    {
        "report_id": report_id,
        "device_ip": device_ip,
        "generated_at": generated_at.isoformat(),
        "assessment": assessment.to_dict(),
    },
    sort_keys=True, separators=(",", ":"),
).encode("utf-8")

report_hash = sha256(canonical_content).hexdigest()
signature   = signing.sign(bytes.fromhex(report_hash), secret_key)
```

Every value needed for Page 3 (`report_hash`, `signature_hex`, `signing_algorithm`, `verification_status`) is therefore known *before* any page is drawn — zero circularity. `report_hash` is labeled **"Report Integrity Hash (SHA-256)"** throughout, and the PDF's own Page 3 text explicitly states the signature protects the canonical report content, not the PDF byte stream — this is a hash of report *data*, never a claim about the final file's bytes. `ReportMetadata.signing_algorithm` is `signing.ALGORITHM_NAME`, reused verbatim (no new label). Only a short, truncated preview of `signature_hex` is printed on the page; the full value lives in `ReportMetadata.signature_hex`.

**`verify_report(metadata, assessment, public_key) -> bool`** reconstructs the same canonical payload from `metadata` + the (separately supplied) `assessment`, recomputes the SHA-256 hash, confirms it matches `metadata.report_hash`, checks `metadata.signing_algorithm == signing.ALGORITHM_NAME`, and delegates the actual cryptographic check to `signing.verify()` unchanged — no duplicated cryptographic logic. Returns `False` for a tampered assessment, a tampered hash, a tampered signature, the wrong public key, or an algorithm mismatch.

**Page layout, mapped to available fields:**
- **Page 1 (Executive Summary):** `APP_NAME`/`APP_TAGLINE` branding, report ID, generated time, `device.ip`/`.first_seen`/`.last_seen`, `final_category`, `risk_assessment.risk_score`/`.category`, anomaly status ("Anomalous" / "Not anomalous" / "Not available" per `anomaly_assessment`), a short structural summary that does not restate specific findings (those live on Page 2).
- **Page 2 (Technical Findings & NIST Remediation):** `risk_assessment.risk_score`/`.category`, `risk_assessment.remediation` (verbatim prose — already names the specific weak setting(s)), `risk_assessment.nist_reference` (verbatim), and full Isolation Forest detail (`is_anomaly`, `anomaly_score`, `confidence`) when `anomaly_assessment is not None`, else "Not available". No raw TLS version / key size / forward secrecy / entropy / protocol fields are rendered — `DeviceAssessment` does not carry them, and none are fabricated.
- **Page 3 (Audit & Verification):** report ID, `assessed_at`, `generated_at`, the Report Integrity Hash (SHA-256), signing algorithm, verification status, and a truncated signature preview.

**PDF library:** `reportlab` (already installed, already in `requirements.txt`) via its plain `Canvas` API — no new PDF dependency. Generated with `pageCompression=0` specifically so tests can locate expected text directly in the raw file bytes without OCR or a PDF-parsing dependency; page count is confirmed structurally (`/Type /Page` object count in the raw bytes), not visually.

**Not implemented:** wiring `generate_report()`/`is_flagged_device()` into `main.py`, `pipeline.runner`, `DeviceRegistry`, REST, or the frontend.

---

## 25. Phase 11 Addendum — Backend Runtime Orchestration

**Status:** Phase 11 (`pipeline/runner.py`, `main.py`) complete and verified.

**`pipeline.runner.run_capture(capture_source, anomaly_detector, public_key, secret_key, report_output_dir=DEFAULT_REPORT_OUTPUT_DIR)`** is the synchronous, single-pass offline orchestrator: it drives every already-implemented stage (entropy, fingerprint, port-risk, QRS, optional Isolation Forest, fusion, signing, PDF generation) through one full pass over a `CaptureSource`, with no new algorithm of its own. It returns `Tuple[List[DeviceAssessment], List[Path]]` — the retained per-device assessments and the paths of every PDF actually written — deliberately not a new `RunSummary` domain model, per the "prefer existing types" instruction for this phase.

**Phase-1 device-identity convention (frozen, explicitly NOT specified by the Execution Report):** the observed device is identified by `RawPacket.src_ip`. This is a Phase-1 implementation convention, sufficient for deterministic offline-`.pcap` execution, chosen because the Execution Report does not specify src_ip vs. dst_ip device identity and no other convention exists anywhere in this repository. A future deployment may use network-position, subnet, or MAC-aware identification instead — none of that (subnet inference, MAC discovery, src/dst heuristics, vendor lookup, network-direction analysis) is implemented here.

**Device lifecycle is local, in-run state only — not `DeviceRegistry`.** `run_capture` holds a plain `Dict[str, Device]` for the duration of one call: first contact for an IP calls `Device.first_contact(src_ip, packet.timestamp)`; a later packet from the same IP advances `last_seen` only if its timestamp is strictly later, via the existing `Device.with_last_seen()` (which already preserves `first_seen` unchanged); an out-of-order (earlier-timestamped) packet never moves `last_seen` backwards. `utils/registry.py`'s `DeviceRegistry` remains an unimplemented stub — nothing in Phase 11 needed its thread-safety, cross-request query API, or bounded-history semantics.

**Representative-assessment selection (frozen runtime policy — does not change QRS, Isolation Forest, or Risk Fusion):** exactly one `DeviceAssessment` is retained per device across the whole run. A new observation replaces the retained one only if: (1) its `final_category` outranks the retained one (`HIGH > MEDIUM > LOW`); or, on a category tie, (2) its `risk_assessment.risk_score` is higher; or, on both ties, (3) its `assessed_at` is later. This guarantees exactly one PDF per flagged device even when a device appears in many packets across a `.pcap` file, without altering any risk computation.

**Port risk:** unchanged from Step 12B. Because `assess_packet()` requires `port_risk` as an already-resolved `int` before it performs its own internal fingerprinting, `run_capture` calls `fingerprint_packet(raw_packet.payload)` itself first to get `.protocol` for `port_risk_for_protocol()`, then calls `assess_packet()`, which fingerprints the same payload again internally. This is accepted, deterministic, side-effect-free duplication — `assess_packet()` was not changed merely to optimize it away.

**ML and signing are loaded exactly once, by the caller, and injected — never acquired inside the per-packet loop.** `main.py` calls `ml.loading.load_anomaly_detector(settings.model_path)` once (fail-open: `None` on a missing artifact, exactly as Step 12A already defined) and `signing.load_or_create_keypair(settings.signing_key_path)` once, then passes the resulting `Optional[AnomalyDetector]` and `(public_key, secret_key)` into `run_capture`. `run_capture` itself never imports `ml.loading` or `signing.key_store` — it only calls `assess_packet()` (which accepts an already-built detector) and `generate_report()` (which accepts already-resolved key bytes).

**Reporting:** `is_flagged_device()` is evaluated once per retained representative, after EOF — never per-packet. Every flagged (`final_category != LOW`) device gets exactly one `generate_report()` call; LOW devices get none.

**Fault isolation, no retry framework:** each packet's `fingerprint → port_risk → assess_packet` sequence, and each device's `generate_report()` call, is wrapped in its own `try/except Exception` — logged at `ERROR` with identifying context, then the run continues. `KeyboardInterrupt`/`SystemExit` are never caught (only `Exception` is) and always propagate. A missing ML artifact is not a per-packet error at all — it was already resolved to `None` before `run_capture` was ever called.

**No threading.** The pre-existing `runner.py` stub's `start()`/`stop()` background-thread design was written for a world where a live NIC capture runs indefinitely alongside a simultaneously-running dashboard — neither exists in Phase 11's scope. Offline mode processes the whole file once, synchronously, to a deterministic final state, then returns; that stale docstring has been replaced.

**`main.py` is finally wired**, exactly per D3 (composition root, no orchestration logic of its own): load `Settings` → configure logging → (if `CAPTURE_MODE=mock`, log and exit 0 immediately — mock mode has no `CaptureSource` and is meant for a dashboard that doesn't exist yet in Phase 1, so it is not attempted) → `capture.factory.get_capture_source(settings)` → `ml.loading.load_anomaly_detector(settings.model_path)` → `signing.load_or_create_keypair(settings.signing_key_path)` → `pipeline.runner.run_capture(...)` → log a concise completion summary (`N device(s) assessed, M report(s) generated`) → exit 0. Any `CipherError` raised during this sequence (including `CaptureError` for a bad/missing `.pcap` file, and `LiveCaptureNotImplementedError` for `CAPTURE_MODE=live`, which surfaces the moment `run_capture` calls `read_packets()`) is logged at `ERROR` and exits 1 — `CAPTURE_MODE=live` still fails loudly and immediately, exactly as D2 always specified; live capture itself remains unimplemented.

**Not implemented:** REST, frontend, dashboard, `DeviceRegistry`, isolation/remediation, Raspberry Pi behavior, live capture, any new ML/scoring algorithm.

---

## 26. Phase 12 Addendum — REST API Contracts

**Status:** Phase 12 (`dashboard/`, `run_api.py`) complete and verified. This section is the frontend contract — a teammate building the UI independently should be able to implement against it without reading any Python.

**Separate entrypoint, `main.py` unchanged in contract.** `run_api.py` is a second composition root alongside `main.py`, not a replacement: `main.py`'s "load, run one offline capture pass, exit" behavior (relied on by existing tests since Step 3) is untouched. `run_api.py` performs the identical one-shot composition (Settings → logging → `CaptureSource` → optional `AnomalyDetector` → signing keypair → `run_capture()`), then — instead of exiting — builds an `ApplicationState` from the results and calls `dashboard.create_app(state, settings).run(...)`, blocking until interrupted. `CAPTURE_MODE=mock` exits gracefully before attempting either (no `CaptureSource` exists for it); `CAPTURE_MODE=live` still fails loudly via the same `CipherError` path as `main.py`.

**Small, targeted `pipeline.runner.run_capture()` change:** its second return value is now `List[Tuple[Path, ReportMetadata]]` (was `List[Path]`) — the `ReportMetadata` that Phase 11 discarded (`path, _metadata = generate_report(...)`) is retained, because Phase 12 genuinely needs it to answer `/api/devices/<ip>/report`. No scoring, ML, signing, fusion, or orchestration behavior changed — this is a return-shape addition only, updated in `main.py` (variable rename, `len()` still works identically) and in Phase 11's own test suite.

**`dashboard.state.ApplicationState`** is the entire runtime data source — an immutable snapshot built once (`build_application_state(assessments, reports)`) from `run_capture()`'s exact return shape, holding only `Dict[str, DeviceAssessment]` and `Dict[str, Tuple[Path, ReportMetadata]]`, both keyed by device IP. No database, no `DeviceRegistry`, no persistence. Every route resolves a device through a plain dict lookup on this state — **never** by constructing a filesystem path from a request parameter. An unknown IP is simply absent from both dicts, so it 404s before any filesystem code runs; the trusted `Path` object served by the download route always originates from `ApplicationState`, never from the URL.

**Frozen REST contract** (all under Flask, no FastAPI, no `flask-cors`):

| Method & path | Returns |
|---|---|
| `GET /api/health` | `{"status": "ok", "app_name": str, "app_version": str, "capture_mode": str, "devices_assessed": int, "reports_generated": int}` — all real, from `config.constants`/`Settings`/`ApplicationState` counts, nothing fabricated. |
| `GET /api/devices` | `{"devices": [<device summary>, ...]}`, ordered deterministically by `device_ip` (a plain string sort — not IP-octet-numeric — see the code for the exact ordering). |
| `GET /api/devices/<ip>` | A device detail object (summary + `remediation` + `nist_reference`); `404` for an unknown IP. |
| `GET /api/devices/<ip>/report` | The report metadata object; `404` if the IP is unknown *or* if that device has no report (e.g., it was never flagged). |
| `GET /api/devices/<ip>/report/download` | The raw PDF, `Content-Type: application/pdf`; same `404` cases as above. |

**Device summary DTO** (`dashboard/serializers.py::serialize_device_summary`):
```json
{
  "device_ip": "192.168.1.10",
  "first_seen": "2026-01-01T12:00:00+00:00",
  "last_seen": "2026-01-01T12:00:00+00:00",
  "final_category": "HIGH",
  "risk_score": 9,
  "risk_category": "HIGH",
  "anomaly": null,
  "assessed_at": "2026-01-01T12:00:00+00:00",
  "has_report": true
}
```
`anomaly` is `null` when `DeviceAssessment.anomaly_assessment is None` (ML did not run for that device — not an error, not "0 risk"), otherwise `{"is_anomaly": bool, "anomaly_score": float, "confidence": float}`. Device detail is this object plus `"remediation"` and `"nist_reference"` (both taken verbatim from `RiskAssessment` — never recomputed or re-mapped in `dashboard/`). All timestamps are ISO-8601 (`datetime.isoformat()`); `final_category`/`risk_category` are the enum's `.value` string (`"LOW"`/`"MEDIUM"`/`"HIGH"`).

**Report metadata DTO** (`serialize_report_metadata`):
```json
{
  "report_id": "CIPHER-192-168-1-10-20260101T120000Z",
  "device_ip": "192.168.1.10",
  "generated_at": "2026-01-01T12:00:00+00:00",
  "page_count": 3,
  "report_hash": "<64 hex chars>",
  "signature_preview": "<first 32 hex chars>...",
  "signing_algorithm": "ML-DSA-44 (FIPS 204; derived from CRYSTALS-Dilithium)",
  "verification_status": true,
  "download_url": "/api/devices/192.168.1.10/report/download"
}
```
`signature_preview` is a short, truncated prefix of `ReportMetadata.signature_hex` (which is thousands of characters for a real ML-DSA-44 signature) — the full value is never sent over REST; it remains in the generated PDF and in the backend's own `ReportMetadata`.

**Standard error shape**, used for every 404 (both explicit — unknown device/report — and a global fallback for any unmatched or malformed URL, so a garbage path never returns Flask's default HTML 404 or leaks a filesystem detail):
```json
{"error": "not_found", "message": "No device found with IP 203.0.113.9"}
```

**CORS:** an optional `CORS_ORIGIN` setting (env-overridable, `None` by default — no new configuration subsystem, just one more field on the existing `Settings`/`config.constants` pattern). When set, every response carries `Access-Control-Allow-Origin: <exact configured value>` via a small Flask `after_request` hook — no `flask-cors` dependency. When unset, no cross-origin header is added at all. A wildcard (`*`) is never emitted under any configuration.

**Dependency boundary:** `dashboard/` imports only `models/`, `config/`, `flask`, and its own `dashboard.state`/`dashboard.serializers` — never `capture/`, `fingerprint/`, `risk/`, `ml/`, `fusion/`, `pipeline/`, or `signing/` (enforced by a static-analysis test, same precedent as `fusion/`, `ml/loading.py`, `risk/port_risk.py`, `signing/`). `run_api.py` is the only place Phase 12 code imports `pipeline.runner`/`ml.loading`/`signing` — it builds the plain `ApplicationState` and hands it to `dashboard.create_app()`, so `dashboard/` never recomputes an assessment.

**`dashboard/mock_data.py` remains unimplemented** — not needed for the real REST path in Phase 1, and your teammate can mock the frozen JSON contract above directly rather than the backend building a second fake backend.

**Not implemented:** frontend code, dashboard HTML/UI, isolation/remediation, Raspberry Pi behavior, a database, `DeviceRegistry`, `flask-cors`.

---

## 27. Phase 14 Addendum — High-Risk Enforcement / Isolation Logic

**Status:** Phase 14 (`enforcement/`) complete and verified. Real hardware execution remains deferred — see below.

**Frozen isolation rule: raw QRS, never the fused category.** The Execution Report specifies isolation eligibility as a literal numeric condition, `QRS >= 7/10`. `enforcement.decision.should_isolate(assessment, threshold)` therefore returns `assessment.risk_assessment.risk_score >= threshold` and deliberately never reads `assessment.final_category`. This is intentional: Risk Fusion (Section 19) may escalate a device's *reported* category from MEDIUM to HIGH purely because Isolation Forest flagged an anomaly — but an ML-only signal must never trigger a high-consequence physical isolation action the deterministic, explainable QRS score does not itself support. A device with `risk_score=5` and an ML-escalated `final_category=HIGH` is **not** eligible for isolation. `should_isolate()` is pure — no logging, no I/O, no subprocess — and reuses the existing `RISK_ISOLATION_THRESHOLD`/`Settings.risk_isolation_threshold` (default 7, previously unused by any logic; this is the first step to actually read it).

**`enforcement.backends.IsolationOutcome`** (`device_ip`, `risk_score`, `requested_at`, `requested`, `enforced`, `reason`) is a small, ephemeral, non-persisted result type living in `enforcement/`, not `models/` — isolation is a runtime enforcement concern, not a fused assessment fact, and nothing here is written to a database.

**`enforcement.backends.IsolationBackend`** is the abstract hardware-execution boundary (`isolate(device_ip, risk_score) -> IsolationOutcome`; no `restore()` — nothing calls it and restoration semantics are exactly the kind of undefined firewall policy below that this phase must not invent). **`NoOpIsolationBackend`** is the only concrete backend implemented in Phase 1: it never calls `subprocess`, never touches iptables or the Windows Firewall, never requires administrator privileges, and never reports a successful physical isolation — it logs one `WARNING` and returns `enforced=False` with an explicit `reason`. This keeps "isolation decided" and "isolation enforced" as two distinct, honestly-reported facts, never conflated — exactly the distinction the original draft's Section 15 `NullHardware`/`RaspberryPiHardware` sketch already called for.

**Real Raspberry Pi iptables execution remains deferred**, not because it was forgotten but because the Execution Report does not specify enough to implement responsibly: which chain, `INPUT` vs. `FORWARD`, source vs. destination rule direction, `DROP` vs. `REJECT`, duplicate-rule semantics, restoration semantics, or the privilege model. Inventing these now would be firewall policy, not architecture. A `LinuxIptablesBackend` is a future, explicitly-scoped addition, swapped in at the composition root exactly like `NoOpIsolationBackend` is today — never via platform-sniffing inside `enforcement/` or `pipeline/runner.py`.

**Enforcement timing: immediate, per-packet — not deferred to EOF.** `pipeline.runner.run_capture()` calls `should_isolate()`/the injected `IsolationBackend` immediately after each individual `assess_packet()` result, inside `_process_packet()` — *before* that assessment is folded into the end-of-capture representative selection. This is deliberate: representative selection and report generation are a reporting concern that correctly waits for the strongest assessment across the whole run, but the Execution Report's detection-to-isolation latency target cannot be met by a decision that waits for EOF. Reporting itself is completely unchanged — still one PDF per flagged representative device, generated after the capture source is exhausted.

**One isolation attempt per device per run.** A local `enforcement_attempted_ips: Set[str]` (explicitly *not* `isolated_ips` — `NoOpIsolationBackend` never actually isolates anything) — scoped to one `run_capture()` call, exactly like the existing per-run `devices`/`representatives` dicts, *not* `DeviceRegistry` — ensures a device that produces many high-risk packets is only ever handed to the backend once. The IP is marked attempted *before* the backend call, so a raising/failing attempt still counts as the one attempt (no retries).

**Failure handling** mirrors the runner's existing per-packet/per-report fault-isolation style exactly: an unexpected exception from `isolation_backend.isolate()` is caught, logged at `ERROR` with device/QRS context, and the run continues — it never aborts remaining packet processing, and it never prevents that packet's assessment from still being recorded for representative selection. `KeyboardInterrupt`/`SystemExit` are not caught (only `Exception` is) and always propagate, consistent with the rest of `run_capture()`.

**Auditability** uses the existing `logging` infrastructure only — no new persistence, no new file, no database. Two log lines per enforcement attempt: `NoOpIsolationBackend` logs its own hardware-unavailable warning; `pipeline.runner` separately logs the full decision context (device IP, QRS, threshold, requested/enforced, reason) that only the decision layer knows.

**Composition root wiring, no new setting.** `main.py` and `run_api.py` each construct a single `NoOpIsolationBackend()` explicitly and pass it — together with `settings.risk_isolation_threshold` — into `run_capture()`. No platform detection, no new environment variable; a future Pi deployment swaps the concrete backend at this exact point, not inside `pipeline/runner.py`.

**Reports, REST, and signing are unchanged.** The Execution Report does not require isolation status inside the PDF or the REST contract; `reports/`, `ReportMetadata`, `dashboard/routes.py`, `dashboard/serializers.py`, and the frozen Phase 12/13 API are untouched.

**Stale terminology corrected:** Section 15's `RiskEvent.risk_score >= settings.RISK_ISOLATION_THRESHOLD` and `Pipeline._process_packet()` referred to the pre-Step-4-addendum draft types. The actual implementation is `assessment.risk_assessment.risk_score >= threshold` inside `pipeline.runner.run_capture()`'s per-packet loop — the design Section 15 sketched, using the terminology every later addendum already established.

**Not implemented:** any real Linux/Raspberry-Pi iptables backend, root-privilege handling, restoration/unblock workflow, isolation status in the PDF or REST contract, any new configuration setting for backend selection.

---

## 28. Phase 15 Addendum — Self-Contained Application Packaging

**Status:** Phase 15 packaging/integration (`web/`, `dashboard/spa.py`, `run_demo.py`) complete and verified. Evaluation fixtures, latency/false-positive benchmarks, and any packaging beyond a `pip install` + `python run_demo.py` workflow (browser auto-open, `.exe`/PyInstaller, a Windows launcher) remain out of scope and are not implemented.

**Two-repository release-artifact boundary, not duplicated source ownership.** React/TypeScript source continues to live entirely in the separate `cipher-frontend` repository — nothing under `cipher-frontend/src`, its `package.json`, `node_modules`, or its Vite/TypeScript config is copied into this repository. What *is* committed here is `web/`: an exact, unmodified copy of `cipher-frontend/dist/` (its already-built production output — `index.html`, `favicon.svg`, `icons.svg`, `assets/*.js`, `assets/*.css`) checked in as a release artifact, the same way a compiled binary or a vendored third-party asset would be, not as source this repository owns or edits. `web/` is intentionally **not** gitignored.

**Frontend release update procedure (developers only; end users never do this):**
```
cd cipher-frontend
npm run build
```
then replace this repository's `web/` with the newly-built `cipher-frontend/dist/` contents, then rerun this repository's test suite before committing the updated `web/`. No automation for this exists or is planned in Phase 1 — it is a manual, infrequent step tied to frontend releases, not a build step of this repository.

**Same-origin deployment, no new CORS surface.** `cipher-frontend`'s production build now issues same-origin requests (`/api/...`, no absolute host) rather than a build-time-baked `http://127.0.0.1:5000` base URL — a change made entirely in `cipher-frontend`, not here. `run_demo.py` therefore never needs `Settings.cors_origin` set, and no wildcard CORS behavior was added anywhere; the existing optional `CORS_ORIGIN` mechanism (Phase 12 addendum) is untouched and still available for `run_api.py`'s cross-origin dev workflow (a separately-running frontend dev server on a different port).

**`run_demo.py` is a third composition root — `main.py` and `run_api.py` are both unmodified in behavior.** It performs the exact same one-shot composition `run_api.py` does (Settings → logging → `CaptureSource` → optional `AnomalyDetector` → signing keypair → `NoOpIsolationBackend` → `run_capture()` → `ApplicationState`), then additionally registers static/SPA serving (below) onto the Flask app before calling `app.run(...)`. `main.py`'s "load, run once, exit" contract and `run_api.py`'s API-only server are both unchanged — nothing about their tests, imports, or behavior was touched.

**`dashboard/spa.py`, a small helper module, not a `dashboard/app.py` rewrite.** `dashboard.create_app()`'s existing contract (used unchanged by `run_api.py`) is left completely untouched — `run_api.py`'s app has no static/SPA routes at all, on purpose, since it remains the API-only dev entrypoint. `run_demo.py` alone calls the new `dashboard.spa.register_spa(app, web_dir)` after `create_app()` to layer static/SPA serving on top. `dashboard/spa.py` follows the same dependency-boundary precedent as the rest of `dashboard/` (enforced by a static-analysis test): it imports only `flask` and `pathlib`, never `capture/`, `fingerprint/`, `risk/`, `ml/`, `fusion/`, `pipeline/`, or `signing/` — it has no awareness of React, Vite, or Node, only of serving static files from a directory.

**Route layering (registered on top of the existing, unchanged `/api/...` blueprint):**
- `GET /` and `GET /favicon.svg` / `GET /icons.svg` serve the corresponding real file from `web/` directly.
- `GET /assets/<path:filename>` serves the matching file from `web/assets/` directly — never through the fallback below.
- `GET /<path:path>` (registered last) is the BrowserRouter fallback: it serves `web/index.html` for any other path (so a full-page reload on a client-side route like `/devices` or `/reports` survives), **except** a path starting with `api/`, which is aborted with a real `404` instead — a genuinely-unknown API path (e.g. `/api/does-not-exist`) must continue to 404 through the existing global JSON error handler, never silently receive the SPA shell. Flask/Werkzeug's routing already prefers a fully-static rule (like each real `/api/...` route) over a rule containing a `<path:...>` converter regardless of registration order, so the existing blueprint routes are never at risk of being shadowed by the fallback.

**Fail-fast on a missing/incomplete build, never a silent or half-functional server.** `dashboard.spa.validate_web_build(web_dir)` requires both `index.html` and an `assets/` directory to exist; `run_demo.py` calls it once, before any capture work starts (so a missing build is reported immediately rather than after spending time on a capture pass and key generation), and `register_spa()` calls it again itself before registering any route, so the module is safe and correct even if ever used directly. Neither path attempts to invoke `npm`/Vite/Node automatically — the error message is purely informational (`"CIPHER web application is missing.\nExpected: <path>/web/index.html"`), pointing at the manual release procedure above.

**Web directory resolution is anchored to the file, not the caller's cwd.** `run_demo.py`'s `WEB_DIR = Path(__file__).resolve().parent / "web"` — identical in spirit to `REPO_ROOT`-style path resolution already used by several test files (e.g. `tests/test_main_step3.py`) — so `python run_demo.py` behaves identically regardless of the directory it's launched from, and is unaffected by `Settings`' existing cwd-relative defaults (`LOG_DIR`, `DATA_DIR`, `SIGNING_KEY_PATH`, `generate_report`'s report-output default), which intentionally remain cwd-relative and untouched.

**No new destructive startup behavior.** `run_demo.py` never clears `data/reports/`, `data/keys/`, or `logs/` on startup — it reuses `load_or_create_keypair`'s existing behavior exactly (a keypair is created once and never silently regenerated), the same as `main.py`/`run_api.py` always have.

**Capture input unchanged.** `run_demo.py` uses the exact same `Settings`-driven `CaptureSource` construction as `run_api.py` (`PCAP_PATH`/`CAPTURE_MODE`, defaulting to the committed `tests/fixtures/sample.pcap`) — no new demo fixture was introduced in this step; that is explicitly deferred to a later Phase 15 hardening step.

**Runtime independence from `cipher-frontend` is a tested property, not just a claim.** `web/` is a plain committed directory inside this repository; nothing in `run_demo.py` or `dashboard/spa.py` references `../cipher-frontend` or any path outside this repository at runtime. `cipher-frontend`, Node, npm, and Vite are build-time-only, developer-side concerns (see the release procedure above) — never a runtime dependency of `python run_demo.py`.

**Not implemented (as of this section; see Section 29):** HIGH-risk/isolation-triggering or MQTT-detected demo fixtures, any evaluation/latency/false-positive benchmark harness, browser auto-opening, `.exe`/PyInstaller packaging, a Windows batch launcher, and (per Section 27) any real hardware isolation backend.

---

## 29. Phase 15 Evaluation Addendum — Controlled Demo & Evaluation Harness

**Status:** the controlled evaluation, latency/false-positive/entropy/tamper-detection measurement, startup-time measurement, and `run_demo.py`'s default demo fixture are complete and verified, including a correction pass (below) that fixed three release/evaluation issues found after the first pass. `tests/fixtures/sample.pcap` is untouched throughout — every fixture described below is new and separate.

**CORE five-scenario evaluation vs. ADDITIONAL validation — never conflated.** The Execution Report's target is exactly 5 scenarios. `tests/fixtures/evaluation_manifest.py::CORE_EVALUATION_SCENARIOS` contains exactly those 5; MQTT protocol detection (`MQTT_SCENARIO`, a real coverage gap this phase closed) is a separate, clearly-labeled ADDITIONAL VALIDATION check, never folded into the "x/5" count. `evaluate_demo.py`'s output, its `data/evaluation/latest_results.json` (a top-level `core`/`additional` split), and every test file all preserve this distinction — an earlier draft of this harness incorrectly reported "5-scenario target -> 6/6," which has been corrected everywhere.

**Controlled, synthetic evaluation — not a real-world network validation.** Everything in this section runs `tests/fixtures/generate_evaluation_fixtures.py`'s deterministic, hand-constructed-but-wire-format-valid packets through the real, unmodified CIPHER pipeline (`fingerprint_packet` → `port_risk_for_protocol` → `assess_packet` → `should_isolate` → `NoOpIsolationBackend`, and `generate_report`/`verify_report` for tamper-detection). No QRS threshold, Isolation Forest policy, fusion rule, or Phase 14 enforcement policy was changed to make any scenario land where it does. All latency figures are explicitly measured on **controlled local synthetic/offline observations on the development machine running the harness** — never Raspberry Pi hardware or live-network conditions, which remain unmeasured until Pi integration. Any Isolation Forest output included reflects this project's own synthetically-trained model only, never a research-grade or real-world anomaly-detection accuracy claim.

**CORE: five evaluation fixtures, one packet each** (`tests/fixtures/evaluation_*.pcap`, expectations frozen in `CORE_EVALUATION_SCENARIOS`, re-verified against the real pipeline by `tests/fixtures/test_evaluation_fixtures.py` on every test run):

| scenario_id | mechanism exercised | detected protocol | QRS | category | isolation-eligible |
|---|---|---|---|---|---|
| `secure_modern_tls` | real TLS 1.3 ServerHello (`supported_versions` + `key_share` + RFC 7685 padding) | HTTPS | 2 | LOW | No |
| `legacy_tls` | real TLS 1.0 ClientHello, no `supported_versions` extension | HTTPS | 7 | HIGH | Yes |
| `weak_key_size` | real self-signed 513-bit RSA certificate inside a genuine TLS Certificate handshake message | HTTPS | 9 | HIGH | Yes |
| `plaintext_protocol` | real plaintext HTTP/1.1 GET request | HTTP | 6 | MEDIUM | No |
| `high_risk_enforcement` | real Telnet option-negotiation burst (max `port_risk`) | TELNET | 7 | HIGH | Yes |

Three of the five independently reach the raw-QRS≥7 isolation threshold via three genuinely different mechanisms (TLS version, key size, protocol exposure) — an honest emergent property of the frozen scoring formula, not something engineered to make exactly one scenario "the enforcement demo." `high_risk_enforcement` is the one `evaluate_demo.py` walks through end to end for the isolation demonstration, since it reaches HIGH via protocol exposure alone with no TLS/certificate involved at all.

**ADDITIONAL VALIDATION: the MQTT gap, closed without touching the detector.** The Phase 15 inspection found that `sample.pcap`'s pseudo-MQTT packet (`b"MQTT-CONNECT-PAYLOAD"` on UDP/1883) is not valid MQTT wire format and is classified `ProtocolType.OTHER` — not a detector bug, since `fingerprint.protocol._looks_like_mqtt_connect()` correctly requires the real MQTT fixed-header/remaining-length/protocol-name structure that packet never had. `build_mqtt_connect()` constructs a real MQTT 3.1.1 CONNECT packet (over TCP, not UDP — MQTT is TCP-based) that this genuinely recognizes as `ProtocolType.MQTT` (QRS 6, MEDIUM), verified by a focused test and reported by `evaluate_demo.py::run_mqtt_auxiliary_check()` — always as additional validation, never as one of the five core scenarios. `fingerprint/protocol.py` itself is unmodified.

**`weak_key_size`'s certificate is real but its RSA key is reconstructed from fixed, hardcoded prime literals, not generated at runtime** — `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key()` refuses `key_size < 1024`, but `rsa.RSAPrivateNumbers(...).private_key()` does not, so two fixed 256-bit primes (hardcoded in `generate_evaluation_fixtures.py`, never real key material for any actual use) build a genuine, self-signed, 513-bit-RSA X.509 certificate that `fingerprint.tls.extract_rsa_key_size()` parses for real via `cryptography.x509.load_der_x509_certificate()`. RSA PKCS#1v1.5 signing is itself deterministic given a fixed key and message, so the resulting DER bytes — and therefore this fixture — are exactly reproducible across runs.

**CORE: entropy targets, measured against the real `entropy/` implementation.** The Execution Report's "encrypted entropy > 7.5" and "HTTP entropy < 5" targets are evaluated by `evaluate_demo.py::measure_entropy_targets()` and `tests/fixtures/test_evaluation_fixtures.py`. "HTTP entropy" reuses the `plaintext_protocol` core scenario's own real GET request unchanged (measured 4.72, comfortably under 5). "Encrypted entropy" deliberately uses a **new, separate fixture** — `tests/fixtures/evaluation_encrypted_entropy.pcap`, a real TLS Application Data record (content type `0x17`) — rather than the `secure_modern_tls` ServerHello: a ServerHello is handshake *negotiation*, sent in cleartext even under TLS 1.3 (only `EncryptedExtensions` onward is actually encrypted), so its bytes are legitimately only moderately entropic and are not a faithful stand-in for "encrypted" traffic. Measuring naive Shannon entropy on a small byte sample systematically underestimates a source's true entropy (verified directly against real `os.urandom` output of matching sizes, which shows the identical convergence curve); at ~500 bytes — a realistic size for one encrypted chunk — the measurement converges to ~7.63, clearing the 7.5 target with margin. This is a genuine, defensible fixture-content choice (a differently-purposed fixture added, not the existing scenario's bytes padded to force a pass), not a change to the entropy algorithm itself (`entropy/engine.py` is untouched).

**CORE: controlled false-positive evaluation** (`tests/fixtures/evaluation_known_safe_set.pcap`, 10 packets, each a `secure_modern_tls`-style real TLS 1.3 ServerHello with a different deterministic seed): a known-safe observation counts as "flagged" iff its `final_category != LOW` — the exact same rule `reports/pdf_generator.py`'s `is_flagged_device()` already uses for report-generation eligibility. Measured rate: 0/10 (0%), against the Execution Report's <10% target.

**CORE: latency measurement** (`evaluate_demo.py`, `time.perf_counter()`, 50 repeated trials for a stable mean/p95/max — never a single noisy sample): "assessment latency" times exactly `assess_packet()` (packet ready → `DeviceAssessment` returned) across the five core scenarios, explicitly reported as measured **on controlled local synthetic/offline observations on this machine**; measured mean well under 1ms against the <500ms target. **ADDITIONAL: "software enforcement-decision/backend latency"** times `should_isolate()` + `NoOpIsolationBackend.isolate()` together on the `high_risk_enforcement` scenario and is labeled exactly that everywhere it's printed or stored — **never** "physical isolation latency": real physical network isolation latency remains unmeasured until Raspberry Pi hardware integration (Section 27). No production domain model gained a benchmark-only field; both measurements live entirely in `evaluate_demo.py`.

**CORE: tamper-detection demonstration** (`evaluate_demo.py::run_tamper_detection_demo()`) exercises both signing layers CIPHER actually has — `signing.sign_assessment`/`verify_signed_event` (assessment-level) and `reports.pdf_generator.generate_report`/`verify_report` (report-level) — entirely on an ephemeral, freshly-generated ML-DSA-44 keypair and a `tempfile.TemporaryDirectory()`, never the user's real `data/keys/` or `data/reports/`. 7/7 controlled tamper cases (tampered risk score, tampered signature, tampered hash [report layer], wrong public key, at both layers) are independently confirmed to fail verification — 100% is only ever printed when every case actually failed for real.

**CORE: isolation demonstration wording is exact, not paraphrased.** `evaluate_demo.py::run_isolation_demonstration()` prints `Isolation Decision: REQUIRED`, `Physical Enforcement: NOT PERFORMED`, and `Reason: <outcome.reason>` — reading `outcome.reason` directly off the real `IsolationOutcome`, never a second, hand-typed copy.

**CORE: startup-time measurement, re-measured after the presentation fixture became a committed asset** (`measure_startup.py`, separate from `evaluate_demo.py` so the pure in-process evaluation harness never itself spawns a server): launches `run_demo.py` as a real subprocess on port 5099 (never the normal default 5000), polls `GET /api/health` until 200 OK, and always terminates the subprocess in a `finally` block. Before the fixes below, startup measured ~6s but included a one-time ~50-60s fixture-generation cost whenever the presentation pcap didn't already exist on disk — a risk to the <30s target on a genuinely fresh clone. Re-measured after `demo_presentation.pcap` became a committed runtime asset: **~4s**, with no generation step in the path at all.

**Release/evaluation correction pass — three issues fixed:**

1. **The presentation fixture is now a committed runtime asset.** `run_demo.py` defaults to `tests/fixtures/demo_presentation.pcap` (sample.pcap's existing 3 MEDIUM packets, unchanged, plus one new LOW and one new HIGH packet), but every other evaluation `.pcap` is gitignored (`tests/fixtures/*.pcap`) and only ever regenerated for tests. Since `run_demo.py` is meant to work from a fresh clone with no prior `pytest` run, this specific file needed to be committed: `.gitignore` now has `!tests/fixtures/demo_presentation.pcap` immediately after the general `tests/fixtures/*.pcap` rule — an explicit, narrow exception, not a policy change for every generated pcap. `tests/fixtures/generate_evaluation_fixtures.py` remains the sole, deterministic provenance for its bytes; nothing was hand-edited.

2. **Runtime fixture use is now fully separate from test/dev fixture generation.** `run_demo.py` no longer imports `tests.fixtures.generate_evaluation_fixtures` at all (confirmed by a static AST-based test, the same precedent used elsewhere in this codebase) and never regenerates the presentation pcap at startup. `DEFAULT_DEMO_PCAP_PATH` is now a plain literal path local to `run_demo.py`. If the committed file is ever missing, `run_demo.py` fails immediately with an actionable message (`"CIPHER presentation data is missing.\nExpected: ..."`) — the same fail-fast pattern already used for a missing `web/` build — rather than spending ~50-60s regenerating it, which would have defeated the <30s target. `tests/conftest.py`'s own auto-generation fixture is unchanged and still covers `demo_presentation.pcap` as a safety net purely for the test suite (e.g. if the file is ever deleted locally); `run_demo.py` never imports or depends on `tests/conftest.py`.

3. **The five-scenario claim is now accurate everywhere.** See "CORE vs. ADDITIONAL" above — this was the fix for a real semantic bug (reporting "5-scenario target -> 6/6"), corrected in `evaluation_manifest.py`'s structure, `evaluate_demo.py`'s functions/output/JSON, `docs/SDD.md` (this section), and every test file.

**Results artifact.** `evaluate_demo.py` writes a full machine-readable result — `{"core": {...5 scenarios, entropy, latency, false-positive, tamper-detection, isolation demo, startup_seconds}, "additional": {...MQTT, enforcement-decision latency}}` plus a `timestamp` and `notes` — to `data/evaluation/latest_results.json`, already covered by the existing `data/*` `.gitignore` pattern. `results_path` is an optional parameter of `main()` (defaulting to that real path) specifically so tests can redirect it to a `tmp_path` instead.

**Reports for evaluation scenarios use the unmodified Phase 10 pipeline.** No PDF layout, field, or signing behavior changed. A `LOW`-category scenario is never passed to `generate_report()` in `run_demo.py`'s own run (`is_flagged_device()` already excludes it); `evaluate_demo.py`'s tamper-detection demo generates a report only for the HIGH `high_risk_enforcement` scenario.

**Not implemented (as of this section; see Section 30):** any real hardware isolation backend (Section 27, unchanged), browser auto-opening, `.exe`/PyInstaller packaging, a Windows batch launcher, and any benchmark against real (non-synthetic) network traffic.

---

## 30. Phase 15 Presentation-Hardening Addendum — Launcher, Preflight & Demo Guide

**Status:** complete and verified. No QRS/Isolation Forest/enforcement/REST/PDF/frontend-source change of any kind — this section is packaging and operational reliability only, layered entirely on top of the already-frozen `run_demo.py`.

**Three new entrypoints, no changes to the existing ones.** `main.py`, `run_api.py`, and `run_demo.py` are all untouched. `preflight.py` validates every runtime precondition without starting anything; `launch_cipher.py` runs that same preflight, starts `run_demo.py` as a real subprocess, waits for genuine readiness, and opens a browser only then; `Start CIPHER.bat` is the double-click entrypoint that resolves the project directory, prefers a project `.venv/`/`venv/` if one exists, and calls `launch_cipher.py`, keeping the console open afterward (`pause`) so a startup failure's message stays readable.

**`preflight.py`** runs seven checks — Python runtime, required imports (`importlib.import_module("run_demo")`, exercising the same import graph a real run would), Web UI (`web/index.html` + `web/assets/`, via the existing `dashboard.spa.validate_web_build`), Demo fixture (`tests/fixtures/demo_presentation.pcap`), Isolation Forest (the ML artifact), Signing keys, and Port 5000 — each returning a `CheckResult(name, status, detail)` with `status` exactly `"PASS"`/`"WARN"`/`"FAIL"`. It never starts the application, never regenerates a fixture, never trains a model, and never touches an existing key file. `run_preflight(project_root, host, port)` accepts overrides specifically so tests never touch the real checkout or the real port 5000.

**ML and signing-key checks mirror the already-approved runtime policy exactly, never inventing new rules.** Missing ML artifact → `WARN` ("Unavailable -- QRS-only mode"), never `FAIL` — `ml.loading.load_anomaly_detector`'s fail-open behavior (Step 12A addendum) is unchanged and this just reports it honestly. Signing keys: both present → `PASS` ("Existing"); neither present → `PASS` ("Will be generated on startup"); exactly one present → `FAIL`, quoting `signing.key_store.load_or_create_keypair`'s own frozen refusal (Phase 9 addendum) rather than restating a new one — the check reads `PUBLIC_KEY_FILENAME`/`SECRET_KEY_FILENAME` from `signing.key_store` directly so the two can never drift.

**Port check never kills anything.** `_check_port()` attempts to bind `127.0.0.1:5000` itself; on failure it reports `FAIL` with the literal message `"Port {port} is already in use.\nStop the existing CIPHER/server process and try again."` and does nothing further — confirmed by a static test that `preflight.py` never imports `subprocess`.

**`launch_cipher.py`'s readiness mechanism is pure HTTP polling, never subprocess-output scraping.** `run_demo.py`'s stdout/stderr are left connected directly to the console (no `PIPE`, nothing captured) — a real startup failure's message appears exactly as it would running `python run_demo.py` by hand. `wait_until_ready()` polls `GET /api/health` until 200, the process exits, or a 30s timeout elapses; only a genuine 200 makes `run()` print `"CIPHER ready at ..."` and call `webbrowser.open(...)` — never before.

**An earlier pass misdiagnosed an environment finding; this pass investigated it properly and corrected the record.** The initial hypothesis — that importing `ml/classifier.py`'s scikit-learn dependency under this machine's `venv/` caused the interpreter to relaunch itself — was **not assumed to be correct** and was re-investigated from first principles with direct process-level evidence (PID/PPID/`sys.executable` before and after, at multiple checkpoints through the entire `run_demo.py` startup sequence, plus a bisection down to a bare `print()` script). The scikit-learn/joblib/Flask-reloader theory was **disproven**: every import in `run_demo.py`'s chain (including `ml.classifier`'s scikit-learn import) runs in a single, unchanged process; Flask's reloader is confirmed off (`debug=False`, `use_reloader=False`, and Werkzeug's own startup banner always printed "Debug mode: off").

**Confirmed root cause:** on Windows, this venv's `Scripts/python.exe` is not a copy of the real interpreter — its embedded `OriginalFilename` metadata is literally `py.exe`, CPython's own official Windows "venv launcher," installed by the standard Python 3.12 Windows installer. On every invocation it reads `pyvenv.cfg` and spawns the actual base interpreter as a **child** process to do the real work, then waits for it and relays its exit code — standard, documented CPython behavior for **any** venv on Windows, reproduced even for a script that does nothing but `print()` a PID. It is unrelated to scikit-learn, joblib, multiprocessing, or Flask, and is not a sign of a broken or inconsistent environment — creating a fresh `.venv` would exhibit the identical launcher/worker pair, so no new environment was created. The launcher process was directly verified to wait for and correctly relay its child's exit, so `subprocess.Popen`'s handle already tracks the real lifecycle correctly for this reason; killing the tracked handle was independently re-confirmed to tear down the whole launcher+worker pair (Windows' job-object semantics propagate the kill).

`wait_until_ready()`'s `EXIT_GRACE_SECONDS` (5s) tolerance for a tracked process appearing to exit before health succeeds is **kept** as cheap, generic robustness — but is no longer documented as a scikit-learn workaround, since it isn't one. `run_demo.py`'s `app.run(...)` call now passes `debug=False, use_reloader=False` explicitly (previously implicit via Flask's defaults) so the "no reloader" guarantee is stated in code, not just observed. `launch_cipher.py` now prints one additional startup line, `Python: <resolved interpreter>`, so the actual interpreter in use is always visible without dumping `sys.path` or other developer diagnostics into normal startup output.

**Process lifecycle, verified manually end to end via a real `Start CIPHER.bat` run:** one double-click/command launches the app; the browser opens only after a real 200; `/`, `/dashboard`, `/devices`, `/network`, `/packets`, `/reports`, `/settings` all load; the HIGH device's PDF downloads; the LOW device's report route 404s; and killing the launched process tree (simulating a stop) leaves zero orphaned `python.exe` processes. Closing the browser never touches the server process — the two are fully decoupled (`webbrowser.open()` is fire-and-forget).

**Evaluation stays a separate, manual command.** `launch_cipher.py` prints `Evaluation command: python evaluate_demo.py` once CIPHER is ready but never invokes it — confirmed by re-running `evaluate_demo.py` after this work and observing byte-identical controlled results (5/5 core scenarios, 0% controlled false-positive rate, entropy/latency/tamper-detection figures unchanged).

**`docs/DEMO_GUIDE.md`** is the concise, presentation-day reference (pre-demo preflight, start/stop, the 8-step demo flow, and a troubleshooting table for every failure mode this section addresses) — it duplicates no architectural detail already covered here, only the operational sequence.

**Not implemented:** any real hardware isolation backend (Section 27, unchanged), `.exe`/PyInstaller packaging, an installer/updater framework, and automatic process-tree killing by port or by name (deliberately not built — see the port-check and shutdown notes above).

---

## 31. Pre-Raspberry-Pi Optimization Pass

**Status:** the two changes approved by the Pre-Pi efficiency audit's "B — ready after small optimizations" verdict are complete and verified. No architecture, QRS, risk fusion, REST/frontend, reports, enforcement, entropy, or logging behavior was touched.

**`ml/classifier.py::AnomalyDetector.predict_one()` no longer calls both `decision_function()` and `predict()`.** The audit measured `predict_one()` as the single most expensive per-packet operation (~10ms, ~350x every other stage combined) and confirmed, by reading the installed scikit-learn version's own source, that `IsolationForest.predict()` internally recomputes `decision_function()` and thresholds it at zero — meaning the prior code paid for the same expensive computation twice. `is_anomaly` is now derived directly from the already-computed `raw_decision < 0` — exactly, not approximately, equivalent to the removed `predict()` call, proven by 8 new tests in `tests/ml/test_classifier.py` that check both `is_anomaly == (decision_function(x) < 0)` and `is_anomaly == (predict(x) == -1)` against the real, unmocked, fitted model (never a mock), across handpicked inlier/anomaly cases and a parametrized sweep of real training-matrix rows. `anomaly_score`, `confidence`, and `AnomalyAssessment`'s shape are all completely unchanged. Measured on this Windows development machine: `predict_one()` mean dropped from ~9.75ms to ~5.03ms (~48% faster); full `assess_packet(..., anomaly_detector=...)` dropped from ~9.96ms to ~4.92ms (~51% faster) — consistent with removing one of two near-identical internal computations. **These percentages are Windows-only measurements; Raspberry Pi timing has not been measured and may differ.**

**`requirements.txt` is now pinned to the exact versions of the 593-test-verified development environment** (Flask, Scapy, scikit-learn, joblib, dilithium-py, cryptography, reportlab, python-dotenv, pytest, numpy), so Pi bring-up starts from a known-good set rather than whatever `pip install` resolves on the day. `scipy` is deliberately not listed — it is only a transitive dependency of scikit-learn, never imported directly by this project. **These pinned versions are the verified Windows/x86 development baseline only — they are not yet validated on Raspberry Pi/ARM64.** That validation (ARM wheel availability, build-from-source risk, any version-specific ARM behavior difference) happens during actual Pi bring-up, not here.

**A dependency baseline inconsistency was found and resolved before this pass was considered final.** The pins above came from this project's *base* Python install, which the 593→605-test suite has always actually run against — but this project's separate `venv/` (the one `Start CIPHER.bat` prefers for presentation) had silently drifted to different versions of four packages: `scikit-learn` (1.9.0 vs. the pinned 1.8.0), `numpy` (2.5.2 vs. 2.4.6), `reportlab` (5.0.1 vs. 5.0.0), and `python-dotenv` (1.2.3 vs. 1.2.2) — `flask`, `scapy`, `joblib`, `dilithium-py`, `cryptography`, and `pytest` matched exactly. Rather than assume either environment was "right," the pinned base versions were independently re-validated from scratch: a brand-new, empty virtual environment (`.venv-pi-validation/`, gitignored, temporary, never committed) was created, `pip install -r requirements.txt` alone (no manual additions) installed every direct dependency at exactly its pinned version, and **605/605 tests passed, `preflight.py` and `evaluate_demo.py` both behaved identically to the base-environment runs (same 5/5 scenarios, same QRS values, same entropy/tamper-detection figures), and the Isolation Forest `predict_one()` equivalence tests (Section 31 above) held** — confirming the pinned set is genuinely self-consistent and installable, not merely "whatever happened to already be present." (One test transiently failed on a timeout during the very first, cold-start run of this brand-new environment — `test_main_exits_zero_with_expected_output`, which spawns `main.py` as a real subprocess — and passed cleanly on every subsequent run; this was first-import/filesystem-cache coldness in a never-before-used environment, not a dependency or code defect.)

**`requirements.txt` is hereby the canonical dependency baseline; the older `venv/` is stale.** It is not deleted (a rebuild is a developer's own choice, e.g. immediately before the final presentation, via `python -m venv venv && venv\Scripts\python.exe -m pip install -r requirements.txt`), but it must not be treated as a source of truth for versions going forward, and **Raspberry Pi bring-up must create its own fresh environment from `requirements.txt` directly** — never by copying assumptions from, or attempting to reuse, this Windows `venv/`.

**Not implemented:** live capture, any hardware integration, any change to the two other flagged-but-optional audit findings (the duplicate `fingerprint_packet()` call in `pipeline/runner.py`, and the live-capture/EOF reporting question) — both remain exactly as the audit left them, deliberately out of scope for this deliberately small pass.

---

## 32. Phase 2A Addendum — Controlled Labelled Evaluation & Metrics Foundation

**Status:** complete and verified. **No change of any kind to the Quantum Risk Score formula, its weights, its category thresholds, the isolation threshold, the Risk Fusion rule, the Isolation Forest configuration or its training generator, packet fingerprinting, the entropy implementation, or the enforcement path.** This phase adds measurement only: one new package (`evaluation/`), one new labelled dataset, one new explicitly-invoked runner, and their tests. The only pre-existing file modified is `tests/conftest.py`, which gained one autouse fixture so the new gitignored pcap is generated on first use exactly like the Phase 15 fixtures.

**Purpose.** The paper reviewers asked for stronger quantitative validation. This phase supplies the defensible part of that: deterministic Quantum Risk Score **specification conformance**, and **controlled security classification** against an a-priori external rubric, both in QRS-only mode. Isolation Forest quantitative evaluation (anomaly scores, ROC-AUC), and CPU/RAM and Raspberry Pi hardware benchmarking, are deliberately **not** in this phase.

**The two kinds of ground truth are separate, and the security labels never come from CIPHER.** `tests/fixtures/labelled_evaluation_manifest.py` declares, per observation and before any packet is executed: (1) the expected per-component contributions, total score, category and isolation eligibility the frozen formula must produce; and (2) an `external_security_label` of SAFE / RISKY / EXCLUDED assigned from published standards — RFC 8996 (TLS 1.0/1.1 deprecated), RFC 8446 (TLS 1.3), NIST SP 800-52r2, and NIST SP 800-131A Rev. 2 (RSA ≥ 2048 bits). The label is never derived from the actual score, the expected score, a risk category, a fused category, or any anomaly signal. Labelling observations by the score under evaluation would make every resulting metric circular; this separation is what makes the classification figures mean anything.

**EXCLUDED is a real answer, not a gap.** 6 of 30 observations carry no binary label, and are carried through conformance reporting while being dropped from every confusion matrix: both TLS 1.2 ClientHellos (SP 800-52r2 permits TLS 1.2 with approved suites, and one passively captured packet does not establish the negotiated suite), both RSA ≥ 2048 certificate messages (the key length is acceptable, but a Certificate message carries no version field, so the surrounding configuration is undetermined), the encrypted Application Data record, and the opaque OTHER payload. Forcing a binary label on any of these would have meant inventing ground truth the standards do not supply for an isolated packet. Forward secrecy is likewise excluded from the rubric: `fingerprint_packet()` always reports `forward_secrecy=False`, so it is a constant across the whole dataset and cannot discriminate — reported as a known limitation rather than used as a criterion.

**The dataset deliberately does not reuse the Phase 15 known-safe fixture as its secure baseline.** That fixture puts an RFC 7685 `padding` extension into a *ServerHello* and fills it with high-entropy bytes; RFC 7685 padding is a ClientHello extension, its bytes are zero-filled, and a server does not echo it. The high-entropy filler also lifts measured entropy into the no-penalty band, which a real ServerHello of that size cannot reach. The Phase 15 fixture and its tests remain **untouched** for regression and continuity, but every TLS observation in the new dataset is built the way a real stack would send it — including a correctly zero-filled ClientHello padding variant, whose padding *lowers* measured entropy.

**Dataset composition** (30 deterministic observations, one uniquely-addressed packet each, joined to the manifest by source IP rather than packet order; `tests/fixtures/evaluation_labelled_set.pcap`, gitignored and regenerated like every other evaluation fixture):

| group | n | contents | external label |
|---|---|---|---|
| secure | 11 | realistic TLS 1.3: 3 ClientHello (X25519), 2 ClientHello (hybrid X25519MLKEM768), 2 zero-padded ClientHello, 2 ServerHello (X25519), 1 minimal ServerHello, 1 ServerHello (hybrid) | 11 SAFE |
| moderate-risk | 9 | 2 TLS 1.2 ClientHello, RSA-2048 and RSA-3072 certificates, 3 cleartext HTTP (GET, response, credential POST), 2 MQTT CONNECT without TLS | 5 RISKY, 4 EXCLUDED |
| high-risk | 8 | 2 TLS 1.0, 2 TLS 1.1, the existing deterministic 513-bit RSA certificate (reused unchanged), 3 Telnet negotiations | 8 RISKY |
| indeterminate | 2 | TLS Application Data, opaque unclassified payload | 2 EXCLUDED |

Totals: **11 SAFE, 13 RISKY, 6 EXCLUDED**, so binary metrics run on N=24. Two observations are not byte-reproducible by design — the RSA-2048 and RSA-3072 certificates use `rsa.generate_private_key()`, which is random — and are included anyway because their measured entropy (~7.39–7.49 and ~7.59–7.65 across sampled keys) sits far above the nearest 7.0 boundary, so their score is stable even though their bytes are not; a test asserts that margin on freshly generated keys. Per the approved decisions, no custom deterministic RSA prime generation was added, and the **RSA-1024 boundary case was omitted** rather than reported as unstable: its measured entropy of 6.998 sits 0.002 below the 7.0 boundary with a random key. Every other payload is byte-for-byte reproducible via the existing SHA-256-chain `_filler`, and no observation in the dataset sits within 0.1 bits/byte of an entropy boundary.

**`evaluation/metrics.py` is standard-library only** (no numpy, scikit-learn or pandas — enforced by an AST test), keeping it trivially ARM64-safe. **Undefined is never zero:** every ratio returns `None` when its denominator is 0, because a precision of `0.0` asserts the system made positive predictions and got them all wrong, while `None` correctly says it made none. F1 is computed from precision and recall specifically so it inherits their undefinedness, and is also `None` when both are defined but sum to 0. `sklearn.metrics` is used to cross-check the hand-written formulas **in tests only**. ROC-AUC is deliberately absent: an integer score over a designed scenario set gives no meaningful ROC curve, and the continuous anomaly score for which it would be valid belongs to the later ML phase.

**Measured results — Quantum Risk Score specification conformance (N=30): exact on every axis.** 30/30 exact score matches (mean absolute error 0.0, max 0), 30/30 per-component agreement on all five components independently, 30/30 protocol detection, 30/30 isolation-eligibility agreement, and a fully diagonal 3×3 category confusion matrix (8 LOW, 16 MEDIUM, 6 HIGH). Each observation's reported component decomposition is additionally cross-checked against the score the engine independently produced. **This measures implementation agreement with a frozen specification — it is not detection accuracy, and it is deliberately not evidence that the specification itself is correct.** Because the scenarios and the formula both derive from NIST-based criteria, conformance of this kind demonstrates correct, internally consistent implementation and nothing about external validity.

**Measured results — controlled security classification (N=24), two deterministic operating points, neither introducing a new threshold:**

| metric | `flagged_for_remediation` (final category ≠ LOW) | `high_risk_isolation_eligible` (raw QRS ≥ 7) |
|---|---|---|
| TP / TN / FP / FN | 13 / 8 / 3 / 0 | 6 / 11 / 0 / 7 |
| accuracy | 87.50% | 70.83% |
| precision | 81.25% | 100.00% |
| recall (sensitivity) | 100.00% | 46.15% |
| specificity | 72.73% | 100.00% |
| F1 | 89.66% | 63.16% |
| false-positive rate | 27.27% | 0.00% |
| false-negative rate | 0.00% | 53.85% |
| balanced accuracy | 86.36% | 73.08% |

Both halves of each trade-off are reported, and no threshold was adjusted to improve any figure. **The remediation point misses nothing externally risky (FNR 0%) but carries a 27.27% controlled false-positive rate**, from exactly three realistic secure TLS 1.3 observations — the two correctly zero-padded ClientHellos and the minimal ServerHello — each penalized by the entropy component for a low-entropy payload whose configuration is sound. This is a genuine, reproducible property of the frozen formula on realistically-shaped handshake packets: on short or zero-padded records, the entropy term substantially measures record length rather than cryptographic quality. It is reported, not suppressed, and it is the single most useful finding of this phase. **The isolation point is conservative exactly as designed** — 100% precision and a 0% false-positive rate, so nothing externally safe is ever isolation-eligible, at the cost of a 53.85% false-negative rate: cleartext HTTP, unencrypted MQTT and TLS 1.1 all score 6 and therefore fall below the raw-QRS ≥ 7 threshold, despite being RISKY under RFC 8996 and SP 800-52r2. For a physical-isolation action that is a defensible bias, and it is consistent with the frozen Phase 14 rule that isolation reads the raw score and never a fused category.

**QRS-only is enforced, not assumed.** `anomaly_detector=None` is passed at every call site in `evaluate_research.py`; a static test asserts the runner imports no `ml` module and never names `AnomalyDetector` or `load_anomaly_detector`, so its output cannot depend on whether a model artifact happens to exist on the machine running it. A per-observation test asserts `anomaly_assessment is None` and `final_category == risk_assessment.category` throughout. The fused category being identical to the QRS category here is a structural invariant of QRS-only mode (Section 19), reported as such and never as evidence about anomaly detection.

**Zero runtime impact.** Nothing on the runtime import graph reaches `evaluation/`, the labelled manifest or the runner — verified by an AST test over every entry point (`main.py`, `run_demo.py`, `run_api.py`, `run_live_demo.py`, `launch_cipher.py`, `preflight.py`, `measure_startup.py`) and every runtime package, with a companion test that fails if that file list is ever silently emptied. `evaluation/` also imports no `risk`, `ml`, `fusion`, `fingerprint`, `entropy` or `pipeline` module, so measurement can never contain the logic it measures. The runner writes only to the gitignored `data/evaluation/research/` (`latest_qrs_evaluation.json` plus a per-observation `qrs_observations.csv`), with `results_dir` overridable so tests redirect to `tmp_path`.

**Raspberry Pi compatibility: no new dependency, and `requirements.txt` is unchanged.** Everything added uses the standard library plus the already-pinned scapy/cryptography (fixture generation only) and, in tests only, scikit-learn. `psutil` was considered for the CPU/RAM work and deliberately not added, since that benchmarking is not part of this phase.

**Test count: 649 → 1021** (+372: 41 metrics, 301 labelled-fixture/manifest, 30 runner). **1020 pass.** One pre-existing failure is unrelated to this phase: `tests/reports/test_pdf_generator.py::test_no_pdf_left_in_the_real_default_output_directory` is a sentinel asserting `data/reports/` holds no `CIPHER-*.pdf`, and that directory contains 24 PDFs left by earlier manual `run_demo.py`/`main.py` runs (newest dated 2026-09-22, predating this work). It fails in isolation with none of this phase's code loaded; clearing that directory resolves it, and nothing here writes to it.
**Since resolved, with no code change.** Those pre-existing report artifacts were subsequently removed from `data/reports/`, and the sentinel passed again on the next run without any change to source, tests, thresholds or configuration — confirming the failure was environmental (stale files in a gitignored output directory) and never a defect. The current post-Phase-2C baseline is **1192 passed, 0 failed**.

**Not implemented (deliberately, per the approved scope):** Isolation Forest quantitative evaluation of any kind, ROC-AUC, CPU/RAM measurement, throughput, packet-processing latency benchmarking, Raspberry Pi hardware measurement, and any repair of the Isolation Forest train/serve feature mismatch the Phase 15 audit documented — which remains an observed experimental result, untouched.

---

## 33. Phase 2B Addendum — Quantitative Evaluation of the Existing Isolation Forest

**Status:** complete and verified. **Measurement only.** No change of any kind to `ml/dataset.py`, `ml/classifier.py`, `ml/train.py`, the Isolation Forest's parameters, the feature schema, the Quantum Risk Score, the fusion rule, any threshold, or the production pipeline. Nothing was tuned, retrained differently, repaired or redesigned, and the train/serve mismatch the Phase 15 audit found remains untouched — it is now quantified instead.

**The model under evaluation is fitted in memory, never loaded from the artifact.** `ml/artifacts/anomaly_detector.joblib` is untracked, absent on a fresh clone, and the copy on the development machine was pickled by scikit-learn 1.9.0 while `requirements.txt` pins 1.8.0 (it loads with an `InconsistentVersionWarning`). Depending on it would make every figure below unreproducible. `evaluate_research.build_in_memory_detector()` instead regenerates the frozen training matrix from `ml/dataset.py` at the frozen seed and fits the frozen `AnomalyDetector` on it. Recorded with every run: scikit-learn 1.8.0, numpy 2.4.6, `contamination=0.05`, `random_state=42`, matrix shape (190, 12), `n_estimators=100`, `offset_=-0.6269`, and the 12 feature names. A static test asserts the runner contains no path that could read or write an artifact (no `joblib`, no `load_anomaly_detector`, no `model_path`, no `.save`/`.load` call), and a further test asserts the on-disk artifact's bytes are unchanged by a run.

**ROC-AUC is confined to the continuous score, and confidence is never treated as a probability.** `evaluation/metrics.py::roc_auc` implements the Mann-Whitney form, `[#(s⁺>s⁻) + 0.5·#(s⁺=s⁻)] / (P·N)`, by direct pair enumeration, returns `None` when either class is absent, and reports `n_positive`, `n_negative`, `n_pairs` and `tied_pairs` alongside the value so an AUC leaning on the tie convention can be read as such. It rejects boolean scores outright, which is exactly the misuse of passing `is_anomaly` where `anomaly_score` belongs. It is computed only over `anomaly_score = -decision_function`, never over `is_anomaly`, a risk category, or `confidence`. No calibration metric (Brier score, log loss, reliability) is computed anywhere, because Isolation Forest is not a probabilistic estimator; a test asserts no such key appears in the report. `confidence` is reported under the field name `confidence_not_a_probability`, and a test confirms it is monotone in `anomaly_score` and therefore carries no additional ranking information.

**Held-out set (Section A) reuses `ml/dataset.py` unmodified, with structural labels.** `tests/fixtures/ml_heldout_set.py` calls the existing generator at seed **1042** (training is 42) for 180 normal + 10 injected outlier rows. Labels come from which distribution the generator drew each row from, fixed before inference; tests verify the row-to-distribution correspondence independently from the feature *values* (entropy band, key size, protocol one-hot), so the labels do not rest on an unchecked assumption, and verify no held-out row appears in the training matrix.

### Section A — synthetic feature-distribution evaluation (N=190)

Perfect on every axis: TP=10, TN=180, FP=0, FN=0; accuracy, precision, recall, specificity, F1 and balanced accuracy all 100%; FPR and FNR both 0%; **ROC-AUC 1.0000** over 1800 pairs with zero ties; 190/190 distinct vectors. Anomaly scores separate cleanly with a gap: outliers +0.0335 to +0.1363, normals −0.1955 to −0.0156.

**This is a feature-level result and nothing more.** The two synthetic distributions do not overlap on entropy at all (a test asserts `outlier_max < normal_min`), so this measures that Isolation Forest can separate two disjoint synthetic clusters — a property of the generated data at least as much as of the model. It is **not** real packet accuracy and **not** real network accuracy, and must never be reported as either.

### Section B — pipeline-extracted controlled evaluation (N=24 binary, 30 total)

Feature vectors are **captured as `assess_packet()` hands them to the model**, via a transparent recording proxy that delegates to the real detector. Nothing is hand-constructed: a static test asserts the runner never writes `DeviceFeatures(`, and another asserts the recorded objects re-vectorize to exactly the reported values. This is a stronger guarantee than rebuilding features alongside and hoping they agree.

| metric | value |
|---|---|
| TP / TN / FP / FN | 13 / 1 / 10 / 0 |
| accuracy | 58.33% |
| precision | 56.52% |
| recall (sensitivity) | 100.00% |
| specificity | 9.09% |
| F1 | 72.22% |
| false-positive rate | 90.91% |
| false-negative rate | 0.00% |
| balanced accuracy | 54.55% |
| **ROC-AUC** | **0.9371** (13 positive, 11 negative, 143 pairs, 0 tied) |

**The central finding of this phase is the gap between those two facts: discrimination is high, the operating point is wrong.** An AUC of 0.9371 says the anomaly score *ranks* externally-risky observations above externally-safe ones well — SAFE scores run −0.0093 to +0.0255 (median +0.0088) against RISKY +0.0203 to +0.1068 (median +0.0623). But `is_anomaly` thresholds that score at zero, and the zero point was fixed by `offset_` during training on synthetic vectors that look nothing like pipeline vectors. The result is that 10 of 11 SAFE observations fall on the anomalous side, giving a 90.91% controlled false-positive rate and 9.09% specificity. The single SAFE observation the model does not flag is `tls13_server_hello_hybrid_pq`, the largest and highest-entropy secure record in the set — the one that most resembles the training-normal distribution. The model is therefore **not** "randomly wrong"; it is systematically mis-thresholded for the vectors CIPHER actually produces. Stating only the AUC would overstate the model, and stating only the specificity would understate it; both belong in the paper.

All 13 RISKY observations are flagged (recall 100%, FNR 0%), which on a set where 23 of 24 observations are flagged carries little information. Of the 6 EXCLUDED observations, 3 are flagged: both TLS 1.2 ClientHellos (+0.0131) and the opaque payload (+0.0474); the two strong-RSA certificates (−0.0381, −0.0357) and the encrypted record (−0.0165) are not.

### Train/serve feature-distribution comparison

Per-feature summaries for `training_normal` (180), `training_outlier` (10), `pipeline_safe` (11), `pipeline_risky` (13) and `pipeline_excluded` (6), reported in the JSON and in `ml_feature_distribution.csv`. Three divergences are structural and fully explain Section A passing while Section B mis-thresholds:

| feature | training normal | pipeline SAFE | pipeline RISKY |
|---|---|---|---|
| `key_size_observed` zero-fraction | 0.00 | **1.00** | 0.92 |
| `key_size` median | 3072 | **0** | 0 |
| `forward_secrecy` zero-fraction | 0.17 | **1.00** | 1.00 |
| `shannon_entropy` median | 7.48 | 6.33 | 4.97 |
| `packet_size` median | 863 | 319 | 129 |

1. **Every training row carries both a TLS version and a key size; no real packet can.** A single packet is a Hello *or* a Certificate, and under TLS 1.3 the certificate is encrypted. So `key_size_observed` is 0 for 100% of pipeline SAFE vectors and 0% of training rows — a combination the forest never saw, and `key_size=0` sits *below* even the outlier range of 512–768.
2. **`forward_secrecy` is 0 for 100% of all pipeline vectors**, because `fingerprint_packet()` always reports False, while 83% of training-normal rows have it set. Every real observation therefore looks like the training minority.
3. **Entropy and payload length are both systematically lower** than training-normal, because handshake records are short and Shannon entropy is bounded by log2 of the payload length. A 127-byte ServerHello cannot reach the 7.0–8.0 band the generator drew normals from.

### Section C — QRS-only versus fused, paired on the same 30 observations

Escalated 20/30, unchanged 10. **10 externally SAFE observations were incorrectly escalated** (`tls13_client_hello_x25519_a/b/c`, `tls13_client_hello_hybrid_pq_a/b`, `tls13_client_hello_zero_padded_a/b`, `tls13_server_hello_x25519_a/b`, `tls13_server_hello_minimal`). 7 externally RISKY observations were escalated (3 HTTP, 2 MQTT, 2 TLS 1.1) — but all 7 were **already flagged** under QRS-only, so no remediation decision changed.

Remediation flagging (`final_category != LOW`), paired on N=24:

| metric | QRS-only | QRS + Isolation Forest | delta |
|---|---|---|---|
| TP / TN / FP / FN | 13 / 8 / 3 / 0 | 13 / 1 / 10 / 0 | — |
| accuracy | 87.50% | 58.33% | −29.17 pp |
| precision | 81.25% | 56.52% | −24.73 pp |
| recall | 100.00% | 100.00% | 0 |
| specificity | 72.73% | 9.09% | −63.64 pp |
| F1 | 89.66% | 72.22% | −17.44 pp |
| false-positive rate | 27.27% | 90.91% | +63.64 pp |
| balanced accuracy | 86.36% | 54.55% | −31.82 pp |

**The paired measurements do not support any claim that the existing Isolation Forest improves CIPHER.** Six metrics worsen, none improves, and recall was already saturated at 100% with no headroom to gain. The runner computes this verdict from the deltas rather than asserting it in prose, and a test fails if the verdict ever claims an improvement the numbers do not show.

**Physical-isolation invariant verified.** Eligibility is identical with and without ML: the same 6 devices, no mismatches. This is checked three ways — through the report, observation-by-observation against the real `should_isolate()`, and by a test confirming that observations the model escalated to HIGH while scoring under 7 remain ineligible. `enforcement.decision.should_isolate()` reads the raw score and never `final_category`, so an ML-only escalation can never trigger a physical action. Quantum Risk Scores and categories are also bit-identical with the model attached.

### Scope, outputs and limitations

**Outputs** (all gitignored): `data/evaluation/research/latest_ml_evaluation.json`, `ml_observations.csv` (per observation: labels, score, category before and after fusion, and all 12 feature values), and `ml_feature_distribution.csv`. Phase 2A's `latest_qrs_evaluation.json` and `qrs_observations.csv` are unchanged, and a test asserts Phase 2A's figures are still produced strictly QRS-only.

**Limitations that belong in the paper.** N=24 with an 13/11 split makes the AUC's confidence interval wide; a single ranking swap moves it by about 0.008, so 0.9371 should not be quoted as a precise value. The RISKY cohort also correlates with low entropy and short payloads, which is partly what the model keys on, so some of the ranking ability is confounded with the label definition rather than being independent evidence of anomaly detection. Section A's perfection reflects non-overlapping synthetic distributions. And every figure here is a controlled, deterministic synthetic/offline measurement — never real-world detection accuracy, production accuracy, general IoT accuracy, or a network-wide measurement.

**Test count: 1021 → 1105** (+84: 22 ROC-AUC/value-summary, 16 held-out set, 46 Phase 2B runner). **All 1105 pass.** The `data/reports/` PDF sentinel that failed during Phase 2A now passes because that directory is empty; nothing in either phase writes to or deletes it.

**Not implemented (deliberately, per the approved scope):** any change to the model, its features, its training data or its threshold; any alternative or additional ML algorithm; CPU/RAM benchmarking; throughput and packet-processing latency benchmarking; and Raspberry Pi hardware measurement.

---

## 34. Phase 2C Addendum — Controlled Offline Performance Benchmark

**Status:** complete and verified on Windows; Raspberry Pi figures deliberately **not yet collected** (the code is written to run there unchanged, and will be measured by pulling this branch onto the Pi). **Performance only.** No change to the Quantum Risk Score, the Isolation Forest, the fusion rule, feature extraction, packet parsing, any threshold, enforcement, or report content.

**A separate entry point, `evaluate_performance.py`.** `evaluate_research.py` answers "is the output correct" and must stay cheap and deterministic; benchmarking needs repetition counts, a warm-up discipline, subprocess launches, an optional long-running mode and a CLI. Merging them would force every correctness run to carry benchmark machinery. The measurement primitives live in `evaluation/benchmark.py`, standard-library only (an AST test asserts it imports nothing beyond `platform`, `statistics`, `sys`, `time`, `tracemalloc`, `resource`, `typing`), so **no new dependency was added and `requirements.txt` is unchanged** — notably no `psutil`.

**Methodology.** Every benchmark runs over the Phase 2A controlled labelled dataset (30 deterministic offline packets), **read from disk once before any timing begins**, so no latency figure includes file I/O or pcap parsing; device resolution and port-risk lookup are also hoisted out of the timed region. Timing uses `time.perf_counter_ns()`, with 2 untimed warm-up calls per packet and then 30 timed repetitions per packet, giving n=900 per latency benchmark. Reported for each: n, mean, median, p95, p99, min, max and standard deviation. `p99` is withheld below 100 samples, where a nearest-rank p99 is merely the maximum. The percentile convention matches the project's existing `evaluate_demo.py` helper rather than introducing a second definition. QRS-only and QRS+Isolation Forest are measured over the same packets in the same order, so **ML overhead is a paired per-observation difference**, not a difference of independent means.

### Measured results — Windows development machine

Platform recorded with the results: Windows 11 (10.0.26200), AMD64, 64-bit, Intel64 Family 6 Model 186, CPython 3.12.0, scikit-learn 1.8.0, numpy 2.4.6.

| benchmark | n | mean | median | p95 | p99 | max |
|---|---|---|---|---|---|---|
| QRS-only assessment | 900 | 0.0432 ms | 0.0304 ms | 0.0889 ms | 0.1111 ms | 0.1432 ms |
| QRS + Isolation Forest assessment | 900 | 4.9397 ms | 4.7349 ms | 6.0949 ms | 6.7114 ms | 7.3856 ms |
| **Incremental ML overhead (paired)** | 900 | **4.8965 ms** | 4.7013 ms | 6.0531 ms | 6.6367 ms | 7.3410 ms |
| Full pipeline, QRS-only | 900 | 0.0476 ms | 0.0372 ms | 0.0936 ms | 0.1006 ms | 0.1946 ms |
| Full pipeline, with Isolation Forest | 900 | 5.0185 ms | 4.7214 ms | 6.1246 ms | 6.9617 ms | 62.8954 ms |
| Software enforcement decision | 900 | 0.0005 ms | 0.0002 ms | 0.0017 ms | 0.0019 ms | 0.0095 ms |
| Report generation (signed 3-page PDF) | 20 | 53.8097 ms | 48.3207 ms | 83.5158 ms | n/a | 94.8502 ms |
| Startup (subprocess, cold) | 3 | 3.352 s | — | 3.398 s | — | 3.398 s |

**Isolation Forest inference dominates per-packet cost by roughly two orders of magnitude**: 4.90 ms of added latency against a 0.043 ms deterministic path, and it was slower in **900 of 900 paired observations**. Taken with Phase 2B — where fusion improved no controlled remediation metric — the model currently costs about 114x the deterministic path's latency while degrading measured classification on this controlled set. That is a finding for the paper, not a change made here.

**Throughput** (labelled *single-threaded controlled offline throughput*, never network throughput, line-rate performance or production capacity): 21,604.6 assessments/s QRS-only, versus 204.9 assessments/s with the Isolation Forest attached.

**Process CPU utilization**: 0.983 (98.3% of one logical core) QRS-only and 0.987 with the model — consistent with a single-threaded CPU-bound workload. This is process CPU utilization where 1.0 is approximately one logical core fully busy, **never whole-system CPU usage**.

**A real methodological defect was found and fixed during this phase.** The first implementation measured CPU over whichever interval the requested pass count happened to take. For QRS-only that was ~23 ms, and it produced a ratio of **1.387** — impossible for single-threaded work, and an artifact of Windows' `GetProcessTimes` updating on a ~15.6 ms scheduler tick. Two corrections: the throughput/CPU interval now runs to a minimum wall-clock floor (default 1.0 s), extending the pass count as needed and reporting the actual count; and `cpu_utilization()` now carries the clock resolution, the minimum reliable interval and a `reliable` flag, with an **absolute 0.25 s floor** because the resolution `time.get_clock_info()` advertises (sub-microsecond on Windows) badly understates the platform's real CPU-time accounting granularity. Under-sampled ratios are now printed as `[indicative only — interval too short]` rather than reported as fact.

**Memory.** Peak RSS uses `resource.getrusage(RUSAGE_SELF).ru_maxrss`, with a unit conversion helper that is unit-correct per platform — **KiB on Linux (so ×1024 on the Raspberry Pi)**, already bytes on macOS, and `None` on anything else rather than a guess; getting this wrong misreports memory by three orders of magnitude, so it is tested directly. On Windows the standard library exposes no reliable RSS figure, so it is reported as **not available with a stated reason** rather than adding a dependency for one number; the Pi run will populate it. Python heap peak is `tracemalloc`, measured in a **separate pass** because tracemalloc materially slows what it observes, and it therefore yields no timing: 0.132 MiB for one pass over the dataset, explicitly Python-managed allocations only (excluding interpreter overhead and numpy's C buffers).

**Startup reuses `measure_startup.measure_startup()` unchanged**, so the boundary is not redefined: launching `python run_demo.py` as a subprocess on port 5099 with a temporary cwd, polling `GET /api/health` until it first returns 200 OK — covering interpreter start, all imports, key and model loading, pcap processing and Flask binding the port, plus the 0.1 s poll granularity. A test asserts this module imports no HTTP or subprocess machinery of its own, so no competing definition can drift in. A startup failure is recorded in an `error` field rather than aborting the run.

**Report-generation latency** writes into a `tempfile.TemporaryDirectory()` with an ephemeral keypair and a distinct report id per repetition, so a user's real `data/reports/` is never touched — asserted by a test that compares that directory's contents before and after.

**Optional sustained run**, off by default and never executed by pytest: `--stability-iterations N` or `--duration-seconds N` repeatedly processes the deterministic packet set, reporting per-pass latency, sustained throughput, process CPU and a **drift comparison between the first and last tenth of the run** — which is what will expose thermal throttling on the Pi, where a whole-run mean would average it away. Verified working: 60 passes, 1800 assessments in 8.83 s, 203.9 assessments/s sustained, first-window 146.4 ms against last-window 145.0 ms, so no drift on this machine.

**Raspberry Pi readiness.** Nothing is hard-coded — a test asserts the source contains no Windows or Pi path, CPU model, architecture string or interface name. Every platform value is read at runtime and recorded in the results JSON (`system`, `release`, `machine`, `architecture`, `processor`, `platform`, Python, scikit-learn and numpy versions), and the CSV carries platform rows, so a Windows run and a Pi run can be concatenated and compared directly. The hostname is deliberately not recorded, only a boolean that one exists.

**Outputs** (gitignored): `data/evaluation/research/latest_performance.json` and `performance_metrics.csv` (one metric per row, for cross-platform concatenation).

**Limitations.** These figures are **load-sensitive on a shared desktop**: an earlier run of the same benchmark on this machine measured QRS+IF at 16.58 ms mean against 4.94 ms in the final run, a 3.4x spread driven entirely by machine state, with QRS-only moving in proportion. Absolute values should therefore be read as one machine under one load, while the *ratio* between QRS-only and QRS+IF held across both runs. The full-pipeline maximum of 62.9 ms is a single scheduling outlier, which is why median and p95 are reported alongside the mean. Report generation at n=20 has no meaningful p99. Startup at n=3 is a small sample, chosen because each measurement launches a real subprocess. Peak RSS is unavailable on Windows. And **physical isolation latency remains unmeasured**: no hardware enforcement backend exists, so the enforcement figure above times only the software decision and the NoOp backend, and must never be presented as network isolation latency.

**Test count: 1105 → 1192** (+87: 46 benchmark primitives, 41 benchmark runner). **All 1192 pass.** No long-running benchmark executes in pytest: every test uses 1–5 repetitions, stubs the startup subprocess, and bounds the sustained run at 2 iterations or 0.2 s.

**Not implemented (deliberately):** Raspberry Pi measurements, multi-threaded or concurrent throughput, live-capture performance, network-level measurement, and any change to the scoring, model or enforcement behavior being measured.

---

## 35. Phase 3A Addendum — Isolation Backend Contract (pre-enforcement)

**Purpose: settle the contract, not the firewall policy.** Phase 3A hardens the existing isolation abstraction so a real Linux backend can be added on the Raspberry Pi later *without touching the CIPHER pipeline*. Nothing about detection, scoring, fusion, reporting or the REST contract changed, and no firewall command exists anywhere in the codebase.

**Unchanged and re-asserted by test.** `enforcement.decision.should_isolate()` still compares the raw, deterministic `risk_assessment.risk_score` against `settings.risk_isolation_threshold` (default 7) and still never reads `final_category` — an Isolation-Forest/fusion escalation alone can never cause isolation (Section 27). `pipeline/runner.py` is unmodified: same per-packet enforcement timing, same one-attempt-per-device-per-run set, same fault isolation. Composition roots (`main.py`, `run_api.py`, `run_demo.py`, `run_live_demo.py`) are unmodified and still construct `NoOpIsolationBackend()` explicitly; backend selection remains a composition-root decision, never platform-sniffing inside `enforcement/` or `pipeline/`.

**`IsolationOutcome` gained one field: `backend: str`** (default `"unknown"`, declared last so every existing positional construction keeps working — asserted by test). This completes the result contract the Pi work needs: `requested`, `enforced`, `backend`, `reason`. Without `backend`, an audit log cannot distinguish a deployment that deliberately does not enforce (Windows, `backend="noop"`) from a real enforcing deployment whose attempt failed (`backend="linux"`, `enforced=False`). `IsolationOutcome` is still ephemeral, still lives in `enforcement/` and not `models/`, and is still absent from the PDF and REST contracts — a test now statically asserts that no module under `models/`, `reports/` or `dashboard/` imports `enforcement` at all.

**`IsolationBackend.restore(device_ip)` was added as a concrete, non-abstract default**, not an abstract method. `isolate()` remains the only abstract member, so every existing backend and test double stays instantiable unchanged. The default implementation enforces nothing and says so (`requested=True`, `enforced=False`, reason naming restoration as unsupported). This places the *seam* for un-isolation on the interface — so a future backend can override it without any caller changing shape — while still refusing to invent restoration policy. Nothing in CIPHER calls `restore()`.

**`enforcement/command_runner.py` — the injectable execution seam.** `CommandRunner.run(argv) -> CommandResult`, where `CommandResult` carries `command`, `executed`, `exit_code`, `stdout`, `stderr` and a `succeeded` property that is true only when the command *actually ran* and exited 0 — "exit code 0 from a process that never started" must never read as success, the same honesty rule `enforced` exists for. The only implementation in this phase, `UnavailableCommandRunner`, never spawns a process and returns `executed=False` with an explanatory reason. `run()` never raises for an ordinary failure (missing binary, non-zero exit, insufficient privilege).

**`enforcement/linux_backend.py` — the location, wired but inert.** `LinuxIsolationBackend` is a full `IsolationBackend` whose two policy-bearing parts are both injected: a `RuleBuilder` (`Callable[[str], Sequence[Sequence[str]]]` — what to run, one argv per command so a two-rule policy needs no interface change) and a `CommandRunner` (how to run it). Both defaults are deliberately non-functional: the default rule builder, `unfrozen_rule_builder`, raises `IsolationPolicyNotFrozenError`, and the default runner is `UnavailableCommandRunner`. Constructing the backend with no arguments, on any platform, therefore yields `requested=True, enforced=False` with a reason naming the unfrozen policy — it cannot reach a firewall.

`isolate()` never raises. A raising rule builder, an empty command list, a raising runner, and a command that ran but exited non-zero are all reported identically and honestly: `enforced=False` plus a `reason`. `enforced=True` is claimed only when *every* constructed command actually executed and succeeded.

It lives in its own module rather than in `backends.py` for two reasons: `backends.py` is statically asserted to contain `NoOpIsolationBackend` as its only concrete backend and to import neither `subprocess` nor `os`, and a Windows deployment never needs to import the Linux module at all. All three `enforcement/` modules are statically asserted to import neither `subprocess` nor `os`, and `linux_backend.py` is additionally asserted to contain **no argv string-list literal of any kind** — a machine-checked guarantee that no firewall command is embedded there, not even a placeholder.

**(Superseded by Section 38, which freezes this policy as iptables + a CIPHER-owned chain.)** Deliberately still unfrozen at the time of Phase 3A, to be decided on the Pi once the controlled enforcement topology is fixed: which interface the rule applies to (wlan0 is management, wlan1 is the monitor-mode AR9271, neither is a forwarding path), IP vs. MAC enforcement, `FORWARD` vs. `INPUT`/`OUTPUT`, nftables vs. iptables, the gateway/NAT topology the Pi would have to own to enforce at all, `DROP` vs. `REJECT`, duplicate-rule and restoration semantics, and the privilege model. Those arrive later as one `RuleBuilder` plus one executing `CommandRunner` — not as edits to CIPHER's pipeline.

**Also not implemented, deliberately:** deauthentication, Wi-Fi credential handling, WPA/WPA2/WPA3 decryption, any institutional firewall change, isolation status in the PDF or REST contract, and any new configuration setting for backend selection.

**Test count: 1228 → 1278** (+50 collected cases from 46 test functions: 8 command-runner, 20 Linux-backend, 18 end-to-end backend-contract). **All 1278 pass.** No existing test was weakened, changed or removed. Windows remains non-enforcing, and the contract suite additionally forbids process spawning (`subprocess.Popen/run/call/check_call/check_output`, `os.system/popen/execv/spawnv`) for the duration of a full high-risk pipeline run.

---

## 36. Phase 3B Addendum — Isolation State Propagation

**Purpose.** Make the result of an isolation attempt visible through the existing system — API, dashboard, signed report — so the autonomous demo can state truthfully what was *requested*, what was *enforced*, by which backend, and why. No firewall command is implemented in this phase; the raw-QRS ≥ 7 eligibility rule, the QRS weights/thresholds, Isolation Forest, the fusion rule, and the model artifacts are all untouched.

**Chosen design: extend DeviceAssessment, not a parallel registry.** `DeviceAssessment` gained one optional field, `isolation: Optional[IsolationStatus] = None`, declared last with a default so every pre-existing construction site (the only production one is `fusion.fuse_assessments`) keeps working unchanged. Attaching it here means isolation state travels the paths that already exist — `run_capture()` → `ApplicationState` → serializers → REST, and `to_dict()` → canonical JSON → Dilithium signature → PDF — with no new persistence, no `DeviceRegistry`, and no database. A parallel isolation registry would have needed its own lifecycle, its own API plumbing, and its own way into the signed payload, for no gain.

**`models.isolation_status.IsolationStatus`** (`requested`, `enforced`, `backend`, `reason`, `requested_at`, `enforcement_capable`) is the models/ projection of `enforcement.backends.IsolationOutcome`, converted by `IsolationOutcome.to_status()`. Two types, one direction of dependency: `enforcement/` already imports `models/`, and `models/` must never import `enforcement/` (statically asserted). It deliberately omits `device_ip` and `risk_score` — both already exist on the surrounding assessment, and two copies could disagree.

**`enforcement_capable` is what keeps the display honest.** `enforced=False` alone is ambiguous: it could mean "this deployment does not enforce at all" (Windows/NoOp) or "a real backend tried and failed". The flag is a class attribute on `IsolationBackend` — `False` by default (a capability must be opted into), `False` on `NoOpIsolationBackend`, `True` on `LinuxIsolationBackend` — carried into the outcome and the status. It is the only thing separating `"Requested / not enforced"` from `"Failed"` in `IsolationStatus.status_label`, whose four values (`"Not requested"`, `"Requested / not enforced"`, `"Enforced"`, `"Failed"`) are exported as constants so no display layer re-derives the logic.

**Isolation is tracked per device, not per packet — and this is load-bearing.** `run_capture()` holds a per-run `isolation_by_ip: Dict[str, IsolationStatus]` (local state, exactly like the existing `devices`/`representatives`/`enforcement_attempted_ips`) and attaches each entry to that device's retained representative after EOF, in `_attach_isolation_state()`. The reason is representative selection: `_is_stronger()` breaks a category+score tie on the later `assessed_at`, and repeated identical high-risk packets from one device tie exactly that way — so an outcome attached to the single triggering assessment would be silently erased the moment a later packet displaced it. Recording per IP makes that loss impossible regardless of packet count or order. A dedicated test reproduces precisely that scenario.

**Enforcement timing and once-per-device semantics are unchanged.** The backend is still called inside `_process_packet()`, immediately after `assess_packet()`, still at most once per device per run, still marked attempted before the call. Only the *recording* of the result is new. Attachment happens after EOF but **before** the report-generation loop, so the enforcement result is rendered into the PDF and covered by its signature.

**A raising backend is recorded, never fabricated as success.** A backend that returns a non-enforced outcome is recorded from that outcome. A backend that *raises* produces no outcome of its own, so the runner records the attempt as `requested=True, enforced=False` with the exception text as `reason` and the backend's own name and capability flag. `enforced` is never synthesized as `True`; the only thing synthesized is an honest record that an attempt was made and failed. The existing per-packet fault isolation is unchanged — the run continues and the assessment is still retained.

**API: one additive sub-object, always present.** `serialize_device_summary()` (and therefore `serialize_device_detail()`) gained `"isolation": {requested, enforced, backend, reason, requested_at, enforcement_capable, status}`. It is always present so a client never branches on a missing key; a device that was never eligible reports `requested=False` with null backend/reason/timestamp and `status: "Not requested"`. No existing field changed, moved, or was removed. `dashboard/` still imports no enforcement module — `status` comes off the model. The one existing test with an exact-key assertion (`tests/dashboard/test_devices.py::_SUMMARY_KEYS`) was extended by the single new key; the assertion remains exact and was not relaxed.

**Dashboard: the display contract, not a redesign.** `web/` is a committed, pre-built React production bundle with no source in this repository (see Section 30), so no component can be edited here. The compact status is therefore delivered where this codebase can own it: the API emits the ready-to-render `status` label plus `enforcement_capable`, so the four states (`Not requested` / `Requested / not enforced` / `Enforced` / `Failed`) need no client-side logic and cannot drift between clients. Nothing in that contract lets a NoOp outcome read as real network isolation.

**Signed report: three facts kept distinct.** Page 2 gained an **Autonomous Isolation Enforcement** block: `Isolation Eligible`, `Isolation Requested`, `Isolation Enforced`, `Enforcement Backend`, and an `Enforcement Status` card. Eligibility is read off the *presence* of isolation state, never recomputed — an `IsolationStatus` exists if and only if `should_isolate()` returned `True` — so `reports/` carries no threshold of its own and imports no enforcement module. The wording is explicit per state: not eligible ("its raw Quantum Risk Score did not reach the isolation threshold, so no isolation was requested"); NoOp ("Isolation requested but not enforced by the current backend. The 'noop' backend does not perform physical network enforcement, so this device was NOT physically isolated from the network."); failed ("enforcement FAILED on the '<backend>' backend"); enforced ("Isolation requested and enforced by the '<backend>' backend"). Report structure is still exactly 3 pages, and a layout test renders worst-case remediation/NIST/reason text through the real page-2 renderer to confirm the block stays above the bottom margin.

**Signing.** Because the status rides inside `DeviceAssessment.to_dict()`, it is covered by the existing canonical-JSON Dilithium signature with no change to `signing/`: a report generated with `enforced=True` has a different `report_hash` than the same assessment with a NoOp status, and cross-verification between them fails. `from_dict()` tolerates a missing `"isolation"` key (and a missing `"enforcement_capable"`), so any payload serialized before this phase still loads — as `None`, the safe reading.

**Test count: 1278 → 1346** (+68 collected cases: IsolationStatus, DeviceAssessment isolation state, pipeline propagation and representative-selection survival, API serialization, and report wording/layout/signing). **All 1346 pass.** No existing test was weakened or deleted; one exact-key constant was extended to record the deliberately-extended contract.

**Not implemented (deliberately):** iptables/nftables commands, routing, NAT, AP mode, MAC blocking, deauthentication, Wi-Fi credential handling, any real institutional-network enforcement, any isolation registry or database, and any change to QRS weights/thresholds, the isolation threshold, Isolation Forest, the fusion rule, or the model artifacts.

---

## 37. Phase 3C Addendum — Linux/Raspberry-Pi Live Network Capture (capture only)

**Purpose.** Feed IP-visible packets from one named Linux/Pi interface into the existing pipeline while preserving each packet's true source device identity. Capture only: no iptables/nftables rule, no routing, no NAT, no AP mode, no GPIO/OLED, and no change to enforcement policy. `CaptureSource -> RawPacket -> fingerprinting -> QRS -> Isolation Forest -> fusion -> isolation decision` is untouched; `pipeline/runner.py` was not modified in this phase.

**Why a new capture source was required.** `capture.host_live_source.LiveCaptureSource` cannot serve this role, for three independent reasons found in the audit, each fatal on its own:

1. **It normalizes device identity to the local host.** `_to_raw_packet(pkt, local_ip)` sets `RawPacket.src_ip = local_ip` for every packet, swapping ports on inbound traffic so the local machine is always the source. That is correct for its topology — one monitored endpoint — and catastrophic for a Pi, because `pipeline/runner.py` keys a device on `src_ip` and a later Linux backend would isolate that address. Every monitored device would assess, and later be enforced, as the Pi.
2. **It discards exactly the traffic a Pi must see.** Any packet where neither end is `local_ip` returns `None`. On a monitored path, that is *all* of it — a Pi would observe zero packets.
3. **It cannot even construct on a Pi.** `check_capture_backend_available()` requires `conf.use_pcap`, which is typically false on Linux (scapy uses native sockets there), and `__init__` rejects any interface with no IPv4 address — which a monitor-mode `wlan1` does not have.

Generalizing it would mean one class whose device-identity semantics flip on a constructor flag, leaving the Windows demo one wrong default away from attributing traffic to the wrong host. Two small classes behind the same `CaptureSource` interface is the safer shape, and nothing downstream can distinguish them.

**`capture/network_live_source.py` — `NetworkLiveCaptureSource`.** Same `CaptureSource.read_packets() -> Iterator[RawPacket]` contract and the same `RawPacket` contract as `OfflinePcapSource`. **Identity is passed through verbatim**: `src_ip` is the packet's own IP source, `dst_ip` its own destination, ports in their captured order, payload bytes unmodified. No address is rewritten, swapped, or normalized; traffic between two third-party hosts is reported, not dropped. A test asserts the two live sources deliberately disagree about the same frame — each correct for its own topology.

Bounded and streaming, reusing the proven `host_live_source` shape: a background sniff thread bridged through a `Queue`, stopping at `timeout` seconds or `packet_limit` packets. The interface is always supplied by the caller; a static test asserts no `wlan0`/`wlan1`/`eth0` literal appears in any executable string in the module, so reusable capture code cannot touch a management interface.

**Filtering and error behavior.** A *frame* is never fatal; a *backend* failure always is. Frames with no IP layer (ARP, 802.11 management/control, protected frames exposing no decodable IP, IPv6) are counted as `skipped_non_ip`; IP frames with no TCP/UDP layer or an empty payload (a bare SYN) are `skipped_no_transport` — the same rule `OfflinePcapSource` already applies; frames whose fields `RawPacket` rejects, or that raise anything at all during conversion, are counted as `parse_failures` and skipped with the loop continuing. A Radiotap/802.11 frame is processed only when it already exposes a decodable IP layer: **no WPA/WPA2/WPA3 decryption, no deauthentication, no credential capture** is attempted or possible. By contrast a nonexistent interface, a permission error, or any other sniff failure is raised as a `CaptureError` naming the interface and the privilege requirement (root or `CAP_NET_RAW`).

**Counters, not telemetry.** `CaptureCounters` (`seen`, `yielded`, `skipped_non_ip`, `skipped_no_transport`, `parse_failures`, plus a `summary()` string) extends the existing single-public-counter precedent (`host_live_source.LiveCaptureSource.packets_captured`) to five ints on the source. No subsystem, no persistence, no registry, no database.

**`run_pi_live.py` — a fifth composition root.** `run_live_demo.py` is explicitly and documentedly host-level Windows capture with local-host identity normalization, so it was not repurposed; overloading it would put two contradictory identity semantics behind one flag. The new script captures from one named interface, runs the unmodified pipeline, and prints capture counters plus a per-device table with each device's isolation status. `--interface` has **no default** (also accepted as `PI_CAPTURE_INTERFACE`); a missing interface is exit code 2, never a guess. `--list-interfaces`, `--timeout`, `--packet-limit` and an optional pass-through `--filter` complete the CLI. It composes `NoOpIsolationBackend()` exactly like every other entry point — enforcement policy is unchanged, and a test asserts the module neither imports `LinuxIsolationBackend` nor mentions iptables/nftables.

**The frozen factory was not touched.** `capture/factory.py` still resolves `CAPTURE_MODE=live` to the `capture.live_source.LiveCaptureSource` scaffold, so `main.py`, `run_api.py` and `run_demo.py` behave exactly as before; a test asserts this. The Pi source is composed only by its own entry point, the same pattern `run_live_demo.py` already uses.

**Test count: 1346 → 1420** (+74: 40 capture-source unit tests, 14 pipeline-integration and existing-path regression tests, 20 entry-point tests). **All 1420 pass.** No existing test was weakened or modified. Every new test uses deterministic scapy-built packets with `sniff()` stubbed — none requires a real interface, a capture backend, root, or network access. The integration tests deliberately do *not* stub `assess_packet`: they run the genuine pipeline, so an identity that failed to survive it would fail the test. The slowest tests in the suite remain pre-existing ones (fixture generation, startup smoke, performance benchmarks); nothing added here is slow.

**Not implemented (deliberately):** iptables/nftables rules, routing, NAT, AP mode, MAC blocking, deauthentication, WPA/WPA2/WPA3 decryption, credential capture, GPIO/LED/OLED, any change to QRS weights/thresholds, the isolation threshold, Isolation Forest, the fusion rule, the model artifacts, or `pipeline/runner.py`.

---

## 38. Phase 3D Addendum — Linux iptables Enforcement (frozen policy)

**Purpose.** Carry out an already-approved isolation request on Linux through the system `iptables` binary. This phase freezes the firewall policy Phase 3A deliberately left open (§35) and changes nothing else: the eligibility rule, the pipeline, capture, QRS, Isolation Forest, fusion, the API shape, the PDF layout and the frontend are all untouched.

**The trigger is unchanged and is the only trigger.** `enforcement.decision.should_isolate()` still returns `assessment.risk_assessment.risk_score >= threshold` (default 7) and still never reads `final_category`. **Raw deterministic QRS is the only thing that can cause a firewall command. An ML/Isolation-Forest escalation of the reported category can never isolate anything** — a device with `risk_score=5` fused up to HIGH produces no iptables command at all. The backend receives an already-approved request: it is handed only an IP and the raw score, and a structural test asserts the module references no fused or ML identifier, so it cannot consult one even by accident.

**`enforcement/iptables_backend.py` — `IptablesIsolationBackend`.** A specialization of `LinuxIsolationBackend`, not a parallel path: same `IsolationBackend` contract, same injected `CommandRunner` seam, same `_outcome()` reporting, reached through the `pipeline/runner.py` call that already existed. `pipeline/runner.py` was not modified in this phase. `backend_name = "linux-iptables"`, `enforcement_capable = True`, so a failure surfaces through Phase 3B's propagation as `"Failed"` rather than as a non-enforcing deployment.

**Exact strategy — check-then-act at every step, so it is idempotent:**

```
iptables -w -L CIPHER_ISOLATION -n              # does our chain exist?
iptables -w -N CIPHER_ISOLATION                 # create it only if not
iptables -w -C FORWARD -j CIPHER_ISOLATION      # is our jump in place?
iptables -w -I FORWARD 1 -j CIPHER_ISOLATION    # install it once only
iptables -w -C CIPHER_ISOLATION -s <ip> -j DROP # rule already present?
iptables -w -A CIPHER_ISOLATION -s <ip> -j DROP # add only if absent
iptables -w -C CIPHER_ISOLATION -d <ip> -j DROP
iptables -w -A CIPHER_ISOLATION -d <ip> -j DROP
```

Running it twice adds nothing; a partially-present rule set is completed rather than duplicated; a second device reuses the existing chain and jump and issues only its own two rules. A non-zero exit from a `-C`/`-L` check is normal flow (that is how iptables says "not present"), so only an *unexecuted* check or a failing mutation is treated as failure. `-w` waits for the xtables lock instead of failing spuriously. The jump is inserted at position 1 so the isolation decision is evaluated before any pre-existing ACCEPT could let the device through.

**`FORWARD` only, and what that honestly means.** The repository defines no forwarding topology — §35 records that `wlan0` is management and `wlan1` is a monitor-mode capture interface, and that neither is a forwarding path. `FORWARD` is therefore the narrowest rule consistent with the project's stated intent (prevent the isolated device from traversing the enforcement point) while being structurally incapable of locking this host out of its own management network: management traffic to and from the Pi is INPUT/OUTPUT, which this backend never touches (asserted by test). **The consequence is stated plainly rather than papered over: enforcement requires an authorized Linux enforcement point on the device's actual path. A passive monitor-mode interface is not an enforcement path — it observes traffic, it does not forward it, so on a monitor-only topology the rule is installed correctly and drops nothing.** CIPHER does not configure routing, NAT or AP mode to change that, and this is not an institutional-network enforcement capability. `enforced=True` means "CIPHER's DROP rule is in place on this host", which is what the outcome's reason string says.

**Safety protections, each covered by test.** IPv4 only — device identity is IPv4 throughout CIPHER, and an IPv6 literal is a clean refusal, not an attempt. Validation happens *before any argv is built*, so a malformed or hostile target never reaches iptables: a non-IP string, a bad quad, a CIDR, loopback, the unspecified address, multicast, broadcast, and **any address this host itself holds** are all refused with `enforced=False` and a clear reason, having run nothing. Own-address discovery uses `socket` only (no subprocess, no new dependency) and is best-effort: if it cannot be determined, the protection is simply unavailable and ordinary enforcement still works, rather than failing or guessing. CIPHER never flushes a chain (`-F`), never deletes a chain (`-X`), never sets a default policy (`-P`), and never deletes a rule outside its own chain — asserted structurally.

**Command safety.** Commands are argument lists, never shell strings; `shell=True` appears nowhere, and a structural test asserts no call in the executing module passes a `shell` keyword at all, nor reaches `os.system`/`Popen`/`call`/`check_call`/`check_output`.

**`enforcement/subprocess_runner.py` — `SubprocessCommandRunner`.** The only module in CIPHER that can spawn a process, kept separate so that `backends.py`, `command_runner.py`, `linux_backend.py` and `iptables_backend.py` all remain statically asserted to import neither `subprocess` nor `os`. It is **deliberately not re-exported from `enforcement/__init__.py`**: importing `enforcement` cannot make a firewall command possible, and every backend's default runner is the non-executing `UnavailableCommandRunner`. It never raises for an ordinary failure — a missing binary, a permission denial, a timeout and a non-zero exit all come back as a `CommandResult`, and `executed=False` can never read as success whatever the exit-code field says.

**Privilege and failure reporting.** A missing `iptables`, a permission denial, a timeout, a non-zero exit and a silent failure are each reported through the existing contract as `requested=True, enforced=False` with a reason naming the cause and the root/`CAP_NET_ADMIN` requirement. Enforcement is never silently claimed, and a failure never aborts the capture run — the existing per-packet fault isolation is unchanged and the device's assessment is still retained and reported.

**Restore / unisolate.** `restore(device_ip)` deletes only CIPHER's own `-s` and `-d` rules for that device from the owned chain, and nothing else. Idempotent and predictable: a device that is not isolated is a success (`enforced=True`, reason "nothing to remove"), not an error. The chain and the jump are deliberately left in place — other devices may still be isolated through them, and removing shared state would silently un-isolate them. Another device's rules are provably untouched.

**Pi runtime activation — explicit, never implicit.** `run_pi_live.py --enforcement {noop,iptables}` defaults to `noop`, also readable as `CIPHER_ENFORCEMENT` (flag wins), matching the existing `--interface`/`PI_CAPTURE_INTERFACE` style. `iptables` additionally requires `platform.system() == "Linux"`, so a Windows run or a Windows test cannot execute a firewall command even if the flag is passed. It is the only place in CIPHER that composes `SubprocessCommandRunner`. The startup disclaimer states which backend is active, names the owned chain, and repeats the traversal limitation. `main.py`, `run_api.py`, `run_demo.py` and `run_live_demo.py` are unmodified and all still compose `NoOpIsolationBackend()`.

**Logging.** One line each for enforcement requested, refused, succeeded and failed, and for restore requested/succeeded/failed, naming the device, the chain and the reason. No secrets: the only values logged are an IP, a score, a chain name and an iptables diagnostic.

**Test count: 1420 → 1531** (+111: 64 iptables backend, 22 subprocess runner, 14 end-to-end eligibility with the real backend, 11 run_pi_live composition). **All 1531 pass.** No test requires root and none touches the host firewall: every command runner is a recording double, the eligibility suite additionally makes any process spawn an immediate failure, and the two tests that exercise the real execution path run the Python interpreter rather than a firewall utility. One Phase 3C test was rewritten rather than deleted — it asserted `run_pi_live.py` contained no firewall vocabulary, which this phase deliberately changes; it now asserts the stronger invariants (no nftables/firewalld/ufw/`shell=True`, and the generic policy-free Linux seam is not composed).

**Not implemented (deliberately):** nftables, firewalld, ufw, eBPF, tc, controller integrations, IPv6 firewall rules, MAC-based blocking, routing, NAT, AP mode, deauthentication, any global firewall flush or default-policy change, any automatic un-isolation schedule, a database, and any change to QRS weights/thresholds, the isolation threshold, Isolation Forest, the fusion rule, the model artifacts, `pipeline/runner.py`, the API shape, the PDF layout or the frontend.

---

## 39. Phase 3F Addendum — Optional SSD1306 OLED Status Display

**Purpose.** Render state the pipeline already produced on an optional SSD1306 I2C panel. Output only: nothing in `hardware/` computes a Quantum Risk Score, runs or reads the Isolation Forest, applies the fusion rule, or decides isolation eligibility. QRS, the threshold of 7, the fusion rule, iptables enforcement, capture semantics, the API and the frontend are all unchanged. GPIO status LEDs remain unimplemented — a separate, later phase.

**`hardware/display.py` — the boundary.** `StatusDisplay` is an ABC with `start() -> bool`, `show_lines(lines)` and `close()`, plus `show_ready`/`show_assessment`/`show_summary` convenience wrappers shared by every implementation. Implementations are **contractually forbidden from raising** for an ordinary hardware problem; `available` reports whether output is actually reaching a panel, so a caller logs the truth rather than assuming success. `NoOpStatusDisplay` is the default everywhere: it imports no hardware library (statically asserted), touches no bus, never fails, and reports `available == False` even after a successful `start()` — keeping "CIPHER ran" and "a panel showed something" separate facts, the same way `NoOpIsolationBackend` separates decided from enforced.

**Frames are pure data.** `build_ready_frame`, `build_assessment_frame` and `build_summary_frame` return plain lists of short strings, clipped to 5 lines × 21 characters for a 128x64 panel, so the exact content shown is unit-testable with no hardware and no driver present. The assessment frame reads `device.ip`, `risk_assessment.risk_score` (the raw deterministic score, never recomputed) and `final_category` (the already-fused category, never re-fused) straight off the `DeviceAssessment`:

```
CIPHER
Device: 192.168.50.21
QRS: 7/10
Risk: HIGH
Isolation: ISOLATED
```

**Isolation labels are a pure field mapping**, in the one order that cannot overclaim: no object → `N/A`; `requested is not True` → `NONE`; `enforced is True` → `ISOLATED`; otherwise the backend's own `enforcement_capable` decides `FAILED` (a real backend that could not enforce) versus `NOOP` (a deliberately non-enforcing runtime). **`ISOLATED` is never shown unless the backend set `enforced=True`.** A HIGH-risk device with no isolation state shows `Isolation: N/A`, and an ML-escalated HIGH at raw QRS 5 shows `QRS: 5/10` with no isolation — both asserted by test. `describe_isolation` takes exactly one argument, so there is no parameter through which QRS, a category or an anomaly could reach it, and a structural test asserts the module references no scoring, fusion or ML identifier.

**`hardware/ssd1306_display.py` — the optional adapter.** The only module in CIPHER that touches a hardware library, and it does so **lazily**: `luma.oled` is imported inside `start()`, never at module level (asserted structurally, and by the fact the Windows suite imports it). Importing this module without the driver installed is therefore safe and cannot break an unrelated runtime. **I2C only; no SPI** (also asserted structurally). Bus number and address are constructor arguments defaulting to bus 1 and `0x3C` — the standard Raspberry Pi I2C bus and the address most SSD1306 breakouts ship with; both are overridable because a minority of boards are strapped to `0x3D`. No other board-specific value is assumed anywhere.

**Failure handling, all non-fatal and all tested.** A missing driver, an absent or disabled bus (`/dev/i2c-1` not found), an I2C permission denial, a failed initialization and a failed write are each logged once and swallowed. A failed `start()` returns `False` and every later frame is dropped silently. A failed *write* marks the panel unavailable for the rest of the run, so a broken panel costs exactly one write attempt rather than one per packet. `close()` survives a failing `clear()` and is idempotent. The I2C-unavailable warning names `i2cdetect` so the operator knows what to check.

**Performance.** Frames are throttled by `min_interval_seconds` (default 1.0s) and identical consecutive frames are skipped entirely, so a fast capture cannot flood the bus. No background thread, no queue, no event bus was added.

**Runtime integration — one additive, passive pipeline hook.** `run_capture()` gained `assessment_observer: Optional[Callable[[DeviceAssessment], None]] = None`. It is called after representative selection, its return value is discarded, and `_notify_observer()` wraps it in its own `try/except` — so an observer can neither change nor delay an assessment, an isolation decision or a report, and an exploding observer costs nothing (asserted: both devices still assessed, warning logged). With no observer supplied, `pipeline/runner.py` behaves exactly as before. This is the only pipeline change in the phase; capture, enforcement and reporting are untouched.

**Activation — explicit, Linux-only, never implicit.** `run_pi_live.py --display {none,oled}` defaults to `none`, also readable as `CIPHER_DISPLAY` (flag wins), matching the existing `--interface`/`--enforcement` style. `oled` on a non-Linux host logs a warning and falls back to `NoOpStatusDisplay` rather than reaching for a bus. Lifecycle: build → `start()` → ready frame → live per-assessment frames during capture → per-device final frames (now carrying the isolation state attached at end of capture) → run summary → `close()`. The final frames and shutdown run from a `finally` block, so an interrupted or failed run leaves a `Status: STOPPED` frame instead of a frozen mid-capture one. Every lifecycle call goes through `_safe_display()`, defence in depth so that even a contract-violating display cannot fail the run. The summary's `Isolated:` count includes only assessments the backend itself marked `enforced`. `main.py`, `run_api.py`, `run_demo.py` and `run_live_demo.py` are unmodified and compose no display.

**No new dependency.** `requirements.txt` is unchanged, and deliberately so: it is documented there as a verified Windows/x86 baseline, and `luma.oled` is a Raspberry-Pi-only extra needed by exactly one optional code path. It is installed on the Pi, when the panel is actually wired, with `pip install luma.oled`; until then `--display oled` simply reports the driver unavailable and the run continues. No overlapping display library was added, and the whole test suite runs without the driver present.

**Test count: 1531 → 1612** (+81: 31 display/frame/mapping, 29 SSD1306 adapter via an injected fake device and fake canvas, 21 pipeline-observer and run_pi_live composition). **All 1612 pass.** No existing test was modified. Nothing requires hardware, a driver, an I2C bus or root.

**NOT VALIDATED ON HARDWARE — stated plainly, and guarded by a test.** No SSD1306 panel has been wired or driven by this code. The pin map in `docs/hardware_manual` remains PENDING, so the wiring, the electrical behaviour, the real `luma.oled` call sequence, panel legibility at this font size, and I2C timing under load are all unverified. The adapter's docstring carries `NOT VALIDATED ON HARDWARE` and a test asserts that string is still there, so the claim cannot be quietly removed without the test failing. The injected-fake tests prove the command/data flow and every failure path, not the hardware.

**Not implemented (deliberately):** GPIO status LEDs, buttons or any input control, SPI, a second display technology, a hardware event bus, a background rendering thread, a database, and any change to QRS weights/thresholds, the isolation threshold, Isolation Forest, the fusion rule, the model artifacts, capture semantics, the enforcement policy, the API shape or the frontend.

---

## Approved Decisions Recap

D1 (models/ package), D2 (OfflinePcapSource implemented, LiveCaptureSource scaffolded), D3 (pipeline/ package, main.py as pure composition root), and D4 (ML fail-open via `ml.loading.load_anomaly_detector`, superseding the original rule-based-fallback draft — see Section 21) are all approved and reflected above. Proceeding to Step 2: folder scaffolding.
