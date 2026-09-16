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

## Approved Decisions Recap

D1 (models/ package), D2 (OfflinePcapSource implemented, LiveCaptureSource scaffolded), D3 (pipeline/ package, main.py as pure composition root), and D4 (ML fail-open via `ml.loading.load_anomaly_detector`, superseding the original rule-based-fallback draft — see Section 21) are all approved and reflected above. Proceeding to Step 2: folder scaffolding.
