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

- **Fixtures:** the same committed `.pcap` set as the draft (clean TLS 1.3, forced TLS 1.0, plaintext HTTP, MQTT).
- **`OfflinePcapSource`** gets full functional tests against those fixtures.
- **`LiveCaptureSource`** gets exactly one test: confirms it satisfies the `CaptureSource` interface and that calling `read_packets()` raises `LiveCaptureNotImplementedError` with a clear message — this is what "documented scaffold" means in test form, not a skipped/ignored file.
- **`Pipeline`** gets an end-to-end test using `OfflinePcapSource` plus real (not mocked) `RiskEngine`/`MLClassifier`-with-fallback/`DilithiumSigner`, asserting the final `DeviceRegistry` snapshot matches expected risk scores for the fixture devices — this is the test that would have been awkward to write against a monolithic `main.py` and is the concrete payoff of D3.
- Dashboard/report tests still use mocked `RiskEvent` data, independent of whether `Pipeline` has ever run.
- CI runs `pytest -m "not live"` — though with D2 in place there's now nothing marked `live` that does real network I/O; the marker is kept for when Phase 2 revisits `live_source.py`.

---

## 14. Deployment Strategy

Unchanged from the draft. Windows 11: venv, `pip install -r requirements.txt`, `python main.py`, dashboard at `127.0.0.1:5000`. Offline mode needs nothing beyond the pip install; live mode (once implemented) will need Npcap — not relevant to Phase 1's actual test/run path today since `live_source.py` is a scaffold. GitHub Actions runs `pytest -m "not live"` on push using committed fixtures only.

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

## Approved Decisions Recap

D1 (models/ package), D2 (OfflinePcapSource implemented, LiveCaptureSource scaffolded), D3 (pipeline/ package, main.py as pure composition root), and D4 (ML fail-open via `ml.loading.load_anomaly_detector`, superseding the original rule-based-fallback draft — see Section 21) are all approved and reflected above. Proceeding to Step 2: folder scaffolding.
