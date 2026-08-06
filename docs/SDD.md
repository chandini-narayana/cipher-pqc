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

**D4 (retained from draft) — ML fallback.** When no trained model is present at startup, `MLClassifier` falls back to deriving `RiskCategory` directly from the numeric `risk_score` thresholds already defined in `risk/scoring.py`, logs a warning once, and the pipeline continues normally. A missing model is never a startup failure.

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
│   └── engine.py                  # EntropyEngine.shannon(payload) -> float
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
      EntropyEngine.shannon()      TLSFingerprinter.extract()
             │                             │
             └─────────────┬───────────────┘
                            ▼
                    DetectionEvent (models/)
                            │
                            ▼
                  RiskEngine.evaluate(event)
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
class EntropyEngine:
    + shannon(payload: bytes) -> float           # pure

class TLSFingerprinter:
    + extract(packet: PacketRecord) -> TLSInfo   # pure

# --- risk/, ml/ ---
class RiskEngine:
    + evaluate(event: DetectionEvent) -> RiskEvent

class MLClassifier:
    - model: DecisionTreeClassifier | None
    + predict(event: DetectionEvent) -> RiskCategory   # falls back per D4 if model is None
    + train(dataset) -> None
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
| `MODEL_PATH` | `ml/artifacts/risk_classifier.pkl` | trained classifier location |
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

## Approved Decisions Recap

D1 (models/ package), D2 (OfflinePcapSource implemented, LiveCaptureSource scaffolded), D3 (pipeline/ package, main.py as pure composition root), and D4 (ML rule-based fallback retained) are all approved and reflected above. Proceeding to Step 2: folder scaffolding.
