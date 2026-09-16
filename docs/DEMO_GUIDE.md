# CIPHER Demo Guide

A concise, presentation-day reference. For the full architecture and design
rationale, see `docs/SDD.md` (Phase 15 addenda).

## Pre-demo (5 minutes before)

```
python preflight.py
```

Prints PASS/WARN/FAIL for every required runtime asset (web build, demo
fixture, ML model, signing keys, port 5000, Python/import health) without
starting the application. Exit code 0 means CIPHER can start; a WARN (e.g. no
trained ML model) is not a blocker. Fix anything shown as FAIL before going on
stage.

## Start

Double-click:

```
Start CIPHER.bat
```

or, equivalently, from a terminal in the project directory:

```
python run_demo.py
```

`Start CIPHER.bat` resolves the project directory, prefers a project virtual
environment (`.venv/` or `venv/`) if one exists, runs the same preflight check,
starts the application, waits for a real HTTP 200 from `/api/health`, and only
then opens your default browser to `http://127.0.0.1:5000` — never before the
server can actually answer. The console window stays open and shows real
startup progress; if something fails, the reason stays visible there.

## Demo flow

1. **Dashboard** (`/dashboard`) — overview of assessed devices.
2. **Connected Devices** (`/devices`) — the full device list with risk
   categories.
3. **Open the HIGH-risk device** — the one flagged HIGH (raw QRS ≥ 7).
4. **Inspect its QRS breakdown and remediation guidance** on the device detail
   view.
5. **Download its PDF report** — a real, signed 3-page report generated for
   that device.
6. **Network / analyzed-device map** (`/network`) — visual layout of assessed
   devices.
7. **Reports** (`/reports`) — every generated report (MEDIUM and HIGH devices
   only; LOW devices are never flagged for a report, by design).
8. **Evaluation harness** (if asked for evidence/benchmarks):
   ```
   python evaluate_demo.py
   ```
   Prints the controlled five-scenario evaluation, entropy targets, latency,
   false-positive rate, and tamper-detection results — kept separate from
   normal startup on purpose; it never runs automatically.

The committed presentation fixture (`tests/fixtures/demo_presentation.pcap`)
always produces the same 5 devices: 1 LOW, 3 MEDIUM, 1 HIGH, with 4 generated
reports (every non-LOW device) — verified by
`tests/fixtures/test_evaluation_fixtures.py`.

## Stop

Press **Ctrl+C** in the console window. The server shuts down cleanly and
control returns to the console/launcher — closing the browser tab does *not*
stop CIPHER, and stopping CIPHER does not depend on the browser being open.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Preflight or launcher says "Port 5000 is already in use" | Another CIPHER instance (or something else) is already listening on 5000 | Stop the existing process, then retry. CIPHER never force-stops another process for you. |
| "CIPHER web application is missing" | `web/index.html` or `web/assets/` is missing | Restore `web/` from version control — it's a committed release artifact, not something built at runtime. |
| "CIPHER demo data is missing" | `tests/fixtures/demo_presentation.pcap` is missing | Restore it from version control (`git checkout -- tests/fixtures/demo_presentation.pcap`), or regenerate deterministically with `python -m tests.fixtures.generate_evaluation_fixtures`. It is never regenerated automatically at startup. |
| "Incomplete ML-DSA-44 keypair" | Only one of the two signing key files exists in `data/keys/` | Restore the missing file, or delete both and let CIPHER generate a fresh pair on next startup. CIPHER never overwrites or regenerates a surviving key automatically. |
| "Isolation Forest: Unavailable — QRS-only mode" | No trained model at `ml/artifacts/anomaly_detector.joblib` | Not a blocker — QRS risk scoring is unaffected. Only mentioned for completeness; do not train a model just to clear this. |
| Browser opened but shows nothing / connection refused | You opened it manually before CIPHER was ready | Let `Start CIPHER.bat`/`launch_cipher.py` open the browser for you — it only does so after a real `/api/health` 200. |
