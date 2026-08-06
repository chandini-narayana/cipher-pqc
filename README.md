# CIPHER — Phase 1 (Windows, Hardware-Free)

Post-quantum cryptographic vulnerability detection for IoT network traffic.
Phase 1 runs entirely on Windows 11 with no Raspberry Pi, GPIO, OLED, or
systemd dependency — see `docs/SDD.md` for the full design.

## Status

Folder scaffolding only. No modules are implemented yet. See `docs/SDD.md`
for the architecture and the staged build order; each module will be built,
tested, and documented individually before integration.

## Setup (once modules are implemented)

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python main.py

Dashboard: http://127.0.0.1:5000

## Capture modes

- `CAPTURE_MODE=offline` (default) — deterministic replay from a `.pcap`
  file. Fully implemented.
- `CAPTURE_MODE=live` — real NIC capture. Interface exists; implementation
  is a documented scaffold in Phase 1 (see `docs/SDD.md` Section 4, D2).
- `CAPTURE_MODE=mock` — dashboard reads canned data, no capture required.

## Testing

    pytest -m "not live"

## Docs

Full design: [`docs/SDD.md`](docs/SDD.md)
