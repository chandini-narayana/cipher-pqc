"""Pipeline — capture -> entropy/fingerprint -> risk -> ml -> sign -> registry.

Owns:
- start() / stop() — background thread lifecycle
- _loop() — iterates capture_source.read_packets()
- _process_packet() — per-packet sequence wrapped in fault isolation

Implemented in a later step, once capture/, entropy/, fingerprint/, risk/,
ml/, and signing/ each exist.
"""

# TODO: implement Pipeline (Step: pipeline)
