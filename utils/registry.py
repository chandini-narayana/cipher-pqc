"""DeviceRegistry — thread-safe in-memory store, keyed by device IP.

Holds one current RiskEvent per device (bounded memory — see SDD Section
16), not full history. Full history belongs in the signed log files on
disk, not in memory.

Implemented in a later step.
"""

# TODO: implement DeviceRegistry (Step: utils)
